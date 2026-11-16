"""netbox-snmp-sync entrypoint (SPEC.md "CLI").

Order per run: inventory -> SNMP (concurrent) -> per device: NetBox state, collect,
precheck, diff, delete limit, [apply] -> prefixes (global) -> summary.
A device that fails any step is skipped and makes the run exit non-zero in apply mode;
it never produces deletes.
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import ipaddress
import json
import logging
import os
import sys

import yaml

from .apply import execute, limit_deletes, precheck
from .collect import collect
from .config import device_config
from .diff import diff_device, diff_prefixes
from .fixtures import load_fixture, save_fixture
from .model import Action, NbDeviceState
from .netbox import NetBox
from .snmp import SUBTREES, Credentials, collect_many

log = logging.getLogger("netbox_snmp_sync")


def load_config(path: str) -> dict:
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("netbox", {}).setdefault("tag", "snmp-discovery")
    cfg.setdefault("snmp", {})
    cfg.setdefault("defaults", {})
    cfg.setdefault("devices", {})
    cfg.setdefault("inventory", {})
    return cfg


def credentials(snmp: dict) -> Credentials:
    if str(snmp.get("version", "2c")) == "3":
        env = lambda k: os.environ[snmp[k]] if snmp.get(k) else None
        return Credentials(version="3", user=snmp["user"], auth_key=env("auth_key_env"),
                           priv_key=env("priv_key_env"), auth_protocol=snmp.get("auth_protocol", "sha"),
                           priv_protocol=snmp.get("priv_protocol", "aes"))
    return Credentials(version="2c", community=os.environ[snmp.get("community_env", "SNMP_COMMUNITY")])


def label(a: Action, nb: NbDeviceState | None) -> str:
    """Human name for an action's target."""
    p = a.payload
    if a.op == "create":
        return p.get("name") or p.get("address") or p.get("mac_address") or p.get("prefix") or "?"
    if nb is not None:
        for n, i in nb.interfaces.items():
            if a.kind == "interface" and i.id == a.id:
                return n
        for addr, ip in nb.ip_addresses.items():
            if a.kind == "ip" and ip.id == a.id:
                return addr
        for m in nb.macs:
            if a.kind == "mac" and m.id == a.id:
                return m.mac
    return f"#{a.id}"


def print_actions(device: str, actions: list[Action], nb: NbDeviceState | None):
    for a in actions:
        extra = {k: v for k, v in a.payload.items() if k not in ("device", "tags", "assigned_object_type") and not k.startswith("_")}
        detail = f" {json.dumps(extra, sort_keys=True)}" if a.op == "update" else ""
        print(f"  {device:<16} {a.op:<6} {a.kind:<9} {label(a, nb):<40} {a.reason}{detail}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="netbox-snmp-sync")
    ap.add_argument("--config", required=True)
    ap.add_argument("--mode", choices=["report", "apply", "snmp-only", "capture"], default="report")
    ap.add_argument("--device", action="append", default=[], help="limit to these devices")
    ap.add_argument("--force-deletes", action="store_true")
    ap.add_argument("--fixture-dir", default="tests/fixtures",
                    help="capture: where to write; report/apply: read SNMP from here instead of the network if --offline")
    ap.add_argument("--offline", action="store_true", help="use fixtures instead of live SNMP (testing)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    cfg = load_config(args.config)
    nbc, snmpc = cfg["netbox"], cfg["snmp"]
    tag, site = nbc["tag"], nbc.get("site")
    needs_netbox = args.mode in ("report", "apply") or cfg["inventory"].get("netbox_tag")
    client = NetBox(nbc["url"], os.environ[nbc.get("token_env", "NETBOX_TOKEN")]) if needs_netbox else None

    # ---------------------------------------------------------------- inventory
    targets = {n: d["host"] for n, d in cfg["devices"].items() if d and d.get("host")}
    if cfg["inventory"].get("netbox_tag"):
        targets = {**client.list_inventory(cfg["inventory"]["netbox_tag"], site), **targets}
    if args.device:
        targets = {n: h for n, h in targets.items() if n in args.device}
    if not targets:
        log.error("no devices to poll")
        return 1

    # ---------------------------------------------------------------- SNMP
    if args.offline:
        raw = {}
        for n in targets:
            _, _, values = load_fixture(os.path.join(args.fixture_dir, f"{n}.json"))
            raw[n] = values
    else:
        raw = asyncio.run(collect_many(targets, credentials(snmpc), SUBTREES,
                                       concurrency=int(snmpc.get("concurrency", 16))))

    if args.mode == "capture":
        os.makedirs(args.fixture_dir, exist_ok=True)
        rc = 0
        for n, v in raw.items():
            if isinstance(v, Exception):
                log.error("%s: %s", n, v); rc = 1; continue
            save_fixture(os.path.join(args.fixture_dir, f"{n}.json"), n, targets[n], v)
            log.info("%s: %d values captured", n, len(v))
        return rc

    if args.mode == "snmp-only":
        out = {}
        for n, v in raw.items():
            if isinstance(v, Exception):
                out[n] = {"error": str(v)}; continue
            d = collect(v)
            out[n] = {"sysname": d.sysname, "sys_object_id": d.sys_object_id,
                      "interfaces": {k: dataclasses.asdict(i) for k, i in d.interfaces.items()},
                      "addresses": sorted(f"{a.interface} {a.address}" for a in d.addresses)}
        print(json.dumps(out, indent=1, sort_keys=True))
        return 0 if not any(isinstance(v, Exception) for v in raw.values()) else 1

    # ---------------------------------------------------------------- report / apply
    apply_mode = args.mode == "apply"
    skipped, failed, live_for_prefixes = [], [], []
    totals = {"create": 0, "update": 0, "delete": 0}
    print(f"{'APPLY' if apply_mode else 'REPORT (no changes made)'}: {len(targets)} device(s)")
    for name in sorted(targets):
        v = raw[name]
        if isinstance(v, Exception):
            skipped.append(f"{name}: SNMP failed: {v}"); continue
        try:
            dev = collect(v)
            nb = client.get_device_state(name, site, tag)
        except Exception as exc:
            skipped.append(f"{name}: {exc}"); continue
        dcfg = device_config(cfg["defaults"], cfg["devices"].get(name), tag)
        why = precheck(dev, nb, (cfg["devices"].get(name) or {}).get("match", "name"))
        if why:
            skipped.append(f"{name}: {why}"); continue
        plan = diff_device(dev, nb, dcfg)
        for w in limit_deletes(plan, nb, dcfg.max_delete_fraction, force=args.force_deletes):
            log.warning(w)
        live_for_prefixes += [a.address for a in dev.addresses
                              if not dcfg.excluded(a.interface)
                              and not any(ipaddress.ip_interface(a.address).ip in ipaddress.ip_network(x, strict=False)
                                          for x in dcfg.address_exclude)]
        print(f"{name}: {len(plan.actions)} change(s)")
        print_actions(name, plan.actions, nb)
        for a in plan.actions:
            totals[a.op] += 1
        if apply_mode and plan.actions:
            res = execute(plan, client, nb)
            failed += [f"{name}: {a.op} {a.kind} {label(a, nb)}: {err}" for a, err in res.failed]

    # prefixes: global, after device changes
    prefix_actions = diff_prefixes(live_for_prefixes, client.list_prefixes(tag), client.list_ip_addresses(), tag,
                                   cfg["defaults"].get("vrf_id"))
    if skipped:  # a skipped device's addresses are unknown: never delete prefixes on a partial view
        prefix_actions = [a for a in prefix_actions if a.op != "delete"]
    print(f"prefixes: {len(prefix_actions)} change(s)")
    print_actions("(global)", prefix_actions, None)
    for a in prefix_actions:
        totals[a.op] += 1
    if apply_mode:
        for op in ("create", "delete"):
            items = [({**a.payload} if op == "create" else {"id": a.id}) for a in prefix_actions if a.op == op]
            if items:
                try:
                    client.bulk(op, "prefix", items)
                except Exception as exc:
                    failed.append(f"prefixes {op}: {exc}")

    print(f"summary: {totals['create']} create, {totals['update']} update, {totals['delete']} delete; "
          f"{len(skipped)} skipped, {len(failed)} failed")
    for s in skipped:
        print(f"  SKIPPED {s}")
    for f in failed:
        print(f"  FAILED  {f}")
    return 1 if (apply_mode and (skipped or failed)) else 0


if __name__ == "__main__":
    sys.exit(main())
