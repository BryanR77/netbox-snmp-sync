"""Guards and plan execution (SPEC.md "Guards").

precheck() decides whether a device's SNMP data is trustworthy enough to diff at all.
limit_deletes() drops a kind's deletes when they look like a broken walk, not reality.
execute() writes a Plan through the NetBox client, resolving ids of objects created in
the same run (an IP or MAC on an interface that was just created).
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

from .model import Action, DeviceState, NbDeviceState, Plan

log = logging.getLogger(__name__)


def precheck(dev: DeviceState, nb: NbDeviceState, match: str = "name") -> str | None:
    """Return a reason to skip this device, or None if it is safe to diff."""
    if not dev.interfaces:
        return "SNMP returned no interfaces"
    if match == "name" and dev.sysname.strip().lower() != nb.name.strip().lower():
        return f"sysName {dev.sysname!r} != NetBox name {nb.name!r}"
    live_ips = {ipaddress.ip_interface(a.address).ip for a in dev.addresses}
    for primary in (nb.primary_ip4, nb.primary_ip6):
        if primary and ipaddress.ip_interface(primary).ip not in live_ips:
            return f"primary IP {primary} not among the addresses SNMP reported"
    return None


def limit_deletes(plan: Plan, nb: NbDeviceState, max_fraction: float, min_allowance: int = 2,
                  force: bool = False) -> list[str]:
    """Remove a kind's deletes from the plan if they exceed max(min_allowance,
    max_fraction * tagged objects of that kind). Returns warnings."""
    if force:
        return []
    tagged = {
        "interface": sum(1 for i in nb.interfaces.values() if i.tagged),
        "ip": sum(1 for i in nb.ip_addresses.values() if i.tagged),
        "mac": sum(1 for m in nb.macs if m.tagged),
    }
    warnings = []
    for kind, total in tagged.items():
        deletes = [a for a in plan.actions if a.op == "delete" and a.kind == kind]
        allowed = max(min_allowance, int(max_fraction * total))
        if len(deletes) > allowed:
            plan.actions = [a for a in plan.actions if not (a.op == "delete" and a.kind == kind)]
            warnings.append(f"{plan.device}: {len(deletes)} {kind} deletes exceed the limit of {allowed} "
                            f"({total} tagged); skipped this run (use --force-deletes to apply)")
    return warnings


@dataclass
class Result:
    device: str
    applied: list[Action] = field(default_factory=list)
    failed: list[tuple[Action, str]] = field(default_factory=list)


def _clean(payload: dict) -> dict:
    return {k: v for k, v in payload.items() if not k.startswith("_")}


def execute(plan: Plan, client, nb: NbDeviceState) -> Result:
    """Apply a device plan. Bulk per (op, kind) in plan order; ids of interfaces created
    here are resolved for the IP/MAC actions that reference them by name."""
    res = Result(plan.device)
    iface_ids = {n: i.id for n, i in nb.interfaces.items()}

    def run(op: str, kind: str, actions: list[Action]):
        if not actions:
            return []
        items = []
        for a in actions:
            p = _clean(a.payload)
            if a.interface_name and p.get("assigned_object_id") is None and "assigned_object_type" in p:
                p["assigned_object_id"] = iface_ids.get(a.interface_name)
                if p["assigned_object_id"] is None:
                    res.failed.append((a, f"interface {a.interface_name} has no id"))
                    continue
            if op in ("update", "delete"):
                p["id"] = a.id
            items.append((a, p))
        if not items:
            return []
        try:
            out = client.bulk(op, kind, [p for _, p in items])
        except Exception as exc:  # one failed batch must not stop the other kinds
            res.failed.extend((a, str(exc)) for a, _ in items)
            return []
        res.applied.extend(a for a, _ in items)
        return list(zip((a for a, _ in items), out or [None] * len(items)))

    # creates: interfaces first (so new ids exist), then MACs, then IPs
    for a, obj in run("create", "interface", [a for a in plan.actions if a.op == "create" and a.kind == "interface"]):
        if obj:
            iface_ids[obj["name"]] = obj["id"]
    primaries = []
    for a, obj in run("create", "mac", [a for a in plan.actions if a.op == "create" and a.kind == "mac"]):
        if obj and a.payload.get("_set_primary") and iface_ids.get(a.interface_name):
            primaries.append(Action("update", "interface", iface_ids[a.interface_name],
                                    {"primary_mac_address": obj["id"]}, f"primary MAC -> {obj.get('mac_address')}"))
    run("create", "ip", [a for a in plan.actions if a.op == "create" and a.kind == "ip"])

    # updates (merge new primary-MAC updates into interface updates for the same id)
    updates = [a for a in plan.actions if a.op == "update"]
    by_id = {(a.kind, a.id): a for a in updates}
    for p in primaries:
        prev = by_id.get(("interface", p.id))
        by_id[("interface", p.id)] = (Action("update", "interface", p.id, {**prev.payload, **p.payload},
                                             f"{prev.reason}; {p.reason}") if prev else p)
    merged = list(by_id.values())
    for kind in ("interface", "mac", "ip"):
        run("update", kind, [a for a in merged if a.kind == kind])

    # deletes in plan order (ip -> mac -> interface)
    for kind in ("ip", "mac", "interface"):
        run("delete", kind, [a for a in plan.actions if a.op == "delete" and a.kind == kind])
    return res
