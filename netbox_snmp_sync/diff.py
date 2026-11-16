"""Pure diff: (what the device reports, what NetBox has, config) -> Plan.

No I/O. Ownership rules (SPEC.md "Owned fields and diff rules"):
- only objects carrying the sync tag are ever deleted
- untagged interfaces get their operational fields updated but are never deleted
- untagged IP addresses / MACs are never modified
- the device's primary IPs are never deleted
- device-level fields (role, type, platform, site, status) are never in a plan
"""
from __future__ import annotations

import ipaddress

from .config import DeviceConfig
from .model import Action, DeviceState, NbDeviceState, Plan

# IANA ifType -> NetBox interface type. Ethernet is resolved by speed below.
DEFAULT_IFTYPE_MAP: dict[int, str] = {
    24: "virtual",       # softwareLoopback
    53: "virtual",       # propVirtual
    131: "virtual",      # tunnel
    135: "virtual",      # l2vlan
    136: "virtual",      # l3ipvlan
    209: "bridge",       # bridge
    161: "lag",          # ieee8023adLag
    71: "ieee802.11ax",  # ieee80211
}
ETHERNET_BY_SPEED_MBPS = {
    100: "100base-tx", 1000: "1000base-t", 2500: "2.5gbase-t", 5000: "5gbase-t",
    10000: "10gbase-t", 25000: "25gbase-x-sfp28", 40000: "40gbase-x-qsfpp", 100000: "100gbase-x-qsfp28",
}
ETHERNET_IFTYPES = {6, 62, 117}  # ethernetCsmacd, fastEther, gigabitEthernet


def netbox_type(if_type: int, speed_kbps: int | None, cfg: DeviceConfig) -> str:
    if if_type in cfg.iftype_map:
        return cfg.iftype_map[if_type]
    if if_type in ETHERNET_IFTYPES:
        return ETHERNET_BY_SPEED_MBPS.get((speed_kbps or 0) // 1000, "other")
    return DEFAULT_IFTYPE_MAP.get(if_type, "other")


def _tags(cfg: DeviceConfig) -> list[dict]:
    return [{"name": cfg.tag}]


def _excluded_address(addr: str, cfg: DeviceConfig) -> bool:
    ip = ipaddress.ip_interface(addr).ip
    return any(ip in ipaddress.ip_network(n, strict=False) for n in cfg.address_exclude)


def diff_device(dev: DeviceState, nb: NbDeviceState, cfg: DeviceConfig) -> Plan:
    plan = Plan(device=nb.name)
    add = plan.actions.append

    live_ifaces = {n: i for n, i in dev.interfaces.items() if not cfg.excluded(n)}
    live_addrs = [a for a in dev.addresses if a.interface in live_ifaces and not _excluded_address(a.address, cfg)]

    # ------------------------------------------------------------ interfaces
    for name, li in sorted(live_ifaces.items()):
        pinned = cfg.pinned_type(name)
        want_type = pinned or netbox_type(li.if_type, li.speed_kbps, cfg)
        ni = nb.interfaces.get(name)
        if ni is None:
            add(Action("create", "interface", None, {
                "device": nb.device_id, "name": name, "type": want_type, "mtu": li.mtu,
                "speed": li.speed_kbps, "enabled": li.enabled, "description": li.description,
                "tags": _tags(cfg)}, "reported by SNMP, missing in NetBox"))
            continue
        changes = {}
        if li.mtu is not None and ni.mtu != li.mtu:
            changes["mtu"] = li.mtu
        if li.speed_kbps is not None and ni.speed != li.speed_kbps:
            changes["speed"] = li.speed_kbps
        if ni.enabled != li.enabled:
            changes["enabled"] = li.enabled
        if li.description and ni.description != li.description:
            changes["description"] = li.description
        if pinned and ni.type != pinned:  # type is only enforced when pinned by config
            changes["type"] = pinned
        if changes:
            add(Action("update", "interface", ni.id, changes, "changed: " + ", ".join(sorted(changes))))

    # Deleting an interface in NetBox also deletes every IP address and MAC object
    # assigned to it (generic relations cascade). So a tagged interface is only deleted
    # when nothing we must keep hangs off it: no primary IP, no untagged IP, no untagged MAC.
    protected = {p for p in (nb.primary_ip4, nb.primary_ip6) if p}
    for name, ni in sorted(nb.interfaces.items()):
        if not ni.tagged or name in live_ifaces:
            continue
        keepers = [ip.address for ip in nb.ip_addresses.values()
                   if ip.interface_id == ni.id and (not ip.tagged or ip.address in protected)]
        keepers += [m.mac for m in nb.macs if m.interface_id == ni.id and not m.tagged]
        if keepers:
            continue  # reported in the plan summary as a skipped delete by apply's logging
        add(Action("delete", "interface", ni.id, {}, "tagged, no longer reported (or excluded)"))

    # ------------------------------------------------------------ IP addresses
    iface_id = {n: i.id for n, i in nb.interfaces.items()}
    by_addr: dict[str, set[str]] = {}
    for a in live_addrs:
        by_addr.setdefault(a.address, set()).add(a.interface)

    for addr, ifnames in sorted(by_addr.items()):
        existing = nb.ip_addresses.get(addr)
        if existing is None:
            target = sorted(ifnames)[0]
            payload = {"address": addr, "assigned_object_type": "dcim.interface",
                       "assigned_object_id": iface_id.get(target), "tags": _tags(cfg)}
            if cfg.vrf_id is not None:
                payload["vrf"] = cfg.vrf_id
            add(Action("create", "ip", None, payload, f"reported on {target}", interface_name=target))
            continue
        if not existing.tagged:
            continue  # manual / proxbox address: never modified
        current = next((n for n, i in nb.interfaces.items() if i.id == existing.interface_id), None)
        if current in ifnames:
            continue  # already on one of the interfaces that report it: no flapping
        target = sorted(ifnames)[0]
        add(Action("update", "ip", existing.id, {
            "assigned_object_type": "dcim.interface", "assigned_object_id": iface_id.get(target)},
            f"moved {current} -> {target}", interface_name=target))

    for addr, ip in sorted(nb.ip_addresses.items()):
        if ip.tagged and addr not in by_addr and addr not in protected:
            add(Action("delete", "ip", ip.id, {}, "tagged, no longer reported"))

    # ------------------------------------------------------------ MAC addresses
    nb_ifaces_by_id = {i.id: i for i in nb.interfaces.values()}
    tagged_mac_ids = {m.id for m in nb.macs if m.tagged}
    keep_macs: set[int] = set()
    for name, li in sorted(live_ifaces.items()):
        if not li.mac:
            continue
        ni = nb.interfaces.get(name)
        match = next((m for m in nb.macs if m.mac == li.mac and ni and m.interface_id == ni.id), None)
        primary_free = ni is None or ni.primary_mac_id is None or ni.primary_mac_id in tagged_mac_ids
        if match is None:
            add(Action("create", "mac", None, {
                "mac_address": li.mac, "assigned_object_type": "dcim.interface",
                "assigned_object_id": ni.id if ni else None, "tags": _tags(cfg),
                "_set_primary": primary_free}, f"MAC of {name}", interface_name=name))
            continue
        keep_macs.add(match.id)
        if ni is not None and ni.primary_mac_id != match.id and primary_free:
            add(Action("update", "interface", ni.id, {"primary_mac_address": match.id},
                       f"primary MAC -> {li.mac}"))

    for m in nb.macs:
        if m.tagged and m.id not in keep_macs:
            owner = nb_ifaces_by_id.get(m.interface_id)
            add(Action("delete", "mac", m.id, {}, f"tagged MAC {m.mac} on {owner.name if owner else '?'} no longer reported"))

    # One update per object: merge payloads (e.g. mtu change + primary MAC repoint).
    merged: dict[tuple[str, int], Action] = {}
    rest: list[Action] = []
    for a in plan.actions:
        if a.op != "update":
            rest.append(a)
            continue
        key = (a.kind, a.id)
        if key in merged:
            prev = merged[key]
            merged[key] = Action("update", a.kind, a.id, {**prev.payload, **a.payload},
                                 f"{prev.reason}; {a.reason}", prev.interface_name or a.interface_name)
        else:
            merged[key] = a
    plan.actions = rest + list(merged.values())

    order = {"create": 0, "update": 1, "delete": 2}
    kind_order = {"interface": 0, "mac": 1, "ip": 2}
    plan.actions.sort(key=lambda a: (order[a.op], kind_order[a.kind] if a.op != "delete" else -kind_order[a.kind]))
    return plan


def diff_prefixes(live_addresses: list[str], existing_prefixes: list[tuple[int, str, bool]],
                  all_ip_addresses: list[str], tag: str, vrf_id: int | None = None) -> list[Action]:
    """Prefix actions for the whole run (not per device).

    existing_prefixes: (id, prefix, tagged). all_ip_addresses: every IP address in NetBox
    after the device actions (used to find empty tagged prefixes, as ipam-pruner did)."""
    actions: list[Action] = []
    have = {ipaddress.ip_network(p) for _, p, _ in existing_prefixes}
    wanted = set()
    for a in live_addresses:
        iface = ipaddress.ip_interface(a)
        if iface.network.prefixlen in (32, 128):
            continue  # host routes (loopbacks, WireGuard /32s) don't get a prefix
        wanted.add(iface.network)
    for net in sorted(wanted - have, key=lambda n: (n.version, n)):
        payload = {"prefix": str(net), "tags": [{"name": tag}]}
        if vrf_id is not None:
            payload["vrf"] = vrf_id
        actions.append(Action("create", "prefix", None, payload, "network of a reported address"))
    ips = [ipaddress.ip_interface(a).ip for a in [*all_ip_addresses, *live_addresses]]
    for pid, p, tagged in existing_prefixes:
        net = ipaddress.ip_network(p)
        if tagged and not any(ip.version == net.version and ip in net for ip in ips):
            actions.append(Action("delete", "prefix", pid, {}, "tagged prefix with no IP addresses inside"))
    return actions
