"""Data model shared by collect (SNMP side), netbox (NetBox side) and diff.

SNMP side: what the device reports, normalized. NetBox side: the subset of NetBox
objects for one device that the diff needs, with ids and ownership (tagged or not).
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------- SNMP side

@dataclass(frozen=True)
class Interface:
    name: str                 # ifName, else ifDescr
    if_type: int              # IANA ifType number
    mtu: int | None
    speed_kbps: int | None    # None when the device reports 0
    mac: str | None           # "AA:BB:CC:DD:EE:FF"; None if empty/all-zero
    enabled: bool             # ifAdminStatus == up
    description: str          # ifAlias, stripped ("" if none)


@dataclass(frozen=True)
class Address:
    interface: str            # Interface.name
    address: str              # str(ipaddress.ip_interface(...)), e.g. "192.0.2.1/24"


@dataclass(frozen=True)
class DeviceState:
    sysname: str
    sys_object_id: str
    interfaces: dict[str, Interface]
    addresses: frozenset[Address]


# ---------------------------------------------------------------- NetBox side

@dataclass(frozen=True)
class NbInterface:
    id: int
    name: str
    type: str                 # NetBox interface type slug
    mtu: int | None
    speed: int | None         # kbps, as NetBox stores it
    enabled: bool
    description: str
    tagged: bool              # carries the sync tag (owned by us)
    primary_mac_id: int | None


@dataclass(frozen=True)
class NbIpAddress:
    id: int
    address: str              # "192.0.2.1/24"
    interface_id: int | None  # assigned dcim.interface id, None if unassigned/other
    tagged: bool


@dataclass(frozen=True)
class NbMac:
    id: int
    mac: str                  # upper-case colon form
    interface_id: int | None
    tagged: bool


@dataclass(frozen=True)
class NbDeviceState:
    device_id: int
    name: str
    primary_ip4: str | None   # address string of the primary IPv4, if any
    primary_ip6: str | None
    interfaces: dict[str, NbInterface]          # by name
    ip_addresses: dict[str, NbIpAddress]        # by address string
    macs: list[NbMac] = field(default_factory=list)


# ---------------------------------------------------------------- plan

@dataclass(frozen=True)
class Action:
    op: str                   # "create" | "update" | "delete"
    kind: str                 # "interface" | "ip" | "mac" | "prefix"
    id: int | None            # NetBox id for update/delete
    payload: dict             # fields to write (create/update); {} for delete
    reason: str
    # For creates that refer to an object created in the same run (an IP on a new
    # interface), the interface is named here and resolved to an id at apply time.
    interface_name: str | None = None


@dataclass
class Plan:
    device: str
    actions: list[Action] = field(default_factory=list)

    def by_op(self, op: str) -> list[Action]:
        return [a for a in self.actions if a.op == op]
