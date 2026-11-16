"""Config: YAML -> dataclasses. Only the per-device part is defined here for now;
the loader for the full file comes with cli.py."""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TypePin:
    match: re.Pattern
    type: str


@dataclass(frozen=True)
class DeviceConfig:
    tag: str = "snmp-discovery"
    vrf_id: int | None = None                       # None = global table
    interface_exclude: tuple[re.Pattern, ...] = ()
    address_exclude: tuple[str, ...] = ()            # CIDRs
    interface_type: tuple[TypePin, ...] = ()         # first match wins
    max_delete_fraction: float = 0.25
    iftype_map: dict[int, str] = field(default_factory=dict)  # overrides of the default ifType map

    def excluded(self, ifname: str) -> bool:
        return any(p.search(ifname) for p in self.interface_exclude)

    def pinned_type(self, ifname: str) -> str | None:
        for pin in self.interface_type:
            if pin.match.search(ifname):
                return pin.type
        return None


def device_config(defaults: dict, device: dict | None, tag: str) -> DeviceConfig:
    """Merge the `defaults` block with one entry of `devices` (lists concatenate,
    scalars override)."""
    device = device or {}
    ex = [*defaults.get("interface_exclude", []), *device.get("interface_exclude", [])]
    addr_ex = [*defaults.get("address_exclude", []), *device.get("address_exclude", [])]
    pins = [*device.get("interface_type", []), *defaults.get("interface_type", [])]
    return DeviceConfig(
        tag=tag,
        vrf_id=device.get("vrf_id", defaults.get("vrf_id")),
        interface_exclude=tuple(re.compile(p) for p in ex),
        address_exclude=tuple(addr_ex),
        interface_type=tuple(TypePin(re.compile(p["match"]), p["type"]) for p in pins),
        max_delete_fraction=float(device.get("max_delete_fraction", defaults.get("max_delete_fraction", 0.25))),
        iftype_map={int(k): v for k, v in {**defaults.get("iftype_map", {}), **device.get("iftype_map", {})}.items()},
    )
