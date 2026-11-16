"""Pure SNMP collection parser: dict[oid, SnmpValue] -> DeviceState."""
from __future__ import annotations

import ipaddress
import logging

from .model import Address, DeviceState, Interface
from .values import SnmpValue

log = logging.getLogger(__name__)

OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

PREFIX_IF_DESCR = "1.3.6.1.2.1.2.2.1.2."
PREFIX_IF_TYPE = "1.3.6.1.2.1.2.2.1.3."
PREFIX_IF_MTU = "1.3.6.1.2.1.2.2.1.4."
PREFIX_IF_SPEED = "1.3.6.1.2.1.2.2.1.5."
PREFIX_IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6."
PREFIX_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7."
PREFIX_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1."
PREFIX_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15."
PREFIX_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18."

PREFIX_IP_AD_ENT_IF_INDEX = "1.3.6.1.2.1.4.20.1.2."
PREFIX_IP_AD_ENT_NET_MASK = "1.3.6.1.2.1.4.20.1.3."

PREFIX_IP_ADDRESS_IF_INDEX = "1.3.6.1.2.1.4.34.1.3."
PREFIX_IP_ADDRESS_TYPE = "1.3.6.1.2.1.4.34.1.4."
PREFIX_IP_ADDRESS_PREFIX = "1.3.6.1.2.1.4.34.1.5."

IPV4_LOOPBACK_NET = ipaddress.IPv4Network("127.0.0.0/8")
IPV6_LINK_LOCAL_NET = ipaddress.IPv6Network("fe80::/10")


def _decode_str(val: SnmpValue | None) -> str:
    if val is None or val.value is None:
        return ""
    if isinstance(val.value, bytes):
        return val.value.decode("utf-8", errors="replace").strip()
    return str(val.value).strip()


def _format_mac(val: SnmpValue | None) -> str | None:
    if val is None or not isinstance(val.value, bytes):
        return None
    raw = val.value
    if len(raw) != 6 or not any(raw):
        return None
    return ":".join(f"{b:02X}" for b in raw)


def _is_dropped_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return ip == ipaddress.IPv4Address("0.0.0.0") or ip in IPV4_LOOPBACK_NET
    return ip == ipaddress.IPv6Address("::1") or ip in IPV6_LINK_LOCAL_NET


def _column_by_int_index(values: dict[str, SnmpValue], prefix: str) -> dict[int, SnmpValue]:
    out: dict[int, SnmpValue] = {}
    for oid, val in values.items():
        if oid.startswith(prefix):
            suffix = oid[len(prefix):]
            if suffix.isdigit():
                out[int(suffix)] = val
    return out


def _column_by_suffix(values: dict[str, SnmpValue], prefix: str) -> dict[str, SnmpValue]:
    return {
        oid[len(prefix):]: val
        for oid, val in values.items()
        if oid.startswith(prefix)
    }


def collect(values: dict[str, SnmpValue]) -> DeviceState:
    sysname = _decode_str(values.get(OID_SYS_NAME))
    sys_object_id = _decode_str(values.get(OID_SYS_OBJECT_ID))

    if_descr = _column_by_int_index(values, PREFIX_IF_DESCR)
    if_type = _column_by_int_index(values, PREFIX_IF_TYPE)
    if_mtu = _column_by_int_index(values, PREFIX_IF_MTU)
    if_speed = _column_by_int_index(values, PREFIX_IF_SPEED)
    if_phys = _column_by_int_index(values, PREFIX_IF_PHYS_ADDRESS)
    if_admin = _column_by_int_index(values, PREFIX_IF_ADMIN_STATUS)
    if_name = _column_by_int_index(values, PREFIX_IF_NAME)
    if_high_speed = _column_by_int_index(values, PREFIX_IF_HIGH_SPEED)
    if_alias = _column_by_int_index(values, PREFIX_IF_ALIAS)

    all_if_indices = sorted(set(if_descr) | set(if_name) | set(if_type))

    interfaces: dict[str, Interface] = {}
    ifindex_to_name: dict[int, str] = {}

    for idx in all_if_indices:
        name = _decode_str(if_name.get(idx)) or _decode_str(if_descr.get(idx))
        if not name:
            continue
        if name in interfaces:
            log.warning("Duplicate interface name %r at ifIndex %d; keeping lowest ifIndex", name, idx)
            continue

        raw_type = if_type.get(idx)
        itype = int(raw_type.value) if raw_type is not None and isinstance(raw_type.value, int) else 1

        raw_mtu = if_mtu.get(idx)
        mtu = int(raw_mtu.value) if raw_mtu is not None and isinstance(raw_mtu.value, int) and raw_mtu.value > 0 else None

        raw_hs = if_high_speed.get(idx)
        hs_val = int(raw_hs.value) if raw_hs is not None and isinstance(raw_hs.value, int) else 0
        raw_spd = if_speed.get(idx)
        spd_val = int(raw_spd.value) if raw_spd is not None and isinstance(raw_spd.value, int) else 0

        if hs_val > 0:
            speed_kbps: int | None = hs_val * 1000
        elif spd_val // 1000 > 0:
            speed_kbps = spd_val // 1000
        else:
            speed_kbps = None

        mac = _format_mac(if_phys.get(idx))

        raw_admin = if_admin.get(idx)
        enabled = bool(raw_admin is not None and raw_admin.value == 1)

        description = _decode_str(if_alias.get(idx))

        interfaces[name] = Interface(
            name=name,
            if_type=itype,
            mtu=mtu,
            speed_kbps=speed_kbps,
            mac=mac,
            enabled=enabled,
            description=description,
        )
        ifindex_to_name[idx] = name

    # Parse ipAddressTable (1.3.6.1.2.1.4.34.1)
    addr_if_index = _column_by_suffix(values, PREFIX_IP_ADDRESS_IF_INDEX)
    addr_type = _column_by_suffix(values, PREFIX_IP_ADDRESS_TYPE)
    addr_prefix = _column_by_suffix(values, PREFIX_IP_ADDRESS_PREFIX)

    addresses: set[Address] = set()
    has_v4_from_434 = False

    for suffix, if_idx_val in addr_if_index.items():
        if not isinstance(if_idx_val.value, int):
            continue
        ifname = ifindex_to_name.get(if_idx_val.value)
        if ifname is None:
            continue

        type_val = addr_type.get(suffix)
        if type_val is None or type_val.value != 1:  # 1 == unicast
            continue

        parts = [int(p) for p in suffix.split(".") if p.isdigit()]
        if len(parts) < 2:
            continue
        af, length, octets = parts[0], parts[1], parts[2:]
        if af == 1 and length == 4 and len(octets) == 4:
            ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.IPv4Address(bytes(octets))
            max_prefix = 32
        elif af == 2 and length == 16 and len(octets) == 16:
            ip_obj = ipaddress.IPv6Address(bytes(octets))
            max_prefix = 128
        else:
            continue

        pfx_val = addr_prefix.get(suffix)
        if pfx_val is None or not isinstance(pfx_val.value, str) or pfx_val.value in ("", "0.0"):
            continue
        last_comp = pfx_val.value.rsplit(".", 1)[-1]
        if not last_comp.isdigit():
            continue
        prefixlen = int(last_comp)
        if not (0 <= prefixlen <= max_prefix):
            continue

        if af == 1:
            has_v4_from_434 = True

        if _is_dropped_ip(ip_obj):
            continue

        iface_addr = ipaddress.ip_interface(f"{ip_obj}/{prefixlen}")
        addresses.add(Address(interface=ifname, address=str(iface_addr)))

    # Fallback to ipAddrTable (1.3.6.1.2.1.4.20.1) for IPv4 if 4.34 yielded no IPv4 addresses
    if not has_v4_from_434:
        legacy_if_index = _column_by_suffix(values, PREFIX_IP_AD_ENT_IF_INDEX)
        legacy_netmask = _column_by_suffix(values, PREFIX_IP_AD_ENT_NET_MASK)
        for ip_str, if_idx_val in legacy_if_index.items():
            if not isinstance(if_idx_val.value, int):
                continue
            ifname = ifindex_to_name.get(if_idx_val.value)
            if ifname is None:
                continue
            mask_val = legacy_netmask.get(ip_str)
            if mask_val is None or not isinstance(mask_val.value, str):
                continue
            try:
                iface_addr = ipaddress.IPv4Interface(f"{ip_str}/{mask_val.value}")
            except ValueError:
                continue
            if _is_dropped_ip(iface_addr.ip):
                continue
            addresses.add(Address(interface=ifname, address=str(iface_addr)))

    return DeviceState(
        sysname=sysname,
        sys_object_id=sys_object_id,
        interfaces=interfaces,
        addresses=frozenset(addresses),
    )
