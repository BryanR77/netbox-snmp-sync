"""Unit tests for pure SNMP collection parser (collect.collect)."""
from __future__ import annotations

import ipaddress
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from netbox_snmp_sync.collect import collect
from netbox_snmp_sync.fixtures import load_fixture
from netbox_snmp_sync.model import Address, DeviceState
from netbox_snmp_sync.values import SnmpValue

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
FIXTURE_NAMES = ("fw", "XMG1915-18EP-1", "NWA210AX-1", "NWA130BE-1")


def _load_and_collect(device_name: str) -> DeviceState:
    device, _host, values = load_fixture(FIXTURE_DIR / f"{device_name}.json")
    state = collect(values)
    v6_addrs = sorted(
        f"{a.interface}: {a.address}"
        for a in state.addresses
        if ipaddress.ip_interface(a.address).version == 6
    )
    if v6_addrs:
        print(f"[{device}] IPv6 addresses: {', '.join(v6_addrs)}")
    else:
        print(f"[{device}] IPv6 addresses: (none)")
    return state


@pytest.mark.parametrize("device_name", FIXTURE_NAMES)
def test_fixture_invariants(device_name: str) -> None:
    state = _load_and_collect(device_name)

    assert state.sysname == device_name
    assert state.sys_object_id
    assert len(state.interfaces) > 0

    # Every collected interface name is non-empty and matches its dict key
    for key, iface in state.interfaces.items():
        assert iface.name != ""
        assert iface.name == key
        assert iface.if_type > 0

    # At least one MAC parses on each device, formatted upper-case colon 6-octet
    macs = [i.mac for i in state.interfaces.values() if i.mac is not None]
    assert len(macs) >= 1
    for mac in macs:
        parts = mac.split(":")
        assert len(parts) == 6
        assert all(len(p) == 2 and p == p.upper() for p in parts)
        assert mac != "00:00:00:00:00:00"

    # Built-in drops: no 0.0.0.0/*, 127.0.0.0/8, ::1, or fe80::/10 in collected addresses
    for addr in state.addresses:
        assert addr.interface in state.interfaces
        ip = ipaddress.ip_interface(addr.address).ip
        if isinstance(ip, ipaddress.IPv4Address):
            assert ip != ipaddress.IPv4Address("0.0.0.0")
            assert ip not in ipaddress.IPv4Network("127.0.0.0/8")
        else:
            assert ip != ipaddress.IPv6Address("::1")
            assert ip not in ipaddress.IPv6Network("fe80::/10")


def test_collect_fw() -> None:
    state = _load_and_collect("fw")

    assert set(state.interfaces) == {
        "lo",
        "eth0",
        "eth1",
        "eth2",
        "pim6reg",
        "eth2.10",
        "eth2.11",
        "wg99",
    }
    assert state.interfaces["eth0"].mtu == 1500
    assert state.interfaces["eth0"].speed_kbps == 100_000
    assert state.interfaces["eth0"].mac == "98:FA:9B:5A:93:D8"
    assert state.interfaces["eth0"].enabled is True
    assert state.interfaces["eth0"].description == "Google Fi"

    assert state.interfaces["eth1"].speed_kbps == 10_000_000
    assert state.interfaces["eth1"].mac == "B8:CE:F6:7A:F6:C6"
    assert state.interfaces["eth1"].description == "Wyyerd WAN"

    assert state.interfaces["pim6reg"].speed_kbps is None
    assert state.interfaces["pim6reg"].mac is None

    # Fixture includes the 5 known ground-truth IPv4s plus wg99's IPv4 and ULA IPv6
    assert state.addresses == frozenset(
        {
            Address("eth0", "48.17.59.117/30"),
            Address("eth1", "38.130.14.41/23"),
            Address("eth2", "192.168.42.1/24"),
            Address("eth2.10", "192.168.43.1/24"),
            Address("eth2.11", "192.168.52.1/24"),
            Address("wg99", "100.96.201.208/16"),
            Address("wg99", "fdf4:5279:9478:1cf7:9336:9158:9c29:2812/64"),
        }
    )


def test_collect_xmg1915() -> None:
    state = _load_and_collect("XMG1915-18EP-1")

    assert "swp00" in state.interfaces
    assert state.interfaces["swp00"].speed_kbps == 2_500_000
    assert state.interfaces["swp00"].mac == "F4:4D:5C:96:75:87"
    assert state.interfaces["swp00"].description == "Port1"

    # 0.0.0.0/0 and 127.0.0.1/16 are dropped; only swp00 192.168.42.3/24 remains
    assert state.addresses == frozenset({Address("swp00", "192.168.42.3/24")})


def test_collect_nwa210ax() -> None:
    state = _load_and_collect("NWA210AX-1")

    assert "br0" in state.interfaces
    assert "lo" in state.interfaces
    assert state.interfaces["lo"].mac is None

    # lo 127.0.0.1/8 is dropped; only br0 192.168.42.4/24 remains
    assert state.addresses == frozenset({Address("br0", "192.168.42.4/24")})


def test_collect_nwa130be() -> None:
    state = _load_and_collect("NWA130BE-1")

    assert "br0" in state.interfaces
    assert "lo" in state.interfaces
    assert state.interfaces["lo"].mac is None

    # lo 127.0.0.1/8 is dropped; only br0 192.168.42.5/24 remains
    assert state.addresses == frozenset({Address("br0", "192.168.42.5/24")})


def test_collect_unit_edge_cases() -> None:
    # ifDescr fallback when ifName is missing, ifSpeed//1000 fallback when ifHighSpeed is 0,
    # all-zero MAC ignored, and duplicate interface name keeps lowest ifIndex
    values = {
        "1.3.6.1.2.1.1.2.0": SnmpValue("oid", "1.3.6.1.4.1.1"),
        "1.3.6.1.2.1.1.5.0": SnmpValue("octets", b"switch1\n"),
        "1.3.6.1.2.1.2.2.1.2.1": SnmpValue("octets", b"FastEthernet0/1"),
        "1.3.6.1.2.1.2.2.1.3.1": SnmpValue("int", 6),
        "1.3.6.1.2.1.2.2.1.4.1": SnmpValue("int", 1500),
        "1.3.6.1.2.1.2.2.1.5.1": SnmpValue("gauge", 100_000_000),
        "1.3.6.1.2.1.2.2.1.6.1": SnmpValue("octets", b"\x00" * 6),
        "1.3.6.1.2.1.2.2.1.7.1": SnmpValue("int", 2),  # admin down
        # Duplicate name at higher ifIndex 2 -> ignored
        "1.3.6.1.2.1.2.2.1.2.2": SnmpValue("octets", b"FastEthernet0/1"),
        "1.3.6.1.2.1.2.2.1.3.2": SnmpValue("int", 6),
        "1.3.6.1.2.1.2.2.1.4.2": SnmpValue("int", 9000),
        "1.3.6.1.2.1.2.2.1.7.2": SnmpValue("int", 1),
    }
    state = collect(values)
    assert state.sysname == "switch1"
    assert list(state.interfaces) == ["FastEthernet0/1"]
    iface = state.interfaces["FastEthernet0/1"]
    assert iface.mtu == 1500
    assert iface.speed_kbps == 100_000
    assert iface.mac is None
    assert iface.enabled is False
