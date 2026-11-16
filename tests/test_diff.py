"""Unit tests for pure diff logic (diff_device and diff_prefixes)."""
from __future__ import annotations

from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from netbox_snmp_sync.config import DeviceConfig, TypePin
from netbox_snmp_sync.diff import diff_device, diff_prefixes
from netbox_snmp_sync.model import (
    Action,
    Address,
    DeviceState,
    Interface,
    NbDeviceState,
    NbInterface,
    NbIpAddress,
    NbMac,
)


def _dev(
    interfaces: list[Interface] | None = None,
    addresses: list[Address] | None = None,
    sysname: str = "rtr1",
    sys_object_id: str = "1.3.6.1.4.1.9999",
) -> DeviceState:
    return DeviceState(
        sysname=sysname,
        sys_object_id=sys_object_id,
        interfaces={i.name: i for i in (interfaces or [])},
        addresses=frozenset(addresses or []),
    )


def _nb(
    interfaces: list[NbInterface] | None = None,
    ip_addresses: list[NbIpAddress] | None = None,
    macs: list[NbMac] | None = None,
    primary_ip4: str | None = None,
    primary_ip6: str | None = None,
    device_id: int = 1,
    name: str = "rtr1",
) -> NbDeviceState:
    return NbDeviceState(
        device_id=device_id,
        name=name,
        primary_ip4=primary_ip4,
        primary_ip6=primary_ip6,
        interfaces={i.name: i for i in (interfaces or [])},
        ip_addresses={ip.address: ip for ip in (ip_addresses or [])},
        macs=list(macs or []),
    )


# (1) interface missing in NetBox -> one create with the sync tag
def test_interface_missing_in_netbox_creates_with_tag() -> None:
    dev = _dev(
        interfaces=[
            Interface(
                name="eth0",
                if_type=6,
                mtu=1500,
                speed_kbps=1_000_000,
                mac=None,
                enabled=True,
                description="uplink",
            )
        ]
    )
    nb = _nb()
    cfg = DeviceConfig(tag="snmp-discovery")

    plan = diff_device(dev, nb, cfg)

    assert len(plan.actions) == 1
    act = plan.actions[0]
    assert act.op == "create"
    assert act.kind == "interface"
    assert act.id is None
    assert act.payload == {
        "device": 1,
        "name": "eth0",
        "type": "1000base-t",
        "mtu": 1500,
        "speed": 1_000_000,
        "enabled": True,
        "description": "uplink",
        "tags": [{"name": "snmp-discovery"}],
    }


# (2) only owned fields changed -> update payload contains only mtu/speed/enabled/description keys that changed
def test_interface_update_contains_only_changed_owned_fields() -> None:
    dev = _dev(
        interfaces=[
            Interface(
                name="eth0",
                if_type=6,
                mtu=9000,               # changed from 1500
                speed_kbps=1_000_000,   # unchanged
                mac=None,
                enabled=False,          # changed from True
                description="uplink",   # unchanged
            ),
            Interface(
                name="eth1",
                if_type=6,
                mtu=1500,               # unchanged
                speed_kbps=10_000_000,  # changed from 1_000_000
                mac=None,
                enabled=True,           # unchanged
                description="new-desc", # changed from "old-desc"
            ),
        ]
    )
    nb = _nb(
        interfaces=[
            NbInterface(
                id=10,
                name="eth0",
                type="1000base-t",
                mtu=1500,
                speed=1_000_000,
                enabled=True,
                description="uplink",
                tagged=False,
                primary_mac_id=None,
            ),
            NbInterface(
                id=11,
                name="eth1",
                type="1000base-t",
                mtu=1500,
                speed=1_000_000,
                enabled=True,
                description="old-desc",
                tagged=True,
                primary_mac_id=None,
            ),
        ]
    )

    plan = diff_device(dev, nb, DeviceConfig())

    assert len(plan.actions) == 2
    by_id = {a.id: a for a in plan.actions}
    assert by_id[10].op == "update"
    assert by_id[10].kind == "interface"
    assert by_id[10].payload == {"mtu": 9000, "enabled": False}

    assert by_id[11].op == "update"
    assert by_id[11].kind == "interface"
    assert by_id[11].payload == {"speed": 10_000_000, "description": "new-desc"}


# (3) identical state -> empty plan
def test_identical_state_produces_empty_plan() -> None:
    dev = _dev(
        interfaces=[
            Interface(
                name="eth0",
                if_type=6,
                mtu=1500,
                speed_kbps=1_000_000,
                mac="AA:BB:CC:DD:EE:FF",
                enabled=True,
                description="lan",
            )
        ],
        addresses=[Address(interface="eth0", address="192.0.2.1/24")],
    )
    nb = _nb(
        primary_ip4="192.0.2.1/24",
        interfaces=[
            NbInterface(
                id=10,
                name="eth0",
                type="1000base-t",
                mtu=1500,
                speed=1_000_000,
                enabled=True,
                description="lan",
                tagged=True,
                primary_mac_id=30,
            )
        ],
        ip_addresses=[
            NbIpAddress(id=20, address="192.0.2.1/24", interface_id=10, tagged=True)
        ],
        macs=[
            NbMac(id=30, mac="AA:BB:CC:DD:EE:FF", interface_id=10, tagged=True)
        ],
    )

    plan = diff_device(dev, nb, DeviceConfig())

    assert plan.actions == []


# (4) empty SNMP description does not blank a NetBox description
def test_empty_snmp_description_does_not_blank_netbox_description() -> None:
    dev = _dev(
        interfaces=[
            Interface(
                name="eth0",
                if_type=6,
                mtu=1500,
                speed_kbps=1_000_000,
                mac=None,
                enabled=True,
                description="",
            )
        ]
    )
    nb = _nb(
        interfaces=[
            NbInterface(
                id=10,
                name="eth0",
                type="1000base-t",
                mtu=1500,
                speed=1_000_000,
                enabled=True,
                description="Manually documented port",
                tagged=True,
                primary_mac_id=None,
            )
        ]
    )

    plan = diff_device(dev, nb, DeviceConfig())

    assert plan.actions == []


# (5) type is NOT changed for an existing interface unless a config interface_type pin matches, and IS changed when pinned
def test_interface_type_only_changed_when_pinned() -> None:
    dev = _dev(
        interfaces=[
            Interface(
                name="eth0",
                if_type=6,
                mtu=1500,
                speed_kbps=1_000_000,  # unpinned default would be 1000base-t
                mac=None,
                enabled=True,
                description="",
            ),
            Interface(
                name="eth1",
                if_type=6,
                mtu=1500,
                speed_kbps=1_000_000,
                mac=None,
                enabled=True,
                description="",
            ),
        ]
    )
    nb = _nb(
        interfaces=[
            NbInterface(
                id=10,
                name="eth0",
                type="other",
                mtu=1500,
                speed=1_000_000,
                enabled=True,
                description="",
                tagged=True,
                primary_mac_id=None,
            ),
            NbInterface(
                id=11,
                name="eth1",
                type="other",
                mtu=1500,
                speed=1_000_000,
                enabled=True,
                description="",
                tagged=True,
                primary_mac_id=None,
            ),
        ]
    )
    cfg = DeviceConfig(
        interface_type=(TypePin(match=re.compile(r"^eth1$"), type="25gbase-x-sfp28"),)
    )

    plan = diff_device(dev, nb, cfg)

    assert len(plan.actions) == 1
    act = plan.actions[0]
    assert act.op == "update"
    assert act.kind == "interface"
    assert act.id == 11
    assert act.payload == {"type": "25gbase-x-sfp28"}


# (6) untagged NetBox interface missing from SNMP is not deleted, tagged one is
def test_missing_interface_deletes_tagged_but_keeps_untagged() -> None:
    dev = _dev(interfaces=[])
    nb = _nb(
        interfaces=[
            NbInterface(
                id=10,
                name="mgmt0",
                type="1000base-t",
                mtu=1500,
                speed=1_000_000,
                enabled=True,
                description="",
                tagged=False,
                primary_mac_id=None,
            ),
            NbInterface(
                id=11,
                name="old-vlan",
                type="virtual",
                mtu=1500,
                speed=None,
                enabled=True,
                description="",
                tagged=True,
                primary_mac_id=None,
            ),
        ]
    )

    plan = diff_device(dev, nb, DeviceConfig())

    assert len(plan.actions) == 1
    act = plan.actions[0]
    assert act == Action(
        op="delete",
        kind="interface",
        id=11,
        payload={},
        reason=act.reason,
    )


# (7) excluded interface (config regex) that exists tagged in NetBox is deleted and its addresses are not created
def test_excluded_interface_deleted_if_tagged_and_addresses_not_created() -> None:
    dev = _dev(
        interfaces=[
            Interface(
                name="pim6reg",
                if_type=53,
                mtu=1472,
                speed_kbps=None,
                mac=None,
                enabled=True,
                description="",
            )
        ],
        addresses=[Address(interface="pim6reg", address="10.99.0.1/24")],
    )
    nb = _nb(
        interfaces=[
            NbInterface(
                id=15,
                name="pim6reg",
                type="virtual",
                mtu=1472,
                speed=None,
                enabled=True,
                description="",
                tagged=True,
                primary_mac_id=None,
            )
        ]
    )
    cfg = DeviceConfig(interface_exclude=(re.compile(r"^pim6reg$"),))

    plan = diff_device(dev, nb, cfg)

    assert len(plan.actions) == 1
    act = plan.actions[0]
    assert act.op == "delete"
    assert act.kind == "interface"
    assert act.id == 15
    assert not any(a.kind == "ip" for a in plan.actions)


# (8) untagged IP never updated or deleted
def test_untagged_ip_never_updated_or_deleted() -> None:
    dev = _dev(
        interfaces=[
            Interface("eth0", 6, 1500, 1_000_000, None, True, ""),
            Interface("eth1", 6, 1500, 1_000_000, None, True, ""),
        ],
        # 192.0.2.10/24 is reported on eth1, but in NetBox it is untagged on eth0.
        # 192.0.2.20/24 is absent from SNMP, and in NetBox it is untagged on eth0.
        addresses=[Address(interface="eth1", address="192.0.2.10/24")],
    )
    nb = _nb(
        interfaces=[
            NbInterface(10, "eth0", "1000base-t", 1500, 1_000_000, True, "", True, None),
            NbInterface(11, "eth1", "1000base-t", 1500, 1_000_000, True, "", True, None),
        ],
        ip_addresses=[
            NbIpAddress(id=20, address="192.0.2.10/24", interface_id=10, tagged=False),
            NbIpAddress(id=21, address="192.0.2.20/24", interface_id=10, tagged=False),
        ],
    )

    plan = diff_device(dev, nb, DeviceConfig())

    assert plan.actions == []


# (9) tagged IP equal to the device primary_ip4 is never deleted
def test_tagged_primary_ip4_is_never_deleted() -> None:
    dev = _dev(
        interfaces=[Interface("eth0", 6, 1500, 1_000_000, None, True, "")],
        addresses=[],
    )
    nb = _nb(
        primary_ip4="192.0.2.1/24",
        interfaces=[
            NbInterface(10, "eth0", "1000base-t", 1500, 1_000_000, True, "", True, None)
        ],
        ip_addresses=[
            NbIpAddress(id=20, address="192.0.2.1/24", interface_id=10, tagged=True),
            NbIpAddress(id=21, address="192.0.2.2/24", interface_id=10, tagged=True),
        ],
    )

    plan = diff_device(dev, nb, DeviceConfig())

    assert len(plan.actions) == 1
    assert plan.actions[0].op == "delete"
    assert plan.actions[0].kind == "ip"
    assert plan.actions[0].id == 21


# (10) an address live on two interfaces where NetBox already has it on one of them -> no action (no flapping)
def test_address_live_on_two_interfaces_does_not_flap() -> None:
    dev = _dev(
        interfaces=[
            Interface("eth0", 6, 1500, 1_000_000, None, True, ""),
            Interface("eth1", 6, 1500, 1_000_000, None, True, ""),
        ],
        addresses=[
            Address(interface="eth0", address="192.0.2.1/24"),
            Address(interface="eth1", address="192.0.2.1/24"),
        ],
    )
    # Assigned to eth1 (not the first alphabetically), should still be kept without update
    nb = _nb(
        interfaces=[
            NbInterface(10, "eth0", "1000base-t", 1500, 1_000_000, True, "", True, None),
            NbInterface(11, "eth1", "1000base-t", 1500, 1_000_000, True, "", True, None),
        ],
        ip_addresses=[
            NbIpAddress(id=20, address="192.0.2.1/24", interface_id=11, tagged=True)
        ],
    )

    plan = diff_device(dev, nb, DeviceConfig())

    assert plan.actions == []


# (11) tagged IP on the wrong interface -> one update moving it
def test_tagged_ip_on_wrong_interface_moves_it() -> None:
    dev = _dev(
        interfaces=[
            Interface("eth0", 6, 1500, 1_000_000, None, True, ""),
            Interface("eth1", 6, 1500, 1_000_000, None, True, ""),
        ],
        addresses=[Address(interface="eth1", address="192.0.2.1/24")],
    )
    nb = _nb(
        interfaces=[
            NbInterface(10, "eth0", "1000base-t", 1500, 1_000_000, True, "", True, None),
            NbInterface(11, "eth1", "1000base-t", 1500, 1_000_000, True, "", True, None),
        ],
        ip_addresses=[
            NbIpAddress(id=20, address="192.0.2.1/24", interface_id=10, tagged=True)
        ],
    )

    plan = diff_device(dev, nb, DeviceConfig())

    assert len(plan.actions) == 1
    act = plan.actions[0]
    assert act.op == "update"
    assert act.kind == "ip"
    assert act.id == 20
    assert act.payload == {
        "assigned_object_type": "dcim.interface",
        "assigned_object_id": 11,
    }
    assert act.interface_name == "eth1"


# (12) MAC create sets _set_primary True when the interface has no primary MAC, False when primary is an untagged MAC
def test_mac_create_sets_primary_flag_based_on_existing_primary() -> None:
    dev = _dev(
        interfaces=[
            Interface("eth0", 6, 1500, 1_000_000, "AA:BB:CC:00:00:01", True, ""),
            Interface("eth1", 6, 1500, 1_000_000, "AA:BB:CC:00:00:02", True, ""),
        ]
    )
    nb = _nb(
        interfaces=[
            NbInterface(10, "eth0", "1000base-t", 1500, 1_000_000, True, "", True, primary_mac_id=None),
            NbInterface(11, "eth1", "1000base-t", 1500, 1_000_000, True, "", True, primary_mac_id=99),
        ],
        macs=[
            NbMac(id=99, mac="00:11:22:33:44:55", interface_id=11, tagged=False),
        ],
    )

    plan = diff_device(dev, nb, DeviceConfig())

    mac_creates = {a.interface_name: a for a in plan.actions if a.op == "create" and a.kind == "mac"}
    assert set(mac_creates) == {"eth0", "eth1"}
    assert mac_creates["eth0"].payload["_set_primary"] is True
    assert mac_creates["eth1"].payload["_set_primary"] is False


# (13) stale tagged MAC deleted, untagged never
def test_stale_tagged_mac_deleted_untagged_kept() -> None:
    dev = _dev(
        interfaces=[
            Interface("eth0", 6, 1500, 1_000_000, None, True, ""),
        ]
    )
    nb = _nb(
        interfaces=[
            NbInterface(10, "eth0", "1000base-t", 1500, 1_000_000, True, "", True, primary_mac_id=None),
        ],
        macs=[
            NbMac(id=30, mac="AA:BB:CC:00:00:01", interface_id=10, tagged=True),
            NbMac(id=31, mac="AA:BB:CC:00:00:02", interface_id=10, tagged=False),
        ],
    )

    plan = diff_device(dev, nb, DeviceConfig())

    assert len(plan.actions) == 1
    act = plan.actions[0]
    assert act.op == "delete"
    assert act.kind == "mac"
    assert act.id == 30


# (14) action ordering: creates, then updates, then deletes, and deletes go ip -> mac -> interface
def test_action_ordering_creates_updates_deletes_and_delete_reverse_dependency() -> None:
    dev = _dev(
        interfaces=[
            # new interface -> create interface, create mac, create ip
            Interface("eth0", 6, 1500, 1_000_000, "AA:BB:CC:00:00:01", True, "new"),
            # existing interface -> update interface
            Interface("eth1", 6, 9000, 1_000_000, None, True, "updated"),
        ],
        addresses=[
            Address(interface="eth0", address="192.0.2.1/24"),
            # existing IP moved to eth1 -> update ip
            Address(interface="eth1", address="192.0.2.2/24"),
        ],
    )
    nb = _nb(
        interfaces=[
            NbInterface(11, "eth1", "1000base-t", 1500, 1_000_000, True, "old", True, None),
            # stale interface -> delete interface
            NbInterface(12, "eth2", "1000base-t", 1500, 1_000_000, True, "", True, None),
        ],
        ip_addresses=[
            NbIpAddress(id=20, address="192.0.2.2/24", interface_id=12, tagged=True),
            # stale IP -> delete ip
            NbIpAddress(id=21, address="198.51.100.1/24", interface_id=12, tagged=True),
        ],
        macs=[
            # stale MAC -> delete mac
            NbMac(id=30, mac="AA:BB:CC:00:00:99", interface_id=12, tagged=True),
        ],
    )

    plan = diff_device(dev, nb, DeviceConfig())

    ops_and_kinds = [(a.op, a.kind) for a in plan.actions]
    assert ops_and_kinds == [
        ("create", "interface"),
        ("create", "mac"),
        ("create", "ip"),
        ("update", "interface"),
        ("update", "ip"),
        ("delete", "ip"),
        ("delete", "mac"),
        ("delete", "interface"),
    ]


# (15) diff_prefixes: creates the network of a /24 address, skips /32 and /128,
# never duplicates an existing (untagged) prefix, deletes a tagged prefix with no
# addresses inside, keeps an untagged empty one.
def test_diff_prefixes_lifecycle() -> None:
    live_addresses = [
        "192.0.2.1/24",        # missing -> should create 192.0.2.0/24
        "10.0.0.5/24",         # already exists untagged -> should not duplicate
        "198.51.100.10/32",    # /32 -> skipped
        "2001:db8::1/128",     # /128 -> skipped
    ]
    existing_prefixes = [
        (1, "10.0.0.0/24", False),     # untagged, has live address -> keep, do not duplicate
        (2, "172.16.0.0/24", True),    # tagged, empty -> delete
        (3, "172.16.1.0/24", False),   # untagged, empty -> keep
        (4, "203.0.113.0/24", True),   # tagged, has address in all_ip_addresses -> keep
    ]
    all_ip_addresses = [
        "203.0.113.42/24",
    ]

    actions = diff_prefixes(
        live_addresses=live_addresses,
        existing_prefixes=existing_prefixes,
        all_ip_addresses=all_ip_addresses,
        tag="snmp-discovery",
    )

    assert actions == [
        Action(
            op="create",
            kind="prefix",
            id=None,
            payload={"prefix": "192.0.2.0/24", "tags": [{"name": "snmp-discovery"}]},
            reason="network of a reported address",
        ),
        Action(
            op="delete",
            kind="prefix",
            id=2,
            payload={},
            reason="tagged prefix with no IP addresses inside",
        ),
    ]


# --- added after review: interface deletes must not cascade into kept objects
def test_tagged_interface_holding_primary_or_untagged_objects_is_not_deleted():
    from netbox_snmp_sync.model import DeviceState, NbDeviceState, NbInterface, NbIpAddress, NbMac
    from netbox_snmp_sync.config import DeviceConfig
    from netbox_snmp_sync.diff import diff_device
    gone = lambda i, n: NbInterface(i, n, "virtual", None, None, True, "", True, None)
    nb = NbDeviceState(1, "d", "10.0.0.1/24", None,
                       {"a": gone(1, "a"), "b": gone(2, "b"), "c": gone(3, "c"), "d": gone(4, "d")},
                       {"10.0.0.1/24": NbIpAddress(10, "10.0.0.1/24", 1, True),     # primary on a
                        "10.0.1.1/24": NbIpAddress(11, "10.0.1.1/24", 2, False)},   # manual IP on b
                       [NbMac(20, "AA:BB:CC:DD:EE:FF", 3, False)])                  # manual MAC on c
    plan = diff_device(DeviceState("d", "1.3", {}, frozenset()), nb, DeviceConfig())
    deleted = {a.id for a in plan.actions if a.op == "delete" and a.kind == "interface"}
    assert deleted == {4}


def test_field_update_and_primary_mac_repoint_merge_into_one_update():
    from netbox_snmp_sync.model import DeviceState, Interface, NbDeviceState, NbInterface, NbMac
    from netbox_snmp_sync.config import DeviceConfig
    from netbox_snmp_sync.diff import diff_device
    li = Interface("eth0", 6, 9000, 1_000_000, "AA:BB:CC:DD:EE:FF", True, "")
    ni = NbInterface(1, "eth0", "1000base-t", 1500, 1_000_000, True, "", True, None)
    nb = NbDeviceState(1, "d", None, None, {"eth0": ni}, {}, [NbMac(5, "AA:BB:CC:DD:EE:FF", 1, True)])
    ups = [a for a in diff_device(DeviceState("d", "1.3", {"eth0": li}, frozenset()), nb, DeviceConfig()).actions if a.op == "update"]
    assert len(ups) == 1 and ups[0].payload == {"mtu": 9000, "primary_mac_address": 5}
