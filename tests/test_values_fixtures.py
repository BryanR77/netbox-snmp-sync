import json
from dataclasses import FrozenInstanceError

import pytest

from netbox_snmp_sync.fixtures import load_fixture, save_fixture
from netbox_snmp_sync.values import SnmpValue


def test_fixture_round_trip(tmp_path):
    values = {
        "1.3.6.1.2.1.1.5.0": SnmpValue("octets", b"\x00\xfffw"),
        "1.2": SnmpValue("int", -2),
        "1.3": SnmpValue("oid", "1.3.6.1"),
        "1.4": SnmpValue("ipaddr", "192.0.2.1"),
        "1.5": SnmpValue("counter", 123),
        "1.6": SnmpValue("gauge", 456),
        "1.7": SnmpValue("timeticks", 789),
        "1.8": SnmpValue("null", None),
    }
    path = tmp_path / "device.json"
    save_fixture(path, "fw", "192.0.2.1", values)

    assert load_fixture(path) == ("fw", "192.0.2.1", values)
    fixture = json.loads(path.read_text(encoding="utf-8"))
    assert fixture["values"]["1.3.6.1.2.1.1.5.0"] == {
        "kind": "octets",
        "hex": "00ff6677",
    }
    assert fixture["values"]["1.2"] == {"kind": "int", "value": -2}
    assert fixture["captured_at"].endswith("Z")
    with pytest.raises(FrozenInstanceError):
        values["1.2"].value = 1
