import io
import json
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import pytest

from netbox_snmp_sync.model import NbDeviceState, NbInterface, NbIpAddress, NbMac
from netbox_snmp_sync.netbox import NetBox, NetBoxError


class FakeOpener:
    def __init__(self, handler):
        self.handler = handler
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        assert request.get_header("Authorization") == "Token secret"
        assert request.get_header("Accept") == "application/json"
        assert request.get_header("Content-type") == "application/json"
        return self.handler(request)


def json_response(data, status=200):
    return status, json.dumps(data).encode()


def page(results, next_url=None):
    return {"results": results, "next": next_url}


def device(id=1, name="fw", site=None):
    return {
        "id": id,
        "name": name,
        "site": site or {"name": "Home", "slug": "home"},
        "primary_ip4": {"address": "192.0.2.1/24"},
        "primary_ip6": {"address": "2001:db8::1/64"},
    }


def interface(id, name, tags, primary_mac=None):
    return {
        "id": id,
        "name": name,
        "type": {"value": "1000base-t", "label": "1000BASE-T"},
        "mtu": None,
        "speed": None,
        "enabled": True,
        "description": "",
        "tags": tags,
        "primary_mac_address": primary_mac,
    }


def test_get_device_state_paginates_and_maps_fields():
    def respond(request):
        url = urlsplit(request.full_url)
        query = parse_qs(url.query)
        assert query["limit"] == ["2"]
        if url.path == "/netbox/api/dcim/devices/":
            assert query["name"] == ["fw"]
            return json_response(page([device(), device(2, site={"name": "Other", "slug": "other"})]))
        assert query["device_id"] == ["1"]
        if url.path == "/netbox/api/dcim/interfaces/":
            if query.get("offset") == ["2"]:
                return json_response(page([interface(11, "eth1", [{"name": "other", "slug": "owned"}])]))
            return json_response(
                page(
                    [interface(10, "eth0", [{"name": "owned", "slug": "other"}], {"id": 30})],
                    "?device_id=1&limit=2&offset=2",
                )
            )
        if url.path == "/netbox/api/ipam/ip-addresses/":
            return json_response(page([
                {"id": 20, "address": "192.0.2.1/24", "assigned_object_type": "dcim.interface",
                 "assigned_object_id": 10, "tags": [{"name": "owned", "slug": "different"}]},
                {"id": 21, "address": "192.0.2.2/24", "assigned_object_type": "dcim.device",
                 "assigned_object_id": 1, "tags": []},
            ]))
        if url.path == "/netbox/api/dcim/mac-addresses/":
            return json_response(page([
                {"id": 30, "mac_address": "aa:bb:cc:dd:ee:ff", "assigned_object_type": "dcim.interface",
                 "assigned_object_id": 10, "tags": [{"name": "other", "slug": "owned"}]},
                {"id": 31, "mac_address": "00:11:22:33:44:55", "assigned_object_type": None,
                 "assigned_object_id": None, "tags": []},
            ]))
        pytest.fail(f"Unexpected URL: {request.full_url}")

    fake = FakeOpener(respond)
    client = NetBox("https://netbox.example/netbox/", "secret", page_size=2, opener=fake)
    state = client.get_device_state("fw", "home", "owned")
    assert state == NbDeviceState(
        device_id=1,
        name="fw",
        primary_ip4="192.0.2.1/24",
        primary_ip6="2001:db8::1/64",
        interfaces={
            "eth0": NbInterface(10, "eth0", "1000base-t", None, None, True, "", True, 30),
            "eth1": NbInterface(11, "eth1", "1000base-t", None, None, True, "", True, None),
        },
        ip_addresses={
            "192.0.2.1/24": NbIpAddress(20, "192.0.2.1/24", 10, True),
            "192.0.2.2/24": NbIpAddress(21, "192.0.2.2/24", None, False),
        },
        macs=[
            NbMac(30, "AA:BB:CC:DD:EE:FF", 10, True),
            NbMac(31, "00:11:22:33:44:55", None, False),
        ],
    )
    assert len(fake.requests) == 5


@pytest.mark.parametrize("devices", [
    [],
    [device(1), device(2)],
    [device(site={"name": "Elsewhere", "slug": "elsewhere"})],
    [device(name="fw-other")],
])
def test_device_not_found_or_duplicate(devices):
    fake = FakeOpener(lambda request: json_response(page(devices)))
    with pytest.raises(NetBoxError, match="Expected one device"):
        NetBox("https://netbox.example", "secret", opener=fake).get_device_state("fw", "home", "owned")
    assert len(fake.requests) == 1


def test_site_name_and_missing_primary_ips():
    entry = device()
    entry["primary_ip4"] = entry["primary_ip6"] = None

    def respond(request):
        return json_response(page([entry] if urlsplit(request.full_url).path.endswith("/devices/") else []))

    state = NetBox("https://netbox.example", "secret", opener=FakeOpener(respond)).get_device_state("fw", "Home", "owned")
    assert state.primary_ip4 is None and state.primary_ip6 is None


def test_prefixes_and_global_ip_addresses():
    def respond(request):
        url = urlsplit(request.full_url)
        query = parse_qs(url.query)
        assert query["limit"] == ["1000"]
        if url.path.endswith("/prefixes/"):
            assert "tag" not in query
            if "offset" not in query:
                return json_response(page(
                    [{"id": 1, "prefix": "192.0.2.0/24", "tags": [{"name": "owned"}]}],
                    "https://netbox.example/api/ipam/prefixes/?limit=1000&offset=1",
                ))
            return json_response(page([
                {"id": 2, "prefix": "2001:db8::/32", "tags": [{"slug": "owned"}]},
                {"id": 3, "prefix": "198.51.100.0/24", "tags": []},
            ]))
        assert url.path.endswith("/ip-addresses/") and query["brief"] == ["1"]
        return json_response(page([{"address": "192.0.2.1/24"}, {"address": "2001:db8::1/64"}]))

    client = NetBox("https://netbox.example", "secret", opener=FakeOpener(respond))
    assert client.list_prefixes("owned") == [
        (1, "192.0.2.0/24", True), (2, "2001:db8::/32", True), (3, "198.51.100.0/24", False)
    ]
    assert client.list_ip_addresses() == ["192.0.2.1/24", "2001:db8::1/64"]


def test_bulk_create_chunks_and_returns_results():
    fake = FakeOpener(lambda request: json_response(json.loads(request.data), 201))
    client = NetBox("https://netbox.example", "secret", opener=fake)
    items = [{"name": f"eth{i}"} for i in range(250)]
    assert client.bulk("create", "interface", items) == items
    assert [len(json.loads(request.data)) for request in fake.requests] == [100, 100, 50]
    assert all(request.method == "POST" and urlsplit(request.full_url).path == "/api/dcim/interfaces/" for request in fake.requests)


def test_bulk_update_validates_all_items_before_sending():
    fake = FakeOpener(lambda request: json_response(json.loads(request.data)))
    client = NetBox("https://netbox.example", "secret", chunk=1, opener=fake)
    with pytest.raises(ValueError, match="id"):
        client.bulk("update", "ip", [{"id": 1}, {"address": "192.0.2.1/24"}])
    assert not fake.requests
    assert client.bulk("update", "ip", [{"id": 1, "description": "changed"}]) == [{"id": 1, "description": "changed"}]
    assert fake.requests[0].method == "PATCH"
    assert urlsplit(fake.requests[0].full_url).path == "/api/ipam/ip-addresses/"


def test_bulk_delete_sends_only_ids():
    fake = FakeOpener(lambda request: (200, b"deleted"))
    client = NetBox("https://netbox.example", "secret", chunk=1, opener=fake)
    assert client.bulk("delete", "mac", [{"id": 4, "name": "ignored"}, {"id": 5}]) == []
    assert [json.loads(request.data) for request in fake.requests] == [[{"id": 4}], [{"id": 5}]]
    assert all(request.method == "DELETE" and urlsplit(request.full_url).path == "/api/dcim/mac-addresses/" for request in fake.requests)


def test_bulk_prefix_and_empty_items():
    fake = FakeOpener(lambda request: json_response(json.loads(request.data)))
    client = NetBox("https://netbox.example", "secret", opener=fake)
    assert client.bulk("create", "prefix", []) == []
    assert not fake.requests
    assert client.bulk("create", "prefix", [{"prefix": "192.0.2.0/24"}]) == [{"prefix": "192.0.2.0/24"}]
    assert urlsplit(fake.requests[0].full_url).path == "/api/ipam/prefixes/"


def test_non_2xx_error_includes_status_and_only_first_500_bytes():
    fake = FakeOpener(lambda request: (403, b"x" * 500 + b"hidden"))
    with pytest.raises(NetBoxError) as error:
        NetBox("https://netbox.example", "secret", opener=fake).list_ip_addresses()
    assert str(error.value) == "NetBox HTTP 403: " + "x" * 500


def test_default_opener_http_error_and_timeout(monkeypatch):
    class HttpOpener:
        def open(self, request, timeout):
            assert timeout == 7
            raise HTTPError(request.full_url, 500, "error", {}, io.BytesIO(b"failure"))

    monkeypatch.setattr("netbox_snmp_sync.netbox.build_opener", lambda handler: HttpOpener())
    with pytest.raises(NetBoxError, match="HTTP 500: failure"):
        NetBox("https://netbox.example", "secret", timeout=7).list_ip_addresses()

    def fail(request):
        raise URLError("unreachable")

    with pytest.raises(NetBoxError, match="unreachable"):
        NetBox("https://netbox.example", "secret", opener=fail).list_ip_addresses()


def test_pagination_refuses_cross_origin_without_leaking_token():
    fake = FakeOpener(lambda request: json_response(page([], "https://other.example/steal")))
    with pytest.raises(NetBoxError, match="cross-origin"):
        NetBox("https://netbox.example", "secret", opener=fake).list_ip_addresses()
    assert len(fake.requests) == 1
