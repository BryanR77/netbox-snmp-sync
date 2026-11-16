import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .model import NbDeviceState, NbInterface, NbIpAddress, NbMac


class NetBoxError(Exception):
    pass


def _origin(url):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username:
        raise NetBoxError("Invalid NetBox URL")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise NetBoxError("Invalid NetBox URL") from exc
    return parts.scheme, parts.hostname, port


class _SameOriginRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(req.full_url) != _origin(newurl):
            raise NetBoxError("Refusing cross-origin NetBox redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _tagged(item, tag):
    return any(
        entry.get("name") == tag or entry.get("slug") == tag
        for entry in (item.get("tags") or [])
    )


def _interface_id(item):
    if item.get("assigned_object_type") == "dcim.interface":
        return item.get("assigned_object_id")
    return None


class NetBox:
    def __init__(self, url, token, timeout=30, page_size=1000, chunk=100, opener=None):
        if page_size < 1 or chunk < 1:
            raise ValueError("page_size and chunk must be positive")
        self._base_url = url.rstrip("/") + "/api/"
        self._origin = _origin(self._base_url)
        self._token = token
        self._timeout = timeout
        self._page_size = page_size
        self._chunk = chunk
        if opener is None:
            urllib_opener = build_opener(_SameOriginRedirects())

            def opener(request):
                with urllib_opener.open(request, timeout=self._timeout) as response:
                    return response.status, response.read()

        self._opener = opener

    def _request(self, method, url, payload=None):
        if _origin(url) != self._origin:
            raise NetBoxError("Refusing cross-origin NetBox request")
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = Request(
            url,
            data=data,
            headers={
                # v2 tokens ("nbt_<key>.<secret>", NetBox >= 4.5) use Bearer; v1 use Token
                "Authorization": (f"Bearer {self._token}" if self._token.startswith("nbt_") else f"Token {self._token}"),
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method=method,
        )
        try:
            status, body = self._opener(request)
        except HTTPError as exc:
            status, body = exc.code, exc.read(500)
        except (URLError, OSError) as exc:
            reason = exc.reason if isinstance(exc, URLError) else exc
            raise NetBoxError(f"NetBox request failed: {reason}") from exc
        if not 200 <= status < 300:
            detail = body[:500].decode("utf-8", errors="replace")
            raise NetBoxError(f"NetBox HTTP {status}: {detail}")
        if method == "DELETE" or not body:
            return None
        try:
            return json.loads(body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise NetBoxError("Invalid JSON response from NetBox") from exc

    def _list(self, endpoint, **params):
        params["limit"] = self._page_size
        url = urljoin(self._base_url, endpoint) + "?" + urlencode(params)
        items = []
        while url:
            page = self._request("GET", url)
            if not isinstance(page, dict) or not isinstance(page.get("results"), list):
                raise NetBoxError("Invalid paginated response from NetBox")
            items.extend(page["results"])
            next_url = page.get("next")
            url = urljoin(url, next_url) if next_url else None
        return items

    def get_device_state(self, name: str, site: str, tag: str) -> NbDeviceState:
        devices = [
            item
            for item in self._list("dcim/devices/", name=name)
            if item.get("name") == name
            and site in (
                (item.get("site") or {}).get("name"),
                (item.get("site") or {}).get("slug"),
            )
        ]
        if len(devices) != 1:
            raise NetBoxError(
                f"Expected one device named {name!r} in site {site!r}; found {len(devices)}"
            )
        device = devices[0]
        device_id = device["id"]
        interfaces = [
            NbInterface(
                id=item["id"],
                name=item["name"],
                type=item["type"]["value"],
                mtu=item.get("mtu"),
                speed=item.get("speed"),
                enabled=item["enabled"],
                description=item["description"],
                tagged=_tagged(item, tag),
                primary_mac_id=(item.get("primary_mac_address") or {}).get("id"),
            )
            for item in self._list("dcim/interfaces/", device_id=device_id)
        ]
        addresses = [
            NbIpAddress(
                id=item["id"],
                address=item["address"],
                interface_id=_interface_id(item),
                tagged=_tagged(item, tag),
            )
            for item in self._list("ipam/ip-addresses/", device_id=device_id)
        ]
        macs = [
            NbMac(
                id=item["id"],
                mac=item["mac_address"].upper(),
                interface_id=_interface_id(item),
                tagged=_tagged(item, tag),
            )
            for item in self._list("dcim/mac-addresses/", device_id=device_id)
        ]
        return NbDeviceState(
            device_id=device_id,
            name=device["name"],
            primary_ip4=(device.get("primary_ip4") or {}).get("address"),
            primary_ip6=(device.get("primary_ip6") or {}).get("address"),
            interfaces={item.name: item for item in interfaces},
            ip_addresses={item.address: item for item in addresses},
            macs=macs,
        )

    def list_inventory(self, tag: str, site: str) -> dict[str, str]:
        """{device name: primary IPv4 host} for devices carrying `tag` in `site`."""
        out = {}
        for item in self._list("dcim/devices/", tag=tag):
            s = item.get("site") or {}
            ip = (item.get("primary_ip4") or {}).get("address")
            if site in (s.get("name"), s.get("slug")) and ip:
                out[item["name"]] = ip.split("/")[0]
        return out

    def list_prefixes(self, tag: str) -> list[tuple[int, str, bool]]:
        return [
            (item["id"], item["prefix"], _tagged(item, tag))
            for item in self._list("ipam/prefixes/")
        ]

    def list_ip_addresses(self) -> list[str]:
        return [
            item["address"]
            for item in self._list("ipam/ip-addresses/", brief=1)
        ]

    def bulk(self, op: str, kind: str, items: list[dict]) -> list[dict]:
        endpoints = {
            "interface": "dcim/interfaces/",
            "ip": "ipam/ip-addresses/",
            "mac": "dcim/mac-addresses/",
            "prefix": "ipam/prefixes/",
        }
        methods = {"create": "POST", "update": "PATCH", "delete": "DELETE"}
        if op not in methods or kind not in endpoints:
            raise ValueError("Invalid bulk operation or kind")
        if op in ("update", "delete") and any("id" not in item for item in items):
            raise ValueError(f"Bulk {op} requires an id for every item")

        url = urljoin(self._base_url, endpoints[kind])
        result = []
        for start in range(0, len(items), self._chunk):
            batch = items[start : start + self._chunk]
            if op == "delete":
                batch = [{"id": item["id"]} for item in batch]
            response = self._request(methods[op], url, batch)
            if op != "delete":
                if not isinstance(response, list):
                    raise NetBoxError("Invalid bulk response from NetBox")
                result.extend(response)
        return result
