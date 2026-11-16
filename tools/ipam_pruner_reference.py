"""Prune IPAM entries that SNMP discovery created but the device no longer has.

Diode/orb-agent only ever create and update. A dynamic WAN address therefore
leaves every previous address (and its prefix) behind in NetBox. Each run:

1. SNMPv2c-walks each target's IPv4 address table (IP-MIB ipAddrTable) and
   interface names (IF-MIB ifName): the device's live truth.
2. Deletes NetBox IPv4 addresses on that device's interfaces that are tagged
   `snmp-discovery` (Diode-created) and no longer live on the device.
3. Deletes `snmp-discovery` prefixes that no longer contain any IP address.

Never touches objects without the tag (manual/proxbox data), primary IPs, or
IPv6. Aborts before deleting anything if a walk fails or doesn't contain the
target's own management address. Stdlib only.

Env: NETBOX_URL, NETBOX_TOKEN, SNMP_COMMUNITY, TARGETS ("device=ip,..."),
     DRY_RUN=1 to only report. SNMP_ONLY=1 prints the walk and exits.
"""
import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.request

TAG = "snmp-discovery"

# ---------------------------------------------------------------- SNMP (BER)


def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, value):
    return bytes([tag]) + _len(len(value)) + value


def _int(n):
    return _tlv(0x02, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True))


def _oid(oid):
    parts = [int(x) for x in oid.strip(".").split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, bytes(out))


def _read(buf, i):
    tag = buf[i]
    n = buf[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, buf[i:i + n], i + n


def _decode_oid(b):
    parts = [b[0] // 40, b[0] % 40]
    v = 0
    for byte in b[1:]:
        v = (v << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def _getnext(sock, host, community, oid, req_id):
    varbind = _tlv(0x30, _tlv(0x30, _oid(oid) + b"\x05\x00"))
    pdu = _tlv(0xA1, _int(req_id) + _int(0) + _int(0) + varbind)
    msg = _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + pdu)  # version 1 = v2c
    sock.sendto(msg, (host, 161))
    data, _ = sock.recvfrom(65535)
    _, msg_body, _ = _read(data, 0)
    _, _, i = _read(msg_body, 0)          # version
    _, _, i = _read(msg_body, i)          # community
    _, pdu_body, _ = _read(msg_body, i)   # response PDU
    _, rid, j = _read(pdu_body, 0)
    _, err, j = _read(pdu_body, j)
    if int.from_bytes(err, "big"):
        raise RuntimeError(f"SNMP error-status {int.from_bytes(err, 'big')} for {oid}")
    _, _, j = _read(pdu_body, j)          # error-index
    _, vbl, _ = _read(pdu_body, j)
    _, vb, _ = _read(vbl, 0)
    _, name, k = _read(vb, 0)
    vtag, value, _ = _read(vb, k)
    return _decode_oid(name), vtag, value


def walk(host, community, base):
    """Return {suffix: (tag, raw value)} for every OID under base."""
    out, oid, req = {}, base, 1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        while True:
            for attempt in range(3):
                try:
                    name, tag, value = _getnext(s, host, community, oid, req)
                    break
                except socket.timeout:
                    if attempt == 2:
                        raise
            req += 1
            if not name.startswith(base + ".") or tag in (0x80, 0x81, 0x82):
                return out
            out[name[len(base) + 1:]] = (tag, value)
            oid = name


def live_ipv4(host, community):
    """{ifName: {ip/len, ...}} from IP-MIB ipAdEntIfIndex/NetMask + IF-MIB ifName."""
    ifindex = walk(host, community, "1.3.6.1.2.1.4.20.1.2")
    masks = walk(host, community, "1.3.6.1.2.1.4.20.1.3")
    names = walk(host, community, "1.3.6.1.2.1.31.1.1.1.1")
    live = {}
    for ip, (_, idx) in ifindex.items():
        mask = ipaddress.IPv4Address(bytes(masks[ip][1]))
        plen = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        ifname = names.get(str(int.from_bytes(idx, "big")), (0, b"?"))[1].decode()
        live.setdefault(ifname, set()).add(f"{ip}/{plen}")
    return live

# ---------------------------------------------------------------- NetBox API


def api(method, path, url, token):
    req = urllib.request.Request(f"{url}/api/{path}", method=method, headers={
        "Authorization": f"Token {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r) if r.status != 204 else None


def api_list(path, url, token):
    out, nxt = [], path
    while nxt:
        page = api("GET", nxt, url, token)
        out += page["results"]
        nxt = page["next"].split("/api/", 1)[1] if page["next"] else None
    return out


def main():
    community = os.environ["SNMP_COMMUNITY"]
    targets = dict(t.split("=") for t in os.environ["TARGETS"].split(","))
    dry = os.environ.get("DRY_RUN") == "1"

    live = {}
    for device, host in targets.items():
        live[device] = live_ipv4(host, community)
        flat = {a.split("/")[0] for addrs in live[device].values() for a in addrs}
        if host not in flat:
            sys.exit(f"ABORT: {device} walk lacks its own address {host}: {live[device]}")
        print(f"live {device}: {json.dumps({k: sorted(v) for k, v in sorted(live[device].items())})}")
    if os.environ.get("SNMP_ONLY") == "1":
        return

    url, token = os.environ["NETBOX_URL"].rstrip("/"), os.environ["NETBOX_TOKEN"]
    deleted = 0
    for device in targets:
        addrs = {a for v in live[device].values() for a in v}
        dev = api_list(f"dcim/devices/?name={device}", url, token)
        if len(dev) != 1:
            print(f"skip {device}: {len(dev)} NetBox devices with that name")
            continue
        primary = (dev[0].get("primary_ip4") or {}).get("id")
        for ip in api_list(f"ipam/ip-addresses/?device_id={dev[0]['id']}&tag={TAG}&family=4", url, token):
            if ip["address"] in addrs or ip["id"] == primary:
                continue
            iface = (ip.get("assigned_object") or {}).get("name")
            print(f"{'would delete' if dry else 'delete'} ip {ip['address']} ({device} {iface}): not on the device")
            if not dry:
                api("DELETE", f"ipam/ip-addresses/{ip['id']}/", url, token)
            deleted += 1

    all_ips = [ipaddress.ip_interface(i["address"]) for i in api_list("ipam/ip-addresses/?brief=1", url, token)]
    for p in api_list(f"ipam/prefixes/?tag={TAG}", url, token):
        net = ipaddress.ip_network(p["prefix"])
        if any(i.ip in net for i in all_ips if i.version == net.version):
            continue
        print(f"{'would delete' if dry else 'delete'} prefix {p['prefix']}: no IP addresses inside")
        if not dry:
            api("DELETE", f"ipam/prefixes/{p['id']}/", url, token)
        deleted += 1
    print(f"done: {deleted} {'candidates (dry run)' if dry else 'deleted'}")


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as e:
        sys.exit(f"NetBox API error {e.code}: {e.read()[:300]}")
