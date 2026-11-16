# netbox-snmp-sync: spec

Polls network devices over SNMP and keeps a narrow, explicitly owned slice of NetBox in
sync: interfaces, IP addresses, MAC addresses and the prefixes around those addresses.
Replaces orb-agent + Diode + ipam-pruner in the homelab; written so the same code can run
against a much larger estate (concurrency, bulk NetBox I/O, delete guards, no
site-specific values in code).

## Principles

1. **Narrow ownership.** The sync only creates, updates or deletes objects tagged
   `snmp-discovery` (configurable), and only the fields listed under "Owned fields".
   It never edits a device's role, type, platform, site, status, or primary IP, and never
   touches untagged objects (manual, proxbox, device-type templates).
2. **Unreachable is not empty.** A device whose collection fails or looks wrong is skipped
   entirely for that run. It is never treated as "has no interfaces".
3. **Report first.** Default mode prints the plan and changes nothing.
4. **Pure core.** `collect` (raw SNMP -> model) and `diff` (model + NetBox state -> plan)
   are pure functions with no I/O, so they are unit-tested from recorded fixtures.
5. **Config, not code.** Anything specific to a network (targets, exclusions, type pins,
   tag names, VRF) lives in the YAML config.

## Layout

```
netbox_snmp_sync/
  __init__.py
  values.py     # neutral SNMP value type shared by every SNMP source
  snmp.py       # async SNMP walker (pysnmp): v2c + v3, GETBULK, per-device timeout
  fixtures.py   # load/save fixture JSON (the same neutral values)
  model.py      # dataclasses: DeviceState, Interface, Address
  collect.py    # pure: {oid: SnmpValue} -> DeviceState
  netbox.py     # NetBox REST client: bulk read (tag-scoped), bulk create/update/delete
  diff.py       # pure: (DeviceState, NetBoxDeviceState, DeviceConfig) -> Plan
  apply.py      # executes a Plan through netbox.py, enforcing guards
  config.py     # YAML config -> dataclasses, with defaults
  cli.py        # entrypoint: modes report | apply | snmp-only | capture
tests/
  fixtures/<device>.json
  test_collect.py, test_diff.py, ...
tools/
  capture_fixtures.py   # standalone (stdlib only) fixture recorder
Dockerfile, pyproject.toml, config.example.yaml, README.md
```

Python 3.12+, dependencies: `pysnmp` (lextudio, 7.x), `PyYAML`. NetBox access via stdlib
`urllib` (no pynetbox): the client is small and we control bulk behaviour.

## Neutral SNMP values (`values.py`)

Every SNMP source (live pysnmp walk, fixture file) yields `dict[str, SnmpValue]` keyed by the
full numeric OID without a leading dot (e.g. `1.3.6.1.2.1.31.1.1.1.1.5`).

```python
@dataclass(frozen=True)
class SnmpValue:
    kind: str   # "int" | "octets" | "oid" | "ipaddr" | "counter" | "gauge" | "timeticks" | "null"
    value: int | bytes | str | None
```

- Integer -> `int`; Counter32/Counter64 -> `counter`; Gauge32/Unsigned32 -> `gauge`;
  TimeTicks -> `timeticks` (all `int` values)
- OctetString -> `octets` (`bytes`; never decoded at this layer)
- ObjectIdentifier -> `oid` (dotted `str`, no leading dot)
- IpAddress -> `ipaddr` (dotted-quad `str`)
- noSuchObject / noSuchInstance / endOfMibView are never returned (the walk stops/skips).

Fixture JSON (`fixtures.py`), one file per device:
```json
{"device": "fw", "host": "192.168.42.1", "captured_at": "2026-11-16T19:00:00Z",
 "values": {"1.3.6.1.2.1.1.5.0": {"kind": "octets", "hex": "6677"},
            "1.3.6.1.2.1.2.2.1.4.1": {"kind": "int", "value": 1500}}}
```
`octets` are stored as `"hex"`; every other kind as `"value"`.

## What is walked (`snmp.py`)

Only these subtrees (columns, not whole tables, to avoid counters):

| Name | OID | Used for |
|---|---|---|
| sysObjectID, sysName | 1.3.6.1.2.1.1.2, 1.3.6.1.2.1.1.5 | identity check |
| ifDescr | 1.3.6.1.2.1.2.2.1.2 | fallback name |
| ifType | 1.3.6.1.2.1.2.2.1.3 | interface type |
| ifMtu | 1.3.6.1.2.1.2.2.1.4 | mtu |
| ifSpeed | 1.3.6.1.2.1.2.2.1.5 | speed fallback |
| ifPhysAddress | 1.3.6.1.2.1.2.2.1.6 | MAC |
| ifAdminStatus | 1.3.6.1.2.1.2.2.1.7 | enabled |
| ifName | 1.3.6.1.2.1.31.1.1.1.1 | name |
| ifHighSpeed | 1.3.6.1.2.1.31.1.1.1.15 | speed (Mbps) |
| ifAlias | 1.3.6.1.2.1.31.1.1.1.18 | description |
| ipAdEntIfIndex, ipAdEntNetMask | 1.3.6.1.2.1.4.20.1.2, .3 | IPv4 (legacy table) |
| ipAddressIfIndex, ipAddressType, ipAddressPrefix | 1.3.6.1.2.1.4.34.1.3, .4, .5 | IPv4 + IPv6 |

Walker contract: `async def walk_device(host, creds, subtrees, timeout, retries) -> dict[str, SnmpValue]`.
GETBULK (v2c/v3), per-request timeout and retries, raises `SnmpError` on any failure
(timeout, auth, error-status). `async def collect_many(targets, concurrency)` runs devices
concurrently with a semaphore and returns per-device result or exception (never raises for
one bad device).

## Model (`model.py`) and collect rules (`collect.py`)

```python
@dataclass(frozen=True)
class Interface:
    name: str            # ifName, else ifDescr
    if_type: int         # IANA ifType number
    mtu: int | None
    speed_kbps: int | None   # ifHighSpeed*1000, else ifSpeed//1000; None if 0
    mac: str | None      # "AA:BB:CC:DD:EE:FF" upper-case; None if empty/all-zero
    enabled: bool        # ifAdminStatus == 1
    description: str     # ifAlias decoded utf-8 (errors=replace), stripped

@dataclass(frozen=True)
class Address:
    interface: str       # Interface.name
    address: str         # "192.0.2.1/24" or "2001:db8::1/64" (ipaddress.ip_interface str)

@dataclass(frozen=True)
class DeviceState:
    sysname: str
    sys_object_id: str
    interfaces: dict[str, Interface]
    addresses: frozenset[Address]
```

- ipAddressTable (4.34) index is `<addrtype>.<len>.<addr bytes...>`; addrtype 1 = ipv4,
  2 = ipv6 (skip 3/4 = zoned). Prefix length is the last component of the ipAddressPrefix
  OID value. Use only ipAddressType == 1 (unicast).
- If 4.34 yields no IPv4 addresses, use ipAddrTable (4.20) for IPv4 (netmask -> prefixlen).
- Always drop: `0.0.0.0/*`, `127.0.0.0/8` members, `::1`, `fe80::/10`, and anything matched
  by config `address_exclude` (list of CIDRs).
- Interfaces matching any config `interface_exclude` regex are dropped together with their
  addresses.
- Duplicate interface names (rare): keep the lowest ifIndex, warn.

## NetBox side (`netbox.py`)

Per device, read in bulk (paginated, `limit=1000`):
- the device by name (+ site from config); must match exactly one
- its interfaces (all, not just tagged: needed to avoid creating duplicates of template
  interfaces)
- IP addresses assigned to its interfaces
- MAC address objects on its interfaces (NetBox >= 4.2 `dcim.macaddress`)
- tagged prefixes (global, once per run)

Writes use list payloads on the collection endpoints (bulk create `POST`, bulk update
`PATCH`, bulk delete `DELETE` with `[{"id": n}, ...]`), chunked at 100.

## Owned fields and diff rules (`diff.py`)

Interfaces (match by exact name on the device):
- Missing in NetBox -> create with name, type, mtu, speed, enabled, description, tag.
- Present -> update only: `mtu`, `speed`, `enabled`, and `description` (only if SNMP value
  non-empty). `type` is set on create only, unless a config `interface_type` pattern
  matches (then it is enforced every run). Untagged interfaces are updated but never get
  the tag added and are never deleted.
- Present in NetBox, tagged, absent from SNMP -> delete, **unless** a primary IP, an untagged IP
  or an untagged MAC is assigned to it (NetBox cascades interface deletes to assigned IPs/MACs).

IP addresses (match by address string, VRF from config, default global):
- Missing -> create, assigned to the interface, tagged.
- Present but assigned elsewhere on the same device -> reassign (owned field:
  `assigned_object`). If the same address is live on two interfaces of the device, keep
  the existing assignment (no flapping).
- Tagged, on this device, absent from SNMP, not the device's primary IP -> delete.

MAC addresses: one `dcim.macaddress` per interface MAC, tagged; set the interface's
`primary_mac_address` if it is empty or points at a tagged MAC. Delete tagged MACs no
longer reported.

Prefixes: for each live address, ensure its network exists (create tagged if missing; any
existing prefix with the same network counts, tagged or not). After applying, delete tagged
prefixes that contain no IP address at all (global check, as ipam-pruner does).

Plan = ordered list of actions: `(op: create|update|delete, kind, netbox_id|None, payload,
reason)`. Creates before updates before deletes; prefixes last.

## Guards (`apply.py`)

Skip a device for the run (log why) if any of:
- SNMP failed or timed out
- sysName != NetBox device name (case-insensitive), unless config `match: ip`
- the device's NetBox primary IP is not among the collected addresses
- zero interfaces collected

Abort the device's deletes (still apply creates/updates) if deletes for any kind exceed
`max_delete_fraction` (default 0.25) of that device's tagged objects of that kind, unless
`--force-deletes`.

## Config (`config.example.yaml`)

```yaml
netbox:
  url: http://netbox.netbox.svc.cluster.local
  token_env: NETBOX_TOKEN
  tag: snmp-discovery
  site: home
snmp:
  version: 2c            # or 3
  community_env: SNMP_COMMUNITY
  timeout: 3
  retries: 2
  concurrency: 16
inventory:
  # devices in NetBox with this tag and a primary IPv4 are polled at that address
  netbox_tag: snmp-sync
defaults:
  interface_exclude: ['^lo$']
  address_exclude: []
  max_delete_fraction: 0.25
devices:
  fw:
    interface_exclude: ['^pim6reg$']
    interface_type:
      - {match: '^eth[12]$', type: 25gbase-x-sfp28}
      - {match: '^wg\d+$', type: virtual}
  XMG1915-18EP-1:
    interface_exclude: ['^enif0$']
```

ifType -> NetBox type default map (overridable): 6 ethernetCsmacd -> `other` unless speed
maps (1000 -> 1000base-t, 2500 -> 2.5gbase-t, 10000 -> 10gbase-t), 24 softwareLoopback ->
`virtual`, 53 propVirtual / 135 l2vlan / 136 l3ipvlan / 131 tunnel ->
`virtual`, 209 bridge -> `bridge`, 161 ieee8023adLag -> `lag`, 71 ieee80211 -> `ieee802.11ax` (config may override).

## CLI

`netbox-snmp-sync --config config.yaml [--mode report|apply|snmp-only|capture] [--device NAME]... [--force-deletes] [--fixture-dir DIR]`

- report: collect, diff, print plan as a table + JSON summary; exit 0
- apply: same, then execute; exit 1 if any device was skipped or any write failed
- snmp-only: print collected DeviceState per device as JSON
- capture: write fixtures for each device into `--fixture-dir`

## Tests

`tests/fixtures/*.json` recorded from the four homelab devices. `test_collect.py` asserts
parsed DeviceState per fixture (names, types, MACs, addresses, exclusions).
`test_diff.py` uses hand-built NetBoxDeviceState objects to cover: create, update of owned
fields only, no change -> empty plan, untagged objects never deleted, primary IP never
deleted, address present on two interfaces doesn't flap, delete-fraction guard.
