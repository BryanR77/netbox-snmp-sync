# netbox-snmp-sync

Polls devices over SNMP and synchronizes interfaces, IP addresses, MAC addresses,
and prefixes with NetBox. Python 3.12+ is required.

Copy and edit [config.example.yaml](config.example.yaml) for your NetBox, devices,
and exclusions. Set the environment variables named in the configuration, such as
`NETBOX_TOKEN` and `SNMP_COMMUNITY`.

```sh
netbox-snmp-sync --config config.yaml --mode report
```

Modes: `report` (default, no writes), `apply` (execute the plan), `snmp-only`
(print collected device state), and `capture` (save SNMP fixtures).

## Ownership

- Created objects receive the configurable sync tag; only tagged objects are deleted.
- Existing interfaces, including untagged ones, may have operational fields updated;
  type is changed only when pinned in configuration.
- Untagged IP and MAC objects are not modified; primary IPs and interfaces with
  protected assigned objects are not deleted.
- MAC primary assignments are changed only when empty or already owned; tagged
  prefixes are deleted only when empty.
- Device role, type, platform, site, status, and primary IPs are never changed.
  Failed or suspect collections are skipped, and delete limits guard each device.

## Tests

```sh
pip install '.[test]'
python -m pytest -q tests
```

## Image

Images are published to `ghcr.io/bryanr77/netbox-snmp-sync` using version tags
for releases and short commit SHA tags for main. Replace the example tag below
with a published tag:

```sh
docker run --rm -v "$PWD/config.yaml:/config/config.yaml:ro" \
  -e NETBOX_TOKEN -e SNMP_COMMUNITY \
  ghcr.io/bryanr77/netbox-snmp-sync:1.2.3
```
