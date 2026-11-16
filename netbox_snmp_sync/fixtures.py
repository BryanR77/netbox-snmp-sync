import json
from datetime import datetime, timezone
from pathlib import Path

from .values import SnmpValue


def load_fixture(path: str | Path) -> tuple[str, str, dict[str, SnmpValue]]:
    with open(path, encoding="utf-8") as file:
        fixture = json.load(file)
    values = {
        oid: SnmpValue(
            item["kind"],
            bytes.fromhex(item["hex"]) if item["kind"] == "octets" else item["value"],
        )
        for oid, item in fixture["values"].items()
    }
    return fixture["device"], fixture["host"], values


def save_fixture(
    path: str | Path, device: str, host: str, values: dict[str, SnmpValue]
) -> None:
    fixture = {
        "device": device,
        "host": host,
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "values": {
            oid: (
                {"kind": value.kind, "hex": value.value.hex()}
                if value.kind == "octets"
                else {"kind": value.kind, "value": value.value}
            )
            for oid, value in values.items()
        },
    }
    with open(path, "w", encoding="utf-8") as file:
        json.dump(fixture, file, indent=2)
        file.write("\n")
