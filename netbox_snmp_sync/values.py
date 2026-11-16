from dataclasses import dataclass


@dataclass(frozen=True)
class SnmpValue:
    kind: str
    value: int | bytes | str | None
