import asyncio
from dataclasses import dataclass, field

from pyasn1.type import univ
from pysnmp.hlapi.v3arch import asyncio as hlapi
from pysnmp.proto import rfc1902, rfc1905

from .values import SnmpValue


SUBTREES = (
    "1.3.6.1.2.1.1.2",
    "1.3.6.1.2.1.1.5",
    "1.3.6.1.2.1.2.2.1.2",
    "1.3.6.1.2.1.2.2.1.3",
    "1.3.6.1.2.1.2.2.1.4",
    "1.3.6.1.2.1.2.2.1.5",
    "1.3.6.1.2.1.2.2.1.6",
    "1.3.6.1.2.1.2.2.1.7",
    "1.3.6.1.2.1.31.1.1.1.1",
    "1.3.6.1.2.1.31.1.1.1.15",
    "1.3.6.1.2.1.31.1.1.1.18",
    "1.3.6.1.2.1.4.20.1.2",
    "1.3.6.1.2.1.4.20.1.3",
    "1.3.6.1.2.1.4.34.1.3",
    "1.3.6.1.2.1.4.34.1.4",
    "1.3.6.1.2.1.4.34.1.5",
)


class SnmpError(Exception):
    pass


@dataclass
class Credentials:
    version: str = "2c"
    community: str | None = field(default=None, repr=False)
    user: str | None = None
    auth_key: str | None = field(default=None, repr=False)
    priv_key: str | None = field(default=None, repr=False)
    auth_protocol: str = "sha"
    priv_protocol: str = "aes"

    def _auth_data(self):
        if self.version == "2c":
            if self.community is None:
                raise SnmpError("SNMP v2c requires a community")
            return hlapi.CommunityData(self.community, mpModel=1)
        if self.version != "3":
            raise SnmpError(f"Unsupported SNMP version: {self.version}")
        if not self.user:
            raise SnmpError("SNMP v3 requires a user")
        if self.priv_key is not None and self.auth_key is None:
            raise SnmpError("SNMP v3 privacy requires authentication")

        auth_protocols = {
            "md5": hlapi.usmHMACMD5AuthProtocol,
            "sha": hlapi.usmHMACSHAAuthProtocol,
            "sha224": hlapi.usmHMAC128SHA224AuthProtocol,
            "sha256": hlapi.usmHMAC192SHA256AuthProtocol,
            "sha384": hlapi.usmHMAC256SHA384AuthProtocol,
            "sha512": hlapi.usmHMAC384SHA512AuthProtocol,
        }
        priv_protocols = {
            "des": hlapi.usmDESPrivProtocol,
            "aes": hlapi.usmAesCfb128Protocol,
            "aes128": hlapi.usmAesCfb128Protocol,
            "aes192": hlapi.usmAesCfb192Protocol,
            "aes256": hlapi.usmAesCfb256Protocol,
        }
        try:
            auth = (
                auth_protocols[self.auth_protocol.lower()]
                if self.auth_key is not None
                else hlapi.usmNoAuthProtocol
            )
            priv = (
                priv_protocols[self.priv_protocol.lower()]
                if self.priv_key is not None
                else hlapi.usmNoPrivProtocol
            )
        except KeyError as exc:
            raise SnmpError(f"Unsupported SNMP v3 protocol: {exc.args[0]}") from exc
        return hlapi.UsmUserData(
            self.user, self.auth_key, self.priv_key, authProtocol=auth, privProtocol=priv
        )


def _convert_value(value) -> SnmpValue | None:
    if isinstance(
        value, (rfc1905.NoSuchObject, rfc1905.NoSuchInstance, rfc1905.EndOfMibView)
    ):
        return None
    if isinstance(value, univ.Null):
        return SnmpValue("null", None)
    if isinstance(value, rfc1902.IpAddress):
        return SnmpValue("ipaddr", value.prettyPrint())
    if isinstance(value, univ.OctetString):
        return SnmpValue("octets", value.asOctets())
    if isinstance(value, univ.ObjectIdentifier):
        return SnmpValue("oid", value.prettyPrint().lstrip("."))
    if isinstance(value, (rfc1902.Counter32, rfc1902.Counter64)):
        return SnmpValue("counter", int(value))
    if isinstance(value, (rfc1902.Gauge32, rfc1902.Unsigned32)):
        return SnmpValue("gauge", int(value))
    if isinstance(value, rfc1902.TimeTicks):
        return SnmpValue("timeticks", int(value))
    if isinstance(value, univ.Integer):
        return SnmpValue("int", int(value))
    raise SnmpError(f"Unsupported SNMP value type: {type(value).__name__}")


async def walk_device(
    host: str,
    creds: Credentials,
    subtrees,
    timeout: float = 3,
    retries: int = 2,
) -> dict[str, SnmpValue]:
    engine = hlapi.SnmpEngine()
    try:
        auth = creds._auth_data()
        target = await hlapi.UdpTransportTarget.create(
            (host, 161), timeout=timeout, retries=retries
        )
        values = {}
        for subtree in subtrees:
            last_oid = tuple(int(part) for part in subtree.strip(".").split("."))
            async for indication, status, index, bindings in hlapi.bulk_walk_cmd(
                engine,
                auth,
                target,
                hlapi.ContextData(),
                0,
                25,
                hlapi.ObjectType(hlapi.ObjectIdentity(subtree)),
                lexicographicMode=False,
                lookupMib=False,
            ):
                if indication:
                    raise SnmpError(str(indication))
                if status:
                    raise SnmpError(f"SNMP error at index {index}: {status}")
                for oid, value in bindings:
                    converted = _convert_value(value)
                    if converted is not None:
                        oid_string = oid.prettyPrint().lstrip(".")
                        oid_parts = tuple(int(part) for part in oid_string.split("."))
                        if oid_parts <= last_oid:
                            raise SnmpError(f"SNMP walk returned a non-increasing OID: {oid_string}")
                        last_oid = oid_parts
                        values[oid_string] = converted
        return values
    except SnmpError:
        raise
    except Exception as exc:
        raise SnmpError(f"SNMP collection failed for {host}: {exc}") from exc
    finally:
        engine.close_dispatcher()


async def collect_many(
    targets: dict[str, str],
    creds: Credentials,
    subtrees,
    concurrency: int = 16,
) -> dict[str, dict[str, SnmpValue] | SnmpError]:
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    semaphore = asyncio.Semaphore(concurrency)
    subtrees = tuple(subtrees)

    async def collect(host):
        async with semaphore:
            try:
                return await walk_device(host, creds, subtrees)
            except SnmpError as exc:
                return exc
            except Exception as exc:
                return SnmpError(f"SNMP collection failed for {host}: {exc}")

    results = await asyncio.gather(*(collect(host) for host in targets.values()))
    return dict(zip(targets, results))
