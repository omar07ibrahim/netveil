"""Immutable endpoint corpus model with internal validated construction."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Self, final

_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")


class IPVersion(Enum):
    """Supported IP address families."""

    IPV4 = 4
    IPV6 = 6


class EndpointScope(Enum):
    """Privacy-relevant address classification."""

    DOCUMENTATION = "documentation"
    GLOBAL = "global"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    SHARED = "shared"
    SITE_LOCAL = "site_local"
    UNSPECIFIED = "unspecified"
    RESERVED = "reserved"


@final
@dataclass(frozen=True, slots=True, init=False)
class Endpoint:
    """One canonical raw IP endpoint produced only by ``parse_corpus``."""

    address: str
    port: int
    version: IPVersion
    scope: EndpointScope

    def __new__(cls) -> Self:
        """Block direct construction outside the validated parser boundary."""

        raise TypeError("Endpoint objects are created by parse_corpus")

    @property
    def canonical(self) -> str:
        """Return the unambiguous canonical endpoint representation."""

        if self.version is IPVersion.IPV6:
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"


@final
@dataclass(frozen=True, slots=True, init=False)
class EndpointCorpus:
    """A parsed corpus bound to exact bytes by the internal factory."""

    source_sha256: str
    source_bytes: int
    physical_line_count: int
    endpoints: tuple[Endpoint, ...]
    unique_endpoints: tuple[Endpoint, ...]

    def __new__(cls) -> Self:
        """Block direct construction outside the validated parser boundary."""

        raise TypeError("EndpointCorpus objects are created by parse_corpus")

    @property
    def endpoint_count(self) -> int:
        return len(self.endpoints)

    @property
    def unique_count(self) -> int:
        return len(self.unique_endpoints)

    @property
    def duplicate_count(self) -> int:
        return self.endpoint_count - self.unique_count


def _scope(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> EndpointScope:
    """Classify one exact stdlib address without any network operation."""

    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        return EndpointScope.DOCUMENTATION
    if address.is_unspecified:
        return EndpointScope.UNSPECIFIED
    if address.is_loopback:
        return EndpointScope.LOOPBACK
    if address.is_multicast:
        return EndpointScope.MULTICAST
    if address.is_link_local:
        return EndpointScope.LINK_LOCAL
    if isinstance(address, ipaddress.IPv6Address) and address.is_site_local:
        return EndpointScope.SITE_LOCAL
    if address in _SHARED_ADDRESS_SPACE:
        return EndpointScope.SHARED
    if address.is_reserved:
        return EndpointScope.RESERVED
    if address.is_private:
        return EndpointScope.PRIVATE
    return EndpointScope.GLOBAL


def _create_endpoint(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    port: int,
) -> Endpoint:
    """Create an endpoint after checking every stored field invariant."""

    if type(address) not in (ipaddress.IPv4Address, ipaddress.IPv6Address):
        raise TypeError("address must be an exact IPv4Address or IPv6Address")
    if type(port) is not int:
        raise TypeError("port must be an exact int")
    if not 1 <= port <= 65_535:
        raise ValueError("port must be in the range 1..65535")
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        raise ValueError("scoped IPv6 addresses are not supported")

    endpoint: Endpoint = object.__new__(Endpoint)
    object.__setattr__(endpoint, "address", address.compressed)
    object.__setattr__(endpoint, "port", port)
    object.__setattr__(
        endpoint,
        "version",
        IPVersion.IPV6
        if isinstance(address, ipaddress.IPv6Address)
        else IPVersion.IPV4,
    )
    object.__setattr__(endpoint, "scope", _scope(address))
    return endpoint


def _create_corpus(
    *,
    payload: bytes,
    physical_line_count: int,
    endpoints: tuple[Endpoint, ...],
) -> EndpointCorpus:
    """Create a corpus while deriving all identity and uniqueness fields."""

    if type(payload) is not bytes:
        raise TypeError("payload must be exact bytes")
    if type(physical_line_count) is not int:
        raise TypeError("physical_line_count must be an exact int")
    if type(endpoints) is not tuple:
        raise TypeError("endpoints must be an exact tuple")
    if physical_line_count < 0:
        raise ValueError("physical_line_count must be non-negative")
    if not endpoints:
        raise ValueError("a corpus must contain at least one endpoint")
    if physical_line_count < len(endpoints):
        raise ValueError("physical_line_count cannot be smaller than endpoint_count")
    if any(type(endpoint) is not Endpoint for endpoint in endpoints):
        raise TypeError("every endpoint must come from the validated factory")

    unique_by_canonical: dict[str, Endpoint] = {}
    for endpoint in endpoints:
        unique_by_canonical.setdefault(endpoint.canonical, endpoint)

    corpus: EndpointCorpus = object.__new__(EndpointCorpus)
    object.__setattr__(corpus, "source_sha256", hashlib.sha256(payload).hexdigest())
    object.__setattr__(corpus, "source_bytes", len(payload))
    object.__setattr__(corpus, "physical_line_count", physical_line_count)
    object.__setattr__(corpus, "endpoints", endpoints)
    object.__setattr__(
        corpus,
        "unique_endpoints",
        tuple(unique_by_canonical.values()),
    )
    return corpus
