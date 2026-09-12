"""Public-address validation used after every DNS resolution."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from webguard.security.errors import BlockedAddressError

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class PublicAddressPolicy:
    """Reject all destinations that are not unambiguously globally routable."""

    def validate_all(self, addresses: Iterable[IPAddress]) -> tuple[IPAddress, ...]:
        unique = tuple(dict.fromkeys(addresses))
        if not unique:
            raise BlockedAddressError("Hostname did not resolve to an address")
        for address in unique:
            self.validate(address)
        return unique

    def validate(self, address: IPAddress) -> None:
        candidate: IPAddress = address
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            candidate = address.ipv4_mapped

        forbidden = (
            candidate.is_private
            or candidate.is_loopback
            or candidate.is_link_local
            or candidate.is_multicast
            or candidate.is_reserved
            or candidate.is_unspecified
            or not candidate.is_global
        )
        if forbidden:
            raise BlockedAddressError("Destination is not a globally routable public address")
