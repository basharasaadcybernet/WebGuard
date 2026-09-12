"""Injectable DNS resolution with no policy bypass."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Protocol

from webguard.security.address_policy import IPAddress
from webguard.security.errors import DNSResolutionError


class Resolver(Protocol):
    """Resolution contract used by the safe client."""

    async def resolve(self, hostname: str, port: int) -> tuple[IPAddress, ...]: ...


class SystemResolver:
    """Resolve A and AAAA records with the operating system resolver."""

    def __init__(self, timeout_seconds: float = 3.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("DNS timeout must be positive")
        self._timeout_seconds = timeout_seconds

    async def resolve(self, hostname: str, port: int) -> tuple[IPAddress, ...]:
        try:
            async with asyncio.timeout(self._timeout_seconds):
                records = await asyncio.get_running_loop().getaddrinfo(
                    hostname,
                    port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                )
        except (OSError, TimeoutError, UnicodeError) as exc:
            raise DNSResolutionError("Hostname could not be resolved") from exc

        addresses: list[IPAddress] = []
        for family, _, _, _, socket_address in records:
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            try:
                addresses.append(ipaddress.ip_address(socket_address[0]))
            except ValueError as exc:
                raise DNSResolutionError("Resolver returned an invalid address") from exc
        if not addresses:
            raise DNSResolutionError("Hostname did not resolve to IPv4 or IPv6")
        return tuple(dict.fromkeys(addresses))
