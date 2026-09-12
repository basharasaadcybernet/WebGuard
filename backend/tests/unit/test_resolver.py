import asyncio
import socket
from typing import Any

import pytest

from webguard.security.errors import DNSResolutionError
from webguard.security.resolver import SystemResolver


class FakeLoop:
    def __init__(self, records: list[tuple[Any, ...]] | None = None, delay: float = 0) -> None:
        self.records = records or []
        self.delay = delay

    async def getaddrinfo(self, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.records


@pytest.mark.asyncio
async def test_system_resolver_returns_deduplicated_ipv4_and_ipv6(monkeypatch: Any) -> None:
    loop = FakeLoop(
        [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700::1111", 443, 0, 0)),
        ]
    )
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: loop)
    result = await SystemResolver().resolve("example.com", 443)
    assert tuple(map(str, result)) == ("8.8.8.8", "2606:4700::1111")


@pytest.mark.asyncio
async def test_system_resolver_has_a_bounded_dns_timeout(monkeypatch: Any) -> None:
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop(delay=0.05))
    with pytest.raises(DNSResolutionError, match="could not be resolved"):
        await SystemResolver(timeout_seconds=0.001).resolve("example.com", 443)


@pytest.mark.asyncio
async def test_system_resolver_fails_when_no_ip_records_exist(monkeypatch: Any) -> None:
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: FakeLoop())
    with pytest.raises(DNSResolutionError, match="IPv4 or IPv6"):
        await SystemResolver().resolve("example.com", 443)
