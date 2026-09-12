"""Shared deterministic fakes for security-boundary tests."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from webguard.security.address_policy import IPAddress
from webguard.security.config import NetworkLimits
from webguard.security.transport import PinnedDestination, TransportResponse


def addresses(*values: str) -> tuple[IPAddress, ...]:
    return tuple(ipaddress.ip_address(value) for value in values)


class FakeResolver:
    def __init__(self, answers: Iterable[tuple[IPAddress, ...]]) -> None:
        self._answers = list(answers)
        self.calls: list[tuple[str, int]] = []

    async def resolve(self, hostname: str, port: int) -> tuple[IPAddress, ...]:
        self.calls.append((hostname, port))
        if not self._answers:
            raise AssertionError("Fake resolver has no answer configured")
        return self._answers.pop(0)


class FakeTransport:
    def __init__(self, responses: Iterable[TransportResponse]) -> None:
        self._responses = list(responses)
        self.destinations: list[PinnedDestination] = []

    async def request(
        self,
        destination: PinnedDestination,
        limits: NetworkLimits,
    ) -> TransportResponse:
        self.destinations.append(destination)
        if not self._responses:
            raise AssertionError("Fake transport has no response configured")
        return self._responses.pop(0)


def response(
    status: int = 200,
    *,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"ok",
) -> TransportResponse:
    return TransportResponse(
        status_code=status,
        headers=headers,
        body=body,
        elapsed_ms=1,
        http_version="HTTP/1.1",
    )
