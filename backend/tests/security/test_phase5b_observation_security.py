from __future__ import annotations

import pytest

from conftest import FakeResolver, FakeTransport, addresses, response
from webguard.checks.hygiene import SecurityTxtCheck
from webguard.domain.enums import FindingStatus, ScanState
from webguard.domain.models import ScanRequest
from webguard.scanner.engine import ScanEngine
from webguard.scanner.registry import CheckRegistry
from webguard.security.client import SafeHttpClient
from webguard.security.config import NetworkLimits

VALID_SECURITY_TXT = b"Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n"


def engine(
    resolver: FakeResolver,
    transport: FakeTransport,
    *,
    limits: NetworkLimits | None = None,
) -> ScanEngine:
    configured_limits = limits or NetworkLimits()
    client = SafeHttpClient(
        limits=configured_limits,
        resolver=resolver,
        transport=transport,
    )
    return ScanEngine(
        registry=CheckRegistry((SecurityTxtCheck(),)),
        client=client,
        limits=configured_limits,
    )


@pytest.mark.asyncio
@pytest.mark.security
async def test_security_txt_redirect_is_revalidated_and_query_is_redacted() -> None:
    resolver = FakeResolver([addresses("8.8.8.8")] * 4)
    transport = FakeTransport(
        [
            response(body=b"<html></html>", headers=(("Content-Type", "text/html"),)),
            response(301, headers=(("Location", "https://example.com/"),)),
            response(
                302,
                headers=(
                    (
                        "Location",
                        "/.well-known/security.txt?token=auxiliary-secret",
                    ),
                ),
            ),
            response(200, headers=(("Content-Type", "text/plain"),), body=VALID_SECURITY_TXT),
        ]
    )
    result = await engine(resolver, transport).scan(ScanRequest(url="https://example.com/"))

    assert result.metadata.state is ScanState.COMPLETED
    assert result.findings[0].status is FindingStatus.PASS
    assert [destination.target.path for destination in transport.destinations[-2:]] == [
        "/.well-known/security.txt",
        "/.well-known/security.txt",
    ]
    assert "auxiliary-secret" not in result.model_dump_json()
    assert "security@example.com" not in result.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.security
async def test_security_txt_redirect_to_private_destination_is_blocked() -> None:
    resolver = FakeResolver(
        [
            addresses("8.8.8.8"),
            addresses("8.8.4.4"),
            addresses("1.1.1.1"),
            addresses("127.0.0.1"),
        ]
    )
    transport = FakeTransport(
        [
            response(body=b"<html></html>"),
            response(301, headers=(("Location", "https://example.com/"),)),
            response(302, headers=(("Location", "http://localhost/admin"),)),
        ]
    )
    result = await engine(resolver, transport).scan(ScanRequest(url="https://example.com/"))

    assert result.metadata.state is ScanState.PARTIAL
    assert result.findings == ()
    assert [error.code for error in result.errors] == ["check.evaluation_failed"]
    assert resolver.calls[-1] == ("localhost", 80)
    assert len(transport.destinations) == 3


@pytest.mark.asyncio
@pytest.mark.security
async def test_security_txt_request_budget_exhaustion_is_an_operational_error() -> None:
    limits = NetworkLimits(max_requests=2)
    resolver = FakeResolver([addresses("8.8.8.8"), addresses("8.8.4.4")])
    transport = FakeTransport(
        [
            response(body=b"<html></html>"),
            response(301, headers=(("Location", "https://example.com/"),)),
        ]
    )
    result = await engine(resolver, transport, limits=limits).scan(
        ScanRequest(url="https://example.com/")
    )

    assert result.metadata.state is ScanState.PARTIAL
    assert result.findings == ()
    assert [error.code for error in result.errors] == ["check.evaluation_failed"]
    assert len(resolver.calls) == 2
    assert len(transport.destinations) == 2


@pytest.mark.asyncio
@pytest.mark.security
async def test_oversized_security_txt_is_rejected_by_network_boundary() -> None:
    limits = NetworkLimits(max_response_bytes=1024)
    resolver = FakeResolver([addresses("8.8.8.8")] * 3)
    transport = FakeTransport(
        [
            response(body=b"<html></html>"),
            response(301, headers=(("Location", "https://example.com/"),)),
            response(body=b"x" * 1025),
        ]
    )
    result = await engine(resolver, transport, limits=limits).scan(
        ScanRequest(url="https://example.com/")
    )

    assert result.metadata.state is ScanState.PARTIAL
    assert result.findings == ()
    assert [error.code for error in result.errors] == ["check.evaluation_failed"]
