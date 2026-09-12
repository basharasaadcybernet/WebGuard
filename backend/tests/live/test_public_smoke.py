"""Opt-in, low-impact checks of the real public-network path."""

from __future__ import annotations

import ssl

import pytest

from webguard.security.client import SafeFetchResult, SafeHttpClient
from webguard.security.config import NetworkLimits
from webguard.security.errors import SecurityBoundaryError, TransportError

pytestmark = [pytest.mark.asyncio, pytest.mark.live]

_LIVE_LIMITS = NetworkLimits(
    max_redirects=3,
    max_requests=4,
    max_response_bytes=512 * 1024,
    total_timeout_seconds=20,
)


async def fetch_public_or_fail(url: str) -> SafeFetchResult:
    try:
        return await SafeHttpClient(limits=_LIVE_LIMITS).fetch(url)
    except SecurityBoundaryError as exc:
        pytest.fail(
            "Optional live smoke test could not reach its public target. "
            f"Check Internet, DNS, firewall, and target availability. {type(exc).__name__}: {exc}"
        )


async def test_real_client_fetches_small_verified_https_page() -> None:
    result = await fetch_public_or_fail("https://example.com/")
    assert result.final.response.status_code == 200
    assert 0 < len(result.final.response.body) <= _LIVE_LIMITS.max_response_bytes
    assert result.final.target.hostname == "example.com"


async def test_real_client_processes_normal_public_redirect() -> None:
    result = await fetch_public_or_fail("https://httpbin.org/redirect/1")
    assert len(result.responses) == 2
    assert result.final.response.status_code == 200
    assert result.final.target.hostname == "httpbin.org"


def exception_chain(error: BaseException) -> tuple[BaseException, ...]:
    chain: list[BaseException] = []
    current: BaseException | None = error
    while current is not None and current not in chain:
        chain.append(current)
        current = current.__cause__ or current.__context__
    return tuple(chain)


@pytest.mark.parametrize(
    "url",
    [
        "https://expired.badssl.com/",
        "https://wrong.host.badssl.com/",
        "https://self-signed.badssl.com/",
    ],
)
async def test_real_client_rejects_invalid_public_certificates(url: str) -> None:
    with pytest.raises(TransportError) as caught:
        await SafeHttpClient(limits=_LIVE_LIMITS).fetch(url)

    chain = exception_chain(caught.value)
    if not any(isinstance(error, ssl.SSLCertVerificationError) for error in chain):
        pytest.fail(
            "The invalid-certificate target failed for an environmental reason rather than "
            f"certificate verification: {[type(error).__name__ for error in chain]}"
        )
