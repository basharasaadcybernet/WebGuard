"""Controlled Phase 9.5 fixtures for real-world accuracy regressions."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from webguard.domain.enums import FindingStatus, RuleEvaluationState, ScanState
from webguard.domain.models import NormalizedTarget, ScanRequest, ScanResult
from webguard.scanner.engine import ScanEngine
from webguard.security.budget import RequestBudget
from webguard.security.client import SafeFetchResult, SafeResponse
from webguard.security.config import NetworkLimits
from webguard.security.errors import (
    ConnectionRefused,
    DNSResolutionError,
    TLSCertificateExpired,
    TLSCertificateUntrusted,
    TLSHandshakeFailed,
    TLSHostnameMismatch,
)
from webguard.security.transport import TLSCertificateMetadata, TransportResponse
from webguard.security.url_policy import URLPolicy

NOW = datetime(2026, 1, 1, tzinfo=UTC)
GOOD_CERTIFICATE = TLSCertificateMetadata(not_after=NOW + timedelta(days=90))
COOKIE_RULES = {"cookies.secure", "cookies.http_only", "cookies.same_site"}


class FixedClock:
    def __init__(self) -> None:
        self._now = NOW

    def __call__(self) -> datetime:
        current = self._now
        self._now += timedelta(milliseconds=1)
        return current


class ScenarioClient:
    """Route fixed normalized URLs to controlled responses or typed failures."""

    def __init__(self, outcomes: dict[str, SafeFetchResult | Exception]) -> None:
        self.outcomes = outcomes

    def normalize(self, raw_url: str) -> NormalizedTarget:
        return URLPolicy().normalize(raw_url)

    async def fetch(
        self, raw_url: str, *, budget: RequestBudget | None = None
    ) -> SafeFetchResult:
        assert budget is not None
        await budget.consume()
        outcome = self.outcomes[URLPolicy().normalize(raw_url).request_url]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def fetch_once(
        self, raw_url: str, *, budget: RequestBudget | None = None
    ) -> SafeFetchResult:
        return await self.fetch(raw_url, budget=budget)


def response(
    url: str,
    *,
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
) -> SafeFetchResult:
    target = URLPolicy().normalize(url)
    return SafeFetchResult(
        responses=(
            SafeResponse(
                target=target,
                destination_ip=ipaddress.ip_address("93.184.216.34"),
                response=TransportResponse(
                    status_code=status,
                    headers=headers,
                    body=body,
                    elapsed_ms=2,
                    http_version="HTTP/1.1",
                    tls_certificate=GOOD_CERTIFICATE if target.scheme.value == "https" else None,
                ),
            ),
        )
    )


def reachable_outcomes(
    *, body: bytes = b"<!doctype html><html></html>", cookies: bool = True
) -> dict[str, SafeFetchResult | Exception]:
    headers: tuple[tuple[str, str], ...] = (
        ("Content-Type", "text/html"),
        ("Strict-Transport-Security", "max-age=31536000"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "geolocation=()"),
    )
    if cookies:
        headers += (("Set-Cookie", "session=secret; Secure; HttpOnly; SameSite=Lax"),)
    return {
        "https://example.com/": response("https://example.com/", headers=headers, body=body),
        "http://example.com/": response(
            "http://example.com/",
            status=301,
            headers=(("Location", "https://example.com/"),),
        ),
        "https://example.com/.well-known/security.txt": response(
            "https://example.com/.well-known/security.txt",
            headers=(("Content-Type", "text/plain"),),
            body=(
                b"Contact: mailto:security@example.com\n"
                b"Expires: 2027-01-01T00:00:00Z\n"
            ),
        ),
    }


def failing_https_outcomes(
    error: Exception,
    *,
    http_reachable: bool = True,
) -> dict[str, SafeFetchResult | Exception]:
    http: SafeFetchResult | Exception = (
        response(
            "http://example.com/",
            status=301,
            headers=(("Location", "https://example.com/"),),
        )
        if http_reachable
        else DNSResolutionError("fixture DNS failure")
    )
    return {
        "https://example.com/": error,
        "http://example.com/": http,
        "https://example.com/.well-known/security.txt": error,
    }


async def scan(outcomes: dict[str, SafeFetchResult | Exception]) -> ScanResult:
    return await ScanEngine(
        client=ScenarioClient(outcomes),
        limits=NetworkLimits(max_requests=4),
        clock=FixedClock(),
    ).scan(ScanRequest(url="https://example.com/"))


@dataclass(frozen=True)
class FailureExpectation:
    error: Exception
    public_code: str
    specific_tls_rule: str | None


TLS_FAILURE_FIXTURES = (
    FailureExpectation(
        TLSCertificateUntrusted("fixture"),
        "tls.certificate_untrusted",
        "transport.tls_validity",
    ),
    FailureExpectation(
        TLSCertificateExpired("fixture"),
        "tls.certificate_expired",
        "transport.tls_expiry",
    ),
    FailureExpectation(
        TLSHostnameMismatch("fixture"),
        "tls.hostname_mismatch",
        "transport.tls_hostname",
    ),
    FailureExpectation(TLSHandshakeFailed("fixture"), "tls.handshake_failed", None),
)


@pytest.mark.asyncio
@pytest.mark.parametrize("fixture", TLS_FAILURE_FIXTURES)
async def test_tls_failures_withhold_score_and_mark_dependent_rules_unevaluated(
    fixture: FailureExpectation,
) -> None:
    result = await scan(failing_https_outcomes(fixture.error))
    findings = {finding.id: finding.status for finding in result.findings}
    rule_errors = {error.rule_id for error in result.errors if error.rule_id is not None}

    assert result.metadata.state is ScanState.FAILED
    assert result.errors[0].code == fixture.public_code
    assert findings["transport.https_available"] is FindingStatus.FAIL
    assert findings["transport.http_redirect"] is FindingStatus.PASS
    if fixture.specific_tls_rule is not None:
        assert findings[fixture.specific_tls_rule] is FindingStatus.FAIL
    assert {
        "headers.content_security_policy",
        "cookies.secure",
        "content.mixed_content",
        "hygiene.server_disclosure",
    } <= rule_errors
    assert result.score is not None
    assert result.score.score is None
    assert result.score.coverage < Decimal("0.700")
    assert any(
        item.state is RuleEvaluationState.NOT_EVALUATED
        for item in result.score.rule_contributions
    )
    assert not any(
        item.state is RuleEvaluationState.NOT_APPLICABLE
        for item in result.score.rule_contributions
    )


@pytest.mark.asyncio
async def test_fully_reachable_https_fixture_has_complete_available_score() -> None:
    result = await scan(reachable_outcomes())

    assert result.metadata.state is ScanState.COMPLETED
    assert result.errors == ()
    assert result.score is not None and result.score.score is not None
    assert result.score.coverage == Decimal("1.000")


@pytest.mark.asyncio
async def test_https_unavailable_but_http_reachable_is_failed_and_withheld() -> None:
    outcomes = failing_https_outcomes(ConnectionRefused("fixture"))
    outcomes["http://example.com/"] = response(
        "http://example.com/", headers=(("Content-Type", "text/html"),)
    )
    result = await scan(outcomes)
    findings = {finding.id: finding.status for finding in result.findings}

    assert result.metadata.state is ScanState.FAILED
    assert findings["transport.https_available"] is FindingStatus.FAIL
    assert findings["transport.http_redirect"] is FindingStatus.FAIL
    assert result.score is not None and result.score.score is None
    assert result.score.coverage < Decimal("0.700")


@pytest.mark.asyncio
async def test_total_network_failure_is_failed_with_low_coverage_and_no_score() -> None:
    result = await scan(
        failing_https_outcomes(DNSResolutionError("fixture"), http_reachable=False)
    )

    assert result.metadata.state is ScanState.FAILED
    assert result.errors[0].code == "network.dns_resolution_failed"
    assert result.score is not None and result.score.score is None
    assert result.score.coverage < Decimal("0.700")


@pytest.mark.asyncio
async def test_profile_canonical_alternate_and_malformed_links_are_not_mixed_content() -> None:
    body = b"""<!doctype html><html><head>
      <link rel="profile" href="http://gmpg.org/xfn/11">
      <link rel="canonical" href="http://example.com/preferred">
      <link rel="alternate" href="http://example.com/feed">
      <link rel="nonsense,,," href="http://example.com/unknown">
      <link href="http://example.com/missing-rel">
    </head></html>"""
    result = await scan(reachable_outcomes(body=body, cookies=False))
    mixed = next(item for item in result.findings if item.id == "content.mixed_content")

    assert result.metadata.state is ScanState.COMPLETED
    assert mixed.status is FindingStatus.PASS


@pytest.mark.asyncio
async def test_fetched_link_relations_and_resources_remain_mixed_content() -> None:
    body = b"""<!doctype html><html><head>
      <link rel="stylesheet" href="http://cdn.example/site.css">
      <link rel="icon" href="http://cdn.example/favicon.ico">
      <link rel="preload" href="http://cdn.example/font.woff2" as="font">
      <script src="http://cdn.example/app.js"></script>
    </head><body><img src="http://cdn.example/photo.jpg"></body></html>"""
    result = await scan(reachable_outcomes(body=body))
    mixed = next(item for item in result.findings if item.id == "content.mixed_content")
    evidence = mixed.evidence[0].value

    assert result.metadata.state is ScanState.COMPLETED
    assert mixed.status is FindingStatus.WARNING
    assert "link" in evidence and "script" in evidence and "img" in evidence


@pytest.mark.asyncio
async def test_no_cookie_fixture_retains_three_not_applicable_rule_outcomes() -> None:
    result = await scan(reachable_outcomes(cookies=False))
    cookies = [finding for finding in result.findings if finding.id in COOKIE_RULES]
    contributions = {
        item.rule_id: item for item in result.score.rule_contributions
    } if result.score is not None else {}

    assert result.metadata.state is ScanState.COMPLETED
    assert len(cookies) == 3
    assert all(finding.evaluation_state == "NOT_APPLICABLE" for finding in cookies)
    assert all(
        contributions[rule_id].state is RuleEvaluationState.NOT_APPLICABLE
        for rule_id in COOKIE_RULES
    )
    assert result.score is not None and result.score.score is not None
