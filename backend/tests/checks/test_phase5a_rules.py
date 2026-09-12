from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

import pytest

from webguard.checks import default_check_registry
from webguard.checks.headers import (
    ClickjackingProtectionCheck,
    ContentSecurityPolicyCheck,
    PermissionsPolicyCheck,
    ReferrerPolicyCheck,
    StrictTransportSecurityCheck,
    XContentTypeOptionsCheck,
)
from webguard.checks.transport import (
    HTTPRedirectCheck,
    HTTPSAvailabilityCheck,
    HTTPSDowngradeCheck,
    TLSExpiryCheck,
    TLSHostnameCheck,
    TLSValidityCheck,
)
from webguard.domain.enums import FindingStatus, ScanState
from webguard.domain.models import Finding, NormalizedTarget, ScanRequest
from webguard.scanner.checks import CheckEvaluationError, SecurityCheck
from webguard.scanner.context import (
    ProbeFailure,
    ScanContext,
    build_probe_observation,
    build_scan_context,
)
from webguard.scanner.engine import ScanEngine
from webguard.security.budget import RequestBudget
from webguard.security.client import SafeFetchResult, SafeResponse
from webguard.security.transport import TLSCertificateMetadata, TransportResponse
from webguard.security.url_policy import URLPolicy

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def response(
    url: str,
    *,
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"<!doctype html><html></html>",
    certificate_not_after: datetime | None = None,
) -> SafeResponse:
    target = URLPolicy().normalize(url)
    certificate = (
        TLSCertificateMetadata(not_after=certificate_not_after)
        if certificate_not_after is not None
        else None
    )
    return SafeResponse(
        target=target,
        destination_ip=ipaddress.ip_address("93.184.216.34"),
        response=TransportResponse(
            status_code=status,
            headers=headers,
            body=body,
            elapsed_ms=5,
            http_version="HTTP/1.1",
            tls_certificate=certificate,
        ),
    )


def context(
    *,
    landing_url: str = "https://example.com/?token=secret",
    landing_headers: tuple[tuple[str, str], ...] = (),
    content_type: str = "text/html",
    certificate_not_after: datetime | None = NOW + timedelta(days=90),
    https_failure: str | None = None,
    http_status: int = 301,
    http_location: str | None = "https://example.com/",
    downgrade: bool = False,
) -> ScanContext:
    target = URLPolicy().normalize(landing_url)
    base_headers = (("Content-Type", content_type), *landing_headers)
    landing_body = b"{}" if content_type == "application/json" else b"<!doctype html><html></html>"
    landing_responses = (
        (
            response(
                "https://example.com/start",
                status=302,
                headers=(("Location", "http://example.com/final"),),
                certificate_not_after=certificate_not_after,
            ),
            response(
                "http://example.com/final",
                headers=base_headers,
            ),
        )
        if downgrade
        else (
            response(
                landing_url,
                headers=base_headers,
                body=landing_body,
                certificate_not_after=(
                    certificate_not_after if landing_url.startswith("https://") else None
                ),
            ),
        )
    )
    landing_result = SafeFetchResult(responses=landing_responses)
    landing = build_probe_observation(requested_target=target, fetch_result=landing_result)

    https_target = URLPolicy().normalize("https://example.com/")
    if https_failure is not None:
        https_probe = build_probe_observation(
            requested_target=https_target,
            failure=ProbeFailure(code=https_failure, message="Safe classified probe failure."),
        )
    else:
        https_result = (
            landing_result
            if downgrade
            else SafeFetchResult(
                responses=(
                    response(
                        "https://example.com/",
                        headers=base_headers,
                        certificate_not_after=certificate_not_after,
                    ),
                )
            )
        )
        https_probe = build_probe_observation(
            requested_target=https_target,
            fetch_result=https_result,
        )

    http_target = URLPolicy().normalize("http://example.com/")
    http_headers = (("Location", http_location),) if http_location is not None else ()
    http_probe = build_probe_observation(
        requested_target=http_target,
        fetch_result=SafeFetchResult(
            responses=(response("http://example.com/", status=http_status, headers=http_headers),)
        ),
    )
    return build_scan_context(
        target=target,
        landing=landing,
        https_probe=https_probe,
        http_probe=http_probe,
        budget=RequestBudget(8),
        started_at=NOW - timedelta(milliseconds=10),
        observations_finished_at=NOW,
    )


def finding(check: SecurityCheck, scan_context: ScanContext) -> Finding:
    result = check.evaluate(scan_context)
    assert len(result.findings) == 1
    return result.findings[0]


def test_real_rule_ids_are_unique_and_ordered_deterministically() -> None:
    checks = tuple(default_check_registry())
    ids = [check.metadata.rule_id for check in checks]
    assert len(checks) == 12
    assert len(ids) == len(set(ids))
    assert ids == [
        "transport.https_available",
        "transport.http_redirect",
        "transport.tls_validity",
        "transport.tls_hostname",
        "transport.tls_expiry",
        "transport.https_downgrade",
        "headers.strict_transport_security",
        "headers.content_security_policy",
        "headers.x_content_type_options",
        "headers.referrer_policy",
        "headers.permissions_policy",
        "headers.clickjacking_protection",
    ]


def test_https_availability_success_and_unavailable() -> None:
    rule = HTTPSAvailabilityCheck()
    assert finding(rule, context()).status is FindingStatus.PASS
    unavailable = context(https_failure="network.endpoint_unavailable")
    result = finding(rule, unavailable)
    assert result.status is FindingStatus.FAIL
    assert "exploitation" in result.description


def test_indeterminate_https_network_failure_is_an_evaluation_error() -> None:
    with pytest.raises(CheckEvaluationError):
        HTTPSAvailabilityCheck().evaluate(context(https_failure="network.fetch_failed"))


def test_http_redirect_to_https_and_http_remaining_available() -> None:
    rule = HTTPRedirectCheck()
    redirected = finding(rule, context())
    remaining = finding(rule, context(http_status=200, http_location=None))
    assert redirected.status is FindingStatus.PASS
    assert remaining.status is FindingStatus.FAIL


def test_valid_tls_certificate_passes_trust_hostname_and_expiry() -> None:
    scan_context = context()
    assert finding(TLSValidityCheck(), scan_context).status is FindingStatus.PASS
    assert finding(TLSHostnameCheck(), scan_context).status is FindingStatus.PASS
    assert finding(TLSExpiryCheck(), scan_context).status is FindingStatus.PASS


@pytest.mark.parametrize(
    ("rule", "failure_code"),
    [
        (TLSValidityCheck(), "tls.certificate_untrusted"),
        (TLSHostnameCheck(), "tls.hostname_mismatch"),
        (TLSExpiryCheck(), "tls.certificate_expired"),
    ],
)
def test_tls_certificate_failures_are_distinguished(
    rule: SecurityCheck, failure_code: str
) -> None:
    result = finding(rule, context(https_failure=failure_code))
    assert result.status is FindingStatus.FAIL


def test_certificate_close_to_expiration_warns_at_configured_threshold() -> None:
    result = finding(
        TLSExpiryCheck(),
        context(certificate_not_after=NOW + timedelta(days=20)),
    )
    assert result.status is FindingStatus.WARNING
    assert "30-day" in result.description


def test_missing_certificate_expiration_metadata_is_an_evaluation_error() -> None:
    with pytest.raises(CheckEvaluationError):
        TLSExpiryCheck().evaluate(context(certificate_not_after=None))


def test_https_to_http_downgrade_is_a_cautious_warning() -> None:
    scan_context = context(downgrade=True)
    result = finding(HTTPSDowngradeCheck(), scan_context)
    assert result.status is FindingStatus.WARNING
    assert "not proof" in result.description
    assert finding(TLSExpiryCheck(), scan_context).status is FindingStatus.PASS


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ((), FindingStatus.WARNING),
        (
            (("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),),
            FindingStatus.PASS,
        ),
        ((("Strict-Transport-Security", "max-age=0"),), FindingStatus.FAIL),
        ((("Strict-Transport-Security", "max-age=tomorrow"),), FindingStatus.WARNING),
    ],
)
def test_hsts_classifications(
    headers: tuple[tuple[str, str], ...], expected: FindingStatus
) -> None:
    assert finding(
        StrictTransportSecurityCheck(), context(landing_headers=headers)
    ).status is expected


def test_hsts_is_not_applicable_to_http_only_landing_response() -> None:
    scan_context = context(landing_url="http://example.com/")
    assert not StrictTransportSecurityCheck().is_applicable(scan_context)


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ((), FindingStatus.WARNING),
        ((("Content-Security-Policy", "default-src 'self'"),), FindingStatus.PASS),
        ((("Content-Security-Policy", " ; "),), FindingStatus.WARNING),
        ((("Content-Security-Policy", "not-a-real-directive value"),), FindingStatus.WARNING),
    ],
)
def test_csp_presence_is_evaluated_conservatively(
    headers: tuple[tuple[str, str], ...], expected: FindingStatus
) -> None:
    result = finding(ContentSecurityPolicyCheck(), context(landing_headers=headers))
    assert result.status is expected
    if expected is FindingStatus.PASS:
        assert "does not claim" in result.description


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ((("X-Content-Type-Options", "nosniff"),), FindingStatus.PASS),
        ((), FindingStatus.WARNING),
        ((("X-Content-Type-Options", "invalid"),), FindingStatus.WARNING),
    ],
)
def test_x_content_type_options_classifications(
    headers: tuple[tuple[str, str], ...], expected: FindingStatus
) -> None:
    assert finding(
        XContentTypeOptionsCheck(), context(landing_headers=headers)
    ).status is expected


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ((), FindingStatus.INFO),
        ((("Referrer-Policy", "strict-origin-when-cross-origin"),), FindingStatus.PASS),
        ((("Referrer-Policy", "unsafe-url"),), FindingStatus.WARNING),
        ((("Referrer-Policy", "made-up-policy"),), FindingStatus.WARNING),
    ],
)
def test_referrer_policy_classifications(
    headers: tuple[tuple[str, str], ...], expected: FindingStatus
) -> None:
    assert finding(ReferrerPolicyCheck(), context(landing_headers=headers)).status is expected


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ((), FindingStatus.INFO),
        ((("Permissions-Policy", "geolocation=(), camera=(self)"),), FindingStatus.PASS),
        ((("Permissions-Policy", "geolocation=*"),), FindingStatus.PASS),
        ((("Permissions-Policy", "geolocation"),), FindingStatus.WARNING),
    ],
)
def test_permissions_policy_classifications(
    headers: tuple[tuple[str, str], ...], expected: FindingStatus
) -> None:
    assert finding(PermissionsPolicyCheck(), context(landing_headers=headers)).status is expected


@pytest.mark.parametrize("x_frame_options", ["DENY", "SAMEORIGIN"])
def test_x_frame_options_restricts_framing(x_frame_options: str) -> None:
    result = finding(
        ClickjackingProtectionCheck(),
        context(landing_headers=(("X-Frame-Options", x_frame_options),)),
    )
    assert result.status is FindingStatus.PASS
    assert x_frame_options in result.evidence[0].value


def test_csp_frame_ancestors_none_takes_precedence_without_xfo() -> None:
    result = finding(
        ClickjackingProtectionCheck(),
        context(landing_headers=(("Content-Security-Policy", "frame-ancestors 'none'"),)),
    )
    assert result.status is FindingStatus.PASS
    assert "frame-ancestors 'none'" in result.evidence[0].value


def test_clickjacking_check_is_not_applicable_to_non_html_response() -> None:
    scan_context = context(content_type="application/json")
    assert not ClickjackingProtectionCheck().is_applicable(scan_context)


def test_public_findings_do_not_contain_sensitive_observations() -> None:
    scan_context = context(
        landing_headers=(
            ("Authorization", "Bearer report-secret"),
            ("Set-Cookie", "session=cookie-secret; Secure; HttpOnly"),
        )
    )
    findings = tuple(
        item
        for rule in default_check_registry()
        if rule.is_applicable(scan_context)
        for item in rule.evaluate(scan_context).findings
    )
    serialized = "".join(item.model_dump_json() for item in findings)
    assert "report-secret" not in serialized
    assert "cookie-secret" not in serialized
    assert "token=secret" not in serialized


class ControlledClient:
    def __init__(self) -> None:
        certificate = NOW + timedelta(days=90)
        self.landing = SafeFetchResult(
            responses=(
                response(
                    "https://example.com/",
                    headers=(
                        ("Content-Type", "text/html"),
                        ("Strict-Transport-Security", "max-age=31536000"),
                        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                        ("X-Content-Type-Options", "nosniff"),
                        ("Referrer-Policy", "strict-origin-when-cross-origin"),
                        ("Permissions-Policy", "geolocation=()"),
                    ),
                    certificate_not_after=certificate,
                ),
            )
        )
        self.http = SafeFetchResult(
            responses=(
                response(
                    "http://example.com/",
                    status=301,
                    headers=(("Location", "https://example.com/"),),
                ),
            )
        )
        self.budgets: list[RequestBudget] = []

    def normalize(self, raw_url: str) -> NormalizedTarget:
        return URLPolicy().normalize(raw_url)

    async def fetch(
        self, raw_url: str, *, budget: RequestBudget | None = None
    ) -> SafeFetchResult:
        assert budget is not None
        self.budgets.append(budget)
        await budget.consume()
        return self.landing

    async def fetch_once(
        self, raw_url: str, *, budget: RequestBudget | None = None
    ) -> SafeFetchResult:
        assert budget is not None
        self.budgets.append(budget)
        await budget.consume()
        return self.http


@pytest.mark.asyncio
async def test_default_engine_runs_all_real_checks_with_one_shared_budget() -> None:
    client = ControlledClient()
    times = iter((NOW - timedelta(milliseconds=2), NOW, NOW + timedelta(milliseconds=2)))
    result = await ScanEngine(client=client, clock=lambda: next(times)).scan(
        ScanRequest(url="https://example.com/")
    )
    assert result.metadata.state is ScanState.COMPLETED
    assert len(result.findings) == 12
    assert result.score is None
    assert result.errors == ()
    assert len(client.budgets) == 2
    assert client.budgets[0] is client.budgets[1]
