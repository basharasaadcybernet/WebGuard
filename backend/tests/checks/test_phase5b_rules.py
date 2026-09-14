from __future__ import annotations

import ipaddress
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from webguard.checks import default_check_registry
from webguard.checks.config import RuleConfig
from webguard.checks.content import MixedContentCheck
from webguard.checks.cookies import CookieHttpOnlyCheck, CookieSameSiteCheck, CookieSecureCheck
from webguard.checks.hygiene import (
    SecurityTxtCheck,
    ServerDisclosureCheck,
    XPoweredByDisclosureCheck,
)
from webguard.domain.enums import FindingStatus, ScanState, Severity
from webguard.domain.models import Finding, NormalizedTarget, ScanRequest
from webguard.scanner.checks import CheckEvaluationError, SecurityCheck
from webguard.scanner.context import (
    AuxiliaryObservation,
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
VALID_SECURITY_TXT = b"Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n"


def response(
    url: str,
    *,
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"<!doctype html><html></html>",
    certificate: bool = False,
) -> SafeResponse:
    return SafeResponse(
        target=URLPolicy().normalize(url),
        destination_ip=ipaddress.ip_address("93.184.216.34"),
        response=TransportResponse(
            status_code=status,
            headers=headers,
            body=body,
            elapsed_ms=5,
            http_version="HTTP/1.1",
            tls_certificate=(
                TLSCertificateMetadata(not_after=NOW + timedelta(days=90))
                if certificate
                else None
            ),
        ),
    )


def context(
    *,
    landing_headers: tuple[tuple[str, str], ...] = (),
    redirect_headers: tuple[tuple[str, str], ...] = (),
    landing_body: bytes = b"<!doctype html><html></html>",
    landing_url: str = "https://example.com/?token=landing-secret",
    security_status: int = 200,
    security_body: bytes = VALID_SECURITY_TXT,
    security_url: str = "https://example.com/.well-known/security.txt",
    security_content_type: str = "text/plain",
    security_failure: str | None = None,
) -> ScanContext:
    target = URLPolicy().normalize(landing_url)
    final_headers = (("Content-Type", "text/html"), *landing_headers)
    landing_responses = (
        (
            response(
                "https://example.com/start",
                status=302,
                headers=(("Location", "/final"), *redirect_headers),
                certificate=True,
            ),
            response(
                landing_url,
                headers=final_headers,
                body=landing_body,
                certificate=True,
            ),
        )
        if redirect_headers
        else (
            response(
                landing_url,
                headers=final_headers,
                body=landing_body,
                certificate=True,
            ),
        )
    )
    landing_result = SafeFetchResult(responses=landing_responses)
    landing = build_probe_observation(requested_target=target, fetch_result=landing_result)
    http_target = URLPolicy().normalize("http://example.com/")
    http_probe = build_probe_observation(
        requested_target=http_target,
        fetch_result=SafeFetchResult(
            responses=(
                response(
                    "http://example.com/",
                    status=301,
                    headers=(("Location", "https://example.com/"),),
                ),
            )
        ),
    )
    security_target = URLPolicy().normalize("https://example.com/.well-known/security.txt")
    security_probe = (
        build_probe_observation(
            requested_target=security_target,
            failure=ProbeFailure(
                code=security_failure,
                message="Safe auxiliary observation failure.",
            ),
        )
        if security_failure is not None
        else build_probe_observation(
            requested_target=security_target,
            fetch_result=SafeFetchResult(
                responses=(
                    response(
                        security_url,
                        status=security_status,
                        headers=(("Content-Type", security_content_type),),
                        body=security_body,
                    ),
                )
            ),
        )
    )
    return build_scan_context(
        target=target,
        landing=landing,
        https_probe=landing,
        http_probe=http_probe,
        budget=RequestBudget(8),
        started_at=NOW - timedelta(milliseconds=10),
        observations_finished_at=NOW,
        auxiliary=(AuxiliaryObservation(key="security_txt", probe=security_probe),),
    )


def finding(check: SecurityCheck, scan_context: ScanContext) -> Finding:
    result = check.evaluate(scan_context)
    assert len(result.findings) == 1
    return result.findings[0]


def test_phase5b_rule_ids_are_unique_and_deterministic() -> None:
    checks = tuple(default_check_registry())
    ids = [check.metadata.rule_id for check in checks]
    assert len(checks) == 19
    assert len(ids) == len(set(ids))
    assert ids[-7:] == [
        "cookies.secure",
        "cookies.http_only",
        "cookies.same_site",
        "content.mixed_content",
        "hygiene.security_txt",
        "hygiene.server_disclosure",
        "hygiene.x_powered_by",
    ]
    auxiliary = default_check_registry().auxiliary_requests()
    assert [(item.key, item.path) for item in auxiliary] == [
        ("security_txt", "/.well-known/security.txt")
    ]


def test_no_cookies_is_informational_not_applicable_without_credit() -> None:
    results = [
        finding(rule, context())
        for rule in (CookieSecureCheck(), CookieHttpOnlyCheck(), CookieSameSiteCheck())
    ]
    assert all(item.status is FindingStatus.INFO for item in results)
    assert all(item.evaluation_state == "NOT_APPLICABLE" for item in results)
    assert all("no security credit" in item.description.lower() for item in results)


@pytest.mark.parametrize(
    ("cookie", "expected"),
    [
        ("session=secret; Secure", FindingStatus.PASS),
        ("session=secret", FindingStatus.WARNING),
    ],
)
def test_cookie_secure_present_and_missing(cookie: str, expected: FindingStatus) -> None:
    result = finding(CookieSecureCheck(), context(landing_headers=(("Set-Cookie", cookie),)))
    assert result.status is expected
    if expected is FindingStatus.WARNING:
        assert result.severity is Severity.LOW


@pytest.mark.parametrize(
    ("cookie", "expected"),
    [
        ("session=secret; HttpOnly", FindingStatus.PASS),
        ("clientPreference=secret", FindingStatus.INFO),
    ],
)
def test_cookie_http_only_is_conservative(cookie: str, expected: FindingStatus) -> None:
    result = finding(CookieHttpOnlyCheck(), context(landing_headers=(("Set-Cookie", cookie),)))
    assert result.status is expected
    if expected is FindingStatus.INFO:
        assert "intentionally" in result.description
        assert result.evaluation_state == "APPLICABLE"


@pytest.mark.parametrize("same_site", ["Strict", "Lax", "None"])
def test_cookie_recognized_same_site_values_pass_when_usable(same_site: str) -> None:
    secure = "; Secure" if same_site == "None" else ""
    cookie = f"session=secret; SameSite={same_site}{secure}"
    assert finding(
        CookieSameSiteCheck(), context(landing_headers=(("Set-Cookie", cookie),))
    ).status is FindingStatus.PASS


def test_cookie_missing_same_site_is_low_csrf_hardening_warning() -> None:
    result = finding(
        CookieSameSiteCheck(),
        context(landing_headers=(("Set-Cookie", "session=secret; Secure"),)),
    )
    assert result.status is FindingStatus.WARNING
    assert result.severity is Severity.LOW
    assert "not proof of a CSRF vulnerability" in result.description


def test_same_site_none_without_secure_is_reported() -> None:
    result = finding(
        CookieSameSiteCheck(),
        context(landing_headers=(("Set-Cookie", "session=secret; SameSite=None"),)),
    )
    assert result.status is FindingStatus.WARNING
    assert "SameSite=None without Secure" in result.evidence[0].value


def test_multiple_cookie_issues_are_grouped_across_redirect_chain() -> None:
    scan_context = context(
        redirect_headers=(("Set-Cookie", "redirect=first-secret"),),
        landing_headers=(
            ("Set-Cookie", "session=second-secret; HttpOnly"),
            ("Set-Cookie", "preference=third-secret; Secure; SameSite=Lax"),
        ),
    )
    result = finding(CookieSecureCheck(), scan_context)
    assert len(result.evidence) == 1
    assert "redirect" in result.evidence[0].value
    assert "session" in result.evidence[0].value
    assert "2 of 3" in result.evidence[0].value


def test_cookie_values_never_enter_findings_or_context_repr() -> None:
    scan_context = context(
        landing_headers=(
            ("Authorization", "Bearer authorization-secret"),
            (
                "Set-Cookie",
                "session=session-identifier-secret; Secure; HttpOnly; SameSite=Lax",
            ),
        )
    )
    rendered = repr(scan_context)
    serialized = "".join(
        finding(rule, scan_context).model_dump_json()
        for rule in (CookieSecureCheck(), CookieHttpOnlyCheck(), CookieSameSiteCheck())
    )
    assert "session-identifier-secret" not in rendered + serialized
    assert "authorization-secret" not in rendered + serialized
    assert "landing-secret" not in serialized


def test_valid_future_security_txt_passes_without_exposing_contact_value() -> None:
    result = finding(SecurityTxtCheck(), context())
    assert result.status is FindingStatus.PASS
    assert "security@example.com" not in result.model_dump_json()
    assert "Contact fields: 1" in result.evidence[0].value


@pytest.mark.parametrize("status", [404, 500])
def test_missing_or_non_success_security_txt_is_informational(status: int) -> None:
    result = finding(SecurityTxtCheck(), context(security_status=status))
    assert result.status is FindingStatus.INFO
    assert str(status) in result.evidence[0].value


@pytest.mark.parametrize(
    ("body", "evidence"),
    [
        (b"Expires: 2027-01-01T00:00:00Z\n", "Contact fields: 0"),
        (b"Contact: mailto:security@example.com\n", "Expires fields: 0"),
        (
            b"Contact: mailto:security@example.com\nExpires: tomorrow\n",
            "Expires: malformed",
        ),
        (
            b"Contact: mailto:security@example.com\nExpires: 2025-01-01T00:00:00Z\n",
            "state: expired",
        ),
    ],
)
def test_invalid_security_txt_conditions_are_low_warnings(body: bytes, evidence: str) -> None:
    result = finding(SecurityTxtCheck(), context(security_body=body))
    assert result.status is FindingStatus.WARNING
    assert result.severity is Severity.LOW
    assert evidence in result.evidence[0].value


def test_oversized_or_failed_security_txt_is_an_operational_evaluation_error() -> None:
    with pytest.raises(CheckEvaluationError):
        SecurityTxtCheck().evaluate(context(security_body=b"x" * (64 * 1024 + 1)))
    with pytest.raises(CheckEvaluationError):
        SecurityTxtCheck().evaluate(context(security_failure="network.fetch_failed"))


def test_missing_security_txt_observation_is_an_operational_error() -> None:
    with pytest.raises(CheckEvaluationError):
        SecurityTxtCheck().evaluate(replace(context(), auxiliary=()))


@pytest.mark.parametrize(
    ("kwargs", "evidence"),
    [
        ({"security_url": "http://example.com/security.txt"}, "not served entirely over HTTPS"),
        ({"security_content_type": "text/html"}, "Content-Type"),
        ({"security_body": b"Contact: \xff\nExpires: 2030-01-01T00:00:00Z\n"}, "UTF-8"),
        (
            {
                "security_body": (
                    b"Contact: mailto:security@example.com\n"
                    b"Expires: 2027-01-01T00:00:00Z\n"
                    b"Expires: 2028-01-01T00:00:00Z\n"
                )
            },
            "Expires fields: 2",
        ),
    ],
)
def test_security_txt_delivery_and_format_edges_are_low_warnings(
    kwargs: dict[str, object], evidence: str
) -> None:
    result = finding(SecurityTxtCheck(), context(**kwargs))  # type: ignore[arg-type]
    assert result.status is FindingStatus.WARNING
    assert result.severity is Severity.LOW
    assert evidence in result.evidence[0].value


def test_rule_config_rejects_unsafe_security_txt_parsing_limits() -> None:
    with pytest.raises(ValueError, match=r"security\.txt parsing limit"):
        RuleConfig(security_txt_max_bytes=1023)
    with pytest.raises(ValueError, match=r"security\.txt parsing limit"):
        RuleConfig(security_txt_max_bytes=1024 * 1024 + 1)


@pytest.mark.parametrize(
    "markup",
    [
        '<script src="http://cdn.example/script.js"></script>',
        '<link rel="stylesheet" href="http://cdn.example/site.css">',
        '<iframe src="http://frames.example/embed"></iframe>',
        '<form action="http://forms.example/submit"></form>',
    ],
)
def test_active_mixed_content_is_a_medium_warning(markup: str) -> None:
    result = finding(MixedContentCheck(), context(landing_body=markup.encode()))
    assert result.status is FindingStatus.WARNING
    assert result.severity is Severity.MEDIUM
    assert "Active/higher-risk" in result.evidence[0].value


def test_http_image_is_a_lower_risk_mixed_content_warning() -> None:
    result = finding(
        MixedContentCheck(),
        context(landing_body=b'<img src="http://images.example/photo.jpg">'),
    )
    assert result.status is FindingStatus.WARNING
    assert result.severity is Severity.LOW
    assert "Passive/lower-risk" in result.evidence[0].value


@pytest.mark.parametrize("relation", ["icon", "preload", "prefetch"])
def test_fetched_link_relations_are_lower_risk_mixed_content(relation: str) -> None:
    markup = f'<link rel="{relation}" href="http://cdn.example/resource">'
    result = finding(MixedContentCheck(), context(landing_body=markup.encode()))
    assert result.status is FindingStatus.WARNING
    assert result.severity is Severity.LOW


@pytest.mark.parametrize(
    "relation",
    ["profile", "canonical", "alternate", "nonsense,,,", ""],
)
def test_metadata_and_malformed_link_relations_are_not_fetched_resources(
    relation: str,
) -> None:
    markup = f'<link rel="{relation}" href="http://cdn.example/resource">'
    result = finding(MixedContentCheck(), context(landing_body=markup.encode()))
    assert result.status is FindingStatus.PASS


def test_non_http_and_malformed_references_are_not_reported() -> None:
    body = b"""
    <script src="/relative.js"></script>
    <img src="//cdn.example/image.png">
    <img src="data:image/png;base64,abc">
    <iframe src="http://"></iframe>
    """
    result = finding(MixedContentCheck(), context(landing_body=body))
    assert result.status is FindingStatus.PASS


def test_duplicate_mixed_content_is_deduplicated_and_query_is_redacted() -> None:
    body = b"""
    <script src="http://cdn.example/app.js?token=resource-secret"></script>
    <script src="http://cdn.example/app.js?token=resource-secret"></script>
    """
    result = finding(MixedContentCheck(), context(landing_body=body))
    serialized = result.model_dump_json()
    assert result.evidence[0].value.count("http://cdn.example/app.js?[redacted]") == 1
    assert "resource-secret" not in serialized
    assert "landing-secret" not in serialized


@pytest.mark.parametrize(
    ("headers", "expected", "severity"),
    [
        ((), FindingStatus.INFO, Severity.INFO),
        (("Server", "nginx"), FindingStatus.INFO, Severity.INFO),
        (("Server", "Apache/2.4.58 (Unix)"), FindingStatus.WARNING, Severity.LOW),
    ],
)
def test_server_disclosure_is_informational_unless_version_is_detailed(
    headers: tuple[()] | tuple[str, str],
    expected: FindingStatus,
    severity: Severity,
) -> None:
    landing_headers = () if not headers else (headers,)
    result = finding(ServerDisclosureCheck(), context(landing_headers=landing_headers))
    assert result.status is expected
    assert result.severity is severity
    assert "exploitable vulnerability" in result.description or not headers


@pytest.mark.parametrize(
    ("headers", "present"),
    [
        ((), False),
        (("X-Powered-By", "Express 4.18"), True),
    ],
)
def test_x_powered_by_presence_and_absence_are_informational(
    headers: tuple[()] | tuple[str, str], present: bool
) -> None:
    landing_headers = () if not headers else (headers,)
    result = finding(XPoweredByDisclosureCheck(), context(landing_headers=landing_headers))
    assert result.status is FindingStatus.INFO
    assert result.severity is Severity.INFO
    assert ("Express" in result.evidence[0].value) is present


class ControlledClient:
    def __init__(self) -> None:
        self.budgets: list[RequestBudget] = []

    def normalize(self, raw_url: str) -> NormalizedTarget:
        return URLPolicy().normalize(raw_url)

    async def fetch(
        self, raw_url: str, *, budget: RequestBudget | None = None
    ) -> SafeFetchResult:
        assert budget is not None
        self.budgets.append(budget)
        await budget.consume()
        if raw_url.endswith("/.well-known/security.txt"):
            return SafeFetchResult(
                responses=(
                    response(
                        raw_url,
                        headers=(("Content-Type", "text/plain"),),
                        body=VALID_SECURITY_TXT,
                    ),
                )
            )
        return SafeFetchResult(
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
                    certificate=True,
                ),
            )
        )

    async def fetch_once(
        self, raw_url: str, *, budget: RequestBudget | None = None
    ) -> SafeFetchResult:
        assert budget is not None
        self.budgets.append(budget)
        await budget.consume()
        return SafeFetchResult(
            responses=(
                response(
                    raw_url,
                    status=301,
                    headers=(("Location", "https://example.com/"),),
                ),
            )
        )


@pytest.mark.asyncio
async def test_default_engine_collects_security_txt_with_shared_budget_and_serializes() -> None:
    client = ControlledClient()
    times = iter((NOW - timedelta(milliseconds=2), NOW, NOW + timedelta(milliseconds=2)))
    result = await ScanEngine(client=client, clock=lambda: next(times)).scan(
        ScanRequest(url="https://example.com/")
    )
    assert result.metadata.state is ScanState.COMPLETED
    assert len(result.findings) == 19
    assert result.errors == ()
    assert result.score is not None
    assert result.score.score == 100
    assert len(client.budgets) == 3
    assert client.budgets[0] is client.budgets[1] is client.budgets[2]
    serialized = result.model_dump_json()
    assert "security@example.com" not in serialized
    assert '"score":100' in serialized
