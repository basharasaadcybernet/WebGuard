from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from pydantic import ValidationError

from webguard.domain.enums import FindingStatus, HttpScheme, ScanState, Severity
from webguard.domain.models import (
    CategoryScore,
    Evidence,
    Finding,
    NormalizedTarget,
    ScanMetadata,
    ScanRequest,
    ScanResult,
    ScoreBreakdown,
)


def target() -> NormalizedTarget:
    return NormalizedTarget(
        scheme=HttpScheme.HTTPS,
        hostname="example.com",
        port=443,
        path="/account",
        query="token=secret",
        display_url="https://example.com/account?[redacted]",
    )


def metadata() -> ScanMetadata:
    started = datetime.now(UTC)
    return ScanMetadata(
        started_at=started,
        finished_at=started + timedelta(milliseconds=12),
        duration_ms=12,
        webguard_version="0.1.0",
        ruleset_version="0.1.0",
        state=ScanState.PARTIAL,
    )


def test_scan_request_rejects_controls_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ScanRequest(url="https://example.com\ninternal")
    with pytest.raises(ValidationError):
        ScanRequest(url="https://example.com", unexpected=True)  # type: ignore[call-arg]


def test_normalized_target_query_is_available_internally_but_never_serialized() -> None:
    normalized = target()
    assert normalized.request_url == "https://example.com/account?token=secret"
    assert normalized.query == "token=secret"
    assert "query" not in normalized.model_dump(mode="json")


def test_evidence_rejects_header_injection() -> None:
    with pytest.raises(ValidationError):
        Evidence(label="Header", value="safe\r\nSet-Cookie: secret=1")


def test_public_contract_urls_require_redacted_queries() -> None:
    with pytest.raises(ValidationError, match="must be redacted"):
        Evidence(
            label="Source",
            value="Header was present",
            source_url="https://example.com/?token=secret",
        )
    evidence = Evidence(
        label="Source",
        value="Header was present",
        source_url="https://example.com/?[redacted]",
    )
    assert evidence.source_url == "https://example.com/?[redacted]"


@pytest.mark.parametrize(
    ("status", "severity"),
    [
        (FindingStatus.PASS, Severity.LOW),
        (FindingStatus.ERROR, Severity.INFO),
        (FindingStatus.WARNING, None),
        (FindingStatus.FAIL, None),
    ],
)
def test_finding_rejects_inconsistent_severity(
    status: FindingStatus, severity: Severity | None
) -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="headers.content_security_policy",
            title="CSP",
            category="Headers",
            status=status,
            severity=severity,
            description="Contract validation only.",
        )


def test_finding_rule_identifier_is_stable_and_serializable() -> None:
    finding = Finding(
        id="transport.https_available",
        title="HTTPS availability",
        category="Transport",
        status=FindingStatus.INFO,
        severity=Severity.INFO,
        description="No actual rule is implemented.",
        references=("https://owasp.org/",),
    )
    assert finding.model_dump(mode="json")["id"] == "transport.https_available"

    with pytest.raises(ValidationError):
        finding.model_copy(update={"id": "HTTPS Available"}).model_validate(
            {**finding.model_dump(), "id": "HTTPS Available"}
        )


def test_category_and_score_relationships_are_validated() -> None:
    category = CategoryScore(
        category="Transport",
        configured_weight=Decimal("30"),
        applicable_points=Decimal("20"),
        earned_points=Decimal("15"),
        coverage=Decimal("0.667"),
    )
    score = ScoreBreakdown(
        score=None,
        grade=None,
        applicable_points=Decimal("20"),
        earned_points=Decimal("15"),
        coverage=Decimal("0.2"),
        categories=(category,),
        explanation="Score withheld because coverage is incomplete.",
    )
    assert score.score is None

    with pytest.raises(ValidationError):
        CategoryScore(
            category="Transport",
            configured_weight=Decimal("30"),
            applicable_points=Decimal("20"),
            earned_points=Decimal("21"),
            coverage=Decimal("1"),
        )


def test_metadata_requires_timezone_and_order() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        ScanMetadata(
            started_at=datetime.now(),
            finished_at=now,
            duration_ms=0,
            webguard_version="0.1",
            ruleset_version="0.1",
            state=ScanState.FAILED,
        )
    with pytest.raises(ValidationError):
        ScanMetadata(
            started_at=now,
            finished_at=now - timedelta(seconds=1),
            duration_ms=0,
            webguard_version="0.1",
            ruleset_version="0.1",
            state=ScanState.FAILED,
        )


def test_scan_result_nested_serialization_does_not_leak_query() -> None:
    result = ScanResult(target=target(), metadata=metadata())
    serialized = result.model_dump_json()
    assert "token=secret" not in serialized
    assert "does not prove" in serialized
