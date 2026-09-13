"""Shared deterministic fakes for security-boundary tests."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

import pytest

from webguard.domain.enums import FindingStatus, Grade, ScanErrorKind, ScanState, Severity
from webguard.domain.models import (
    AppliedScoreCap,
    CategoryScore,
    Evidence,
    Finding,
    NormalizedTarget,
    RuleContribution,
    ScanError,
    ScanMetadata,
    ScanResult,
    ScoreBreakdown,
)
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


def sample_scan_result(
    *,
    state: ScanState = ScanState.COMPLETED,
    score_mode: str = "normal",
    finding: Finding | None = None,
) -> ScanResult:
    """Build deterministic public scan data for CLI/report tests."""
    target = NormalizedTarget(
        scheme="https",
        hostname="example.com",
        port=443,
        path="/account",
        query="token=private-value",
        display_url="https://example.com/account?[redacted]",
    )
    selected_finding = finding or Finding(
        id="headers.content_security_policy",
        title="Content-Security-Policy needs improvement",
        category="Security Headers",
        status=FindingStatus.WARNING,
        severity=Severity.MEDIUM,
        description="The policy was absent from the observed response.",
        evidence=(
            Evidence(
                label="Header observation",
                value="Content-Security-Policy: absent",
                source_url="https://example.com/account?[redacted]",
            ),
        ),
        recommendation="Define and test a restrictive Content-Security-Policy.",
        references=("https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",),
    )
    contribution = RuleContribution(
        rule_id=selected_finding.id,
        category=selected_finding.category,
        state=selected_finding.status.value,
        configured_points=Decimal("10"),
        available_points=Decimal("10"),
        earned_points=Decimal("2.5"),
        deduction=Decimal("7.5"),
        credit_fraction=Decimal("0.25"),
        reason=selected_finding.description,
    )
    category = CategoryScore(
        category="Security Headers",
        configured_weight=Decimal("35"),
        applicable_points=Decimal("35"),
        evaluated_points=Decimal("35"),
        available_points=Decimal("35"),
        earned_points=Decimal("27.5"),
        deductions=Decimal("7.5"),
        normalized_score=Decimal("0.786"),
        earned_normalized_contribution=Decimal("27.5"),
        coverage=Decimal("1"),
    )
    if score_mode == "withheld":
        score = ScoreBreakdown(
            scoring_version="1.0",
            applicable_points=Decimal("100"),
            evaluated_points=Decimal("65"),
            available_points=Decimal("65"),
            earned_points=Decimal("60"),
            deductions=Decimal("5"),
            coverage=Decimal("0.65"),
            categories=(category,),
            rule_contributions=(contribution,),
            withholding_reasons=("Evaluated coverage is below the configured minimum.",),
            explanation="Scan incomplete — insufficient coverage for a reliable score.",
        )
    else:
        cap = (
            AppliedScoreCap(
                rule_id="transport.tls_validity",
                trigger_status=FindingStatus.FAIL,
                maximum_score=59,
                reason="TLS certificate trust failed; the final posture score is capped at F.",
            )
            if score_mode == "capped"
            else None
        )
        score = ScoreBreakdown(
            raw_score=Decimal("92.5"),
            score=59 if cap is not None else 93,
            grade=Grade.F if cap is not None else Grade.A,
            scoring_version="1.0",
            applicable_points=Decimal("100"),
            evaluated_points=Decimal("100"),
            available_points=Decimal("100"),
            earned_points=Decimal("92.5"),
            deductions=Decimal("7.5"),
            coverage=Decimal("1"),
            categories=(category,),
            rule_contributions=(contribution,),
            cap=cap,
            explanation="Deterministic fixture score.",
        )
    errors = (
        (
            ScanError(
                kind=ScanErrorKind.NETWORK,
                code="network.endpoint_unavailable",
                message="The validated endpoint could not establish a connection.",
            ),
        )
        if state is not ScanState.COMPLETED
        else ()
    )
    return ScanResult(
        target=None if state is ScanState.FAILED else target,
        findings=() if state is ScanState.FAILED else (selected_finding,),
        errors=errors,
        score=score,
        metadata=ScanMetadata(
            scan_id=UUID("12345678-1234-5678-1234-567812345678"),
            started_at=datetime(2026, 9, 13, 12, 0, tzinfo=UTC),
            finished_at=datetime(2026, 9, 13, 12, 0, 1, tzinfo=UTC),
            duration_ms=1000,
            webguard_version="0.1.0.dev0",
            ruleset_version="0.1",
            redirect_count=1,
            state=state,
        ),
    )


@pytest.fixture
def make_scan_result():  # type: ignore[no-untyped-def]
    """Expose the deterministic report fixture factory."""
    return sample_scan_result
