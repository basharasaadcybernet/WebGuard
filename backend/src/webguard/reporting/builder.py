"""Pure projection from ScanResult to the versioned report contract."""

from __future__ import annotations

from webguard.domain.enums import FindingStatus, Severity
from webguard.domain.models import Finding, ScanResult
from webguard.reporting.models import ReportDocument, SeverityCount

_SEVERITY_ORDER = (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
_SEVERITY_RANK = {severity: index for index, severity in enumerate(_SEVERITY_ORDER)}

_METHODOLOGY = (
    "Passive inspection of HTTPS, TLS, redirects, response headers, cookies, and bounded content.",
    "Nineteen registered rules consume only observations collected by WebGuard's protected client.",
    "The posture score is deterministic, versioned, coverage-aware, and never recalculated here.",
)

_LIMITATIONS = (
    "This is a passive web security posture assessment, not a penetration test.",
    "Application logic, authorization, dependencies, internal infrastructure, and exploitability "
    "are outside this report's scope.",
    "Results reflect one bounded observation at the recorded scan time and may change later.",
)


def reportable_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Return non-pass outcomes in stable severity and rule-ID order."""
    return tuple(
        sorted(
            (finding for finding in findings if finding.status is not FindingStatus.PASS),
            key=lambda finding: (
                _SEVERITY_RANK.get(finding.severity or Severity.INFO, len(_SEVERITY_ORDER)),
                finding.id,
            ),
        )
    )


class ReportBuilder:
    """Build renderer-independent report data from a public ScanResult only."""

    def build(self, result: ScanResult) -> ReportDocument:
        findings = reportable_findings(result.findings)
        return ReportDocument(
            webguard_version=result.metadata.webguard_version,
            target=result.target,
            scan_metadata=result.metadata,
            completion_state=result.metadata.state,
            score=result.score,
            severity_summary=tuple(
                SeverityCount(
                    severity=severity,
                    count=sum(1 for finding in findings if finding.severity is severity),
                )
                for severity in _SEVERITY_ORDER
            ),
            findings=findings,
            operational_errors=result.errors,
            methodology=_METHODOLOGY,
            limitations=_LIMITATIONS,
            disclaimer=result.disclaimer,
        )
