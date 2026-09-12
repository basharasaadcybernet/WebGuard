"""Small helpers for consistent, bounded real findings."""

from pydantic import AnyHttpUrl

from webguard.domain.enums import FindingStatus, Severity
from webguard.domain.models import Evidence, Finding
from webguard.scanner.checks import CheckMetadata, CheckResult


def finding_result(
    metadata: CheckMetadata,
    *,
    status: FindingStatus,
    description: str,
    evidence: str,
    source_url: str,
    recommendation: str,
    severity: Severity | None = None,
) -> CheckResult:
    """Build one consistent finding from already-sanitized observations."""
    bounded_evidence = evidence if len(evidence) <= 1024 else f"{evidence[:1023]}…"
    return CheckResult(
        findings=(
            Finding(
                id=metadata.rule_id,
                title=metadata.title,
                category=metadata.category,
                status=status,
                severity=severity,
                description=description,
                evidence=(
                    Evidence(label="Observation", value=bounded_evidence, source_url=source_url),
                ),
                recommendation=recommendation,
                references=tuple(AnyHttpUrl(reference) for reference in metadata.references),
            ),
        )
    )
