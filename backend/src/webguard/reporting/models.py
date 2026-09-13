"""Stable public contracts shared by all WebGuard report renderers."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from webguard.domain.enums import ScanState, Severity
from webguard.domain.models import (
    ContractModel,
    Finding,
    NormalizedTarget,
    ScanError,
    ScanMetadata,
    ScoreBreakdown,
    ShortText,
)

REPORT_SCHEMA_VERSION = "1.0"


class SeverityCount(ContractModel):
    """Count of reportable findings at one severity."""

    severity: Severity
    count: Annotated[int, Field(ge=0)]


class ReportDocument(ContractModel):
    """Versioned, renderer-independent projection of a public scan result."""

    report_schema_version: Literal["1.0"] = "1.0"
    webguard_version: ShortText
    target: NormalizedTarget | None
    scan_metadata: ScanMetadata
    completion_state: ScanState
    score: ScoreBreakdown | None
    severity_summary: tuple[SeverityCount, ...]
    findings: tuple[Finding, ...]
    operational_errors: tuple[ScanError, ...]
    methodology: tuple[ShortText, ...]
    limitations: tuple[ShortText, ...]
    disclaimer: Literal[
        "This score reflects only the security controls tested by WebGuard and does not prove "
        "that the website is free of vulnerabilities."
    ] = (
        "This score reflects only the security controls tested by WebGuard and does not prove "
        "that the website is free of vulnerabilities."
    )

    @model_validator(mode="after")
    def validate_metadata_projection(self) -> ReportDocument:
        if self.webguard_version != self.scan_metadata.webguard_version:
            raise ValueError("Report and scan WebGuard versions must match")
        if self.completion_state is not self.scan_metadata.state:
            raise ValueError("Report completion state must match scan metadata")
        expected_severities = (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        if tuple(item.severity for item in self.severity_summary) != expected_severities:
            raise ValueError("Severity summary must contain HIGH, MEDIUM, LOW, and INFO once")
        return self
