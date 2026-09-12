"""Stable domain contracts shared by all future interfaces."""

from webguard.domain.enums import FindingStatus, Grade, HttpScheme, ScanState, Severity
from webguard.domain.models import (
    CategoryScore,
    Evidence,
    FetchHop,
    Finding,
    NormalizedTarget,
    ScanMetadata,
    ScanRequest,
    ScanResult,
    ScoreBreakdown,
)

__all__ = [
    "CategoryScore",
    "Evidence",
    "FetchHop",
    "Finding",
    "FindingStatus",
    "Grade",
    "HttpScheme",
    "NormalizedTarget",
    "ScanMetadata",
    "ScanRequest",
    "ScanResult",
    "ScanState",
    "ScoreBreakdown",
    "Severity",
]
