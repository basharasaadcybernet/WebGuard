"""Stable domain contracts shared by all future interfaces."""

from webguard.domain.enums import (
    FindingStatus,
    Grade,
    HttpScheme,
    ScanErrorKind,
    ScanState,
    Severity,
)
from webguard.domain.models import (
    CategoryScore,
    Evidence,
    FetchHop,
    Finding,
    NormalizedTarget,
    ScanError,
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
    "ScanError",
    "ScanErrorKind",
    "ScanMetadata",
    "ScanRequest",
    "ScanResult",
    "ScanState",
    "ScoreBreakdown",
    "Severity",
]
