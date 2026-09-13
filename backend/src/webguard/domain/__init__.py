"""Stable domain contracts shared by all future interfaces."""

from webguard.domain.enums import (
    FindingStatus,
    Grade,
    HttpScheme,
    RuleEvaluationState,
    ScanErrorKind,
    ScanState,
    Severity,
)
from webguard.domain.models import (
    AppliedScoreCap,
    CategoryScore,
    Evidence,
    FetchHop,
    Finding,
    NormalizedTarget,
    RuleContribution,
    RuleExclusion,
    ScanError,
    ScanMetadata,
    ScanRequest,
    ScanResult,
    ScoreBreakdown,
)

__all__ = [
    "AppliedScoreCap",
    "CategoryScore",
    "Evidence",
    "FetchHop",
    "Finding",
    "FindingStatus",
    "Grade",
    "HttpScheme",
    "NormalizedTarget",
    "RuleContribution",
    "RuleEvaluationState",
    "RuleExclusion",
    "ScanError",
    "ScanErrorKind",
    "ScanMetadata",
    "ScanRequest",
    "ScanResult",
    "ScanState",
    "ScoreBreakdown",
    "Severity",
]
