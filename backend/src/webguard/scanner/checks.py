"""Typed contracts for deterministic, observation-only security checks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from webguard.domain.models import Finding
from webguard.scanner.context import ScanContext

_RULE_ID = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")


@dataclass(frozen=True, slots=True)
class CheckMetadata:
    """Stable identity and deterministic ordering metadata for one check."""

    rule_id: str
    title: str
    category: str
    order: int = 100
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _RULE_ID.fullmatch(self.rule_id):
            raise ValueError("Check rule_id must be a stable dotted lowercase identifier")
        if not self.title.strip() or not self.category.strip():
            raise ValueError("Check title and category cannot be empty")
        if self.order < 0:
            raise ValueError("Check order cannot be negative")


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Structured observations returned by one applicable check."""

    findings: tuple[Finding, ...] = ()


class CheckEvaluationError(Exception):
    """Expected inability to evaluate a check without treating it as a finding."""


@runtime_checkable
class SecurityCheck(Protocol):
    """Observation-only check interface; implementations receive no network client."""

    @property
    def metadata(self) -> CheckMetadata: ...

    def is_applicable(self, context: ScanContext) -> bool: ...

    def evaluate(self, context: ScanContext) -> CheckResult: ...
