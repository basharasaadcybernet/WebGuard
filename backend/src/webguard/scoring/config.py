"""Load and validate WebGuard's versioned scoring policy."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any

from webguard.domain.enums import FindingStatus, Grade, Severity

if TYPE_CHECKING:
    from webguard.scanner.registry import CheckRegistry

_SCORABLE_STATUSES = frozenset(
    {FindingStatus.PASS, FindingStatus.INFO, FindingStatus.WARNING, FindingStatus.FAIL}
)


class ScoringConfigError(ValueError):
    """Raised when the versioned scoring policy is invalid or incomplete."""


@dataclass(frozen=True, slots=True)
class CategoryPolicy:
    id: str
    name: str
    weight: Decimal


@dataclass(frozen=True, slots=True)
class RulePolicy:
    id: str
    category_id: str
    weight: Decimal
    credits: tuple[tuple[FindingStatus, Decimal], ...]
    warning_severity_credits: tuple[tuple[Severity, Decimal], ...] = ()

    def credit(self, status: FindingStatus, severity: Severity | None) -> Decimal:
        if status is FindingStatus.WARNING and severity is not None:
            severity_credit = dict(self.warning_severity_credits).get(severity)
            if severity_credit is not None:
                return severity_credit
        try:
            return dict(self.credits)[status]
        except KeyError as exc:
            raise ScoringConfigError(f"No credit configured for {self.id} status {status}") from exc


@dataclass(frozen=True, slots=True)
class CapPolicy:
    rule_id: str
    status: FindingStatus
    maximum_score: int
    reason: str


@dataclass(frozen=True, slots=True)
class ScoringConfig:
    scoring_version: str
    minimum_coverage: Decimal
    categories: tuple[CategoryPolicy, ...]
    rules: tuple[RulePolicy, ...]
    grade_bands: tuple[tuple[Grade, int], ...]
    caps: tuple[CapPolicy, ...]
    essential_error_rules: tuple[str, ...]

    def validate_registry(self, registry: CheckRegistry) -> None:
        configured = {rule.id for rule in self.rules}
        registered = {check.metadata.rule_id for check in registry}
        if configured != registered:
            unknown = sorted(configured - registered)
            missing = sorted(registered - configured)
            raise ScoringConfigError(
                f"Scoring rule IDs do not match registry; unknown={unknown}, missing={missing}"
            )

    @property
    def rule_map(self) -> dict[str, RulePolicy]:
        return {rule.id: rule for rule in self.rules}

    @property
    def category_map(self) -> dict[str, CategoryPolicy]:
        return {category.id: category for category in self.categories}


def _decimal(value: object, field: str) -> Decimal:
    if isinstance(value, bool):
        raise ScoringConfigError(f"{field} must be numeric")
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ScoringConfigError(f"{field} must be a valid decimal") from exc


def _tables(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = data.get(key)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ScoringConfigError(f"{key} must be an array of tables")
    return value


def _text(table: dict[str, Any], key: str, owner: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ScoringConfigError(f"{owner}.{key} must be non-empty text")
    return value.strip()


def _integer(table: dict[str, Any], key: str, owner: str) -> int:
    value = table.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScoringConfigError(f"{owner}.{key} must be an integer")
    return value


def _unique(values: list[str], label: str) -> None:
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        raise ScoringConfigError(f"Duplicate {label}: {duplicates}")


def _parse_config(data: dict[str, Any]) -> ScoringConfig:
    version = data.get("scoring_version")
    if not isinstance(version, str) or not version.strip():
        raise ScoringConfigError("scoring_version must be non-empty text")
    minimum_coverage = _decimal(data.get("minimum_coverage"), "minimum_coverage")
    if not Decimal("0") <= minimum_coverage <= Decimal("1"):
        raise ScoringConfigError("minimum_coverage must be between 0 and 1")

    categories = tuple(
        CategoryPolicy(
            id=_text(table, "id", "category"),
            name=_text(table, "name", "category"),
            weight=_decimal(table.get("weight"), "category.weight"),
        )
        for table in _tables(data, "categories")
    )
    _unique([category.id for category in categories], "category IDs")
    _unique([category.name for category in categories], "category names")
    if any(category.weight <= 0 for category in categories):
        raise ScoringConfigError("Category weights must be positive")
    if sum((category.weight for category in categories), Decimal("0")) != Decimal("100"):
        raise ScoringConfigError("Category weights must total exactly 100")

    category_ids = {category.id for category in categories}
    rules: list[RulePolicy] = []
    for table in _tables(data, "rules"):
        rule_id = _text(table, "id", "rule")
        category_id = _text(table, "category", rule_id)
        if category_id not in category_ids:
            raise ScoringConfigError(f"Rule {rule_id} references unknown category {category_id}")
        credits_table = table.get("credits")
        if not isinstance(credits_table, dict):
            raise ScoringConfigError(f"Rule {rule_id} credits must be a table")
        try:
            credits = tuple(
                (FindingStatus(key), _decimal(value, f"{rule_id}.credits.{key}"))
                for key, value in credits_table.items()
            )
        except ValueError as exc:
            raise ScoringConfigError(f"Rule {rule_id} has an invalid credit status") from exc
        if {status for status, _ in credits} != _SCORABLE_STATUSES:
            raise ScoringConfigError(
                f"Rule {rule_id} must configure PASS, INFO, WARNING, and FAIL credits"
            )
        credit_map = dict(credits)
        if credit_map[FindingStatus.PASS] != 1 or credit_map[FindingStatus.FAIL] != 0:
            raise ScoringConfigError(f"Rule {rule_id} must give PASS full credit and FAIL zero")
        severity_table = table.get("warning_severity_credits", {})
        if not isinstance(severity_table, dict):
            raise ScoringConfigError(
                f"Rule {rule_id} warning_severity_credits must be a table"
            )
        try:
            severity_credits = tuple(
                (Severity(key), _decimal(value, f"{rule_id}.warning.{key}"))
                for key, value in severity_table.items()
            )
        except ValueError as exc:
            raise ScoringConfigError(f"Rule {rule_id} has an invalid warning severity") from exc
        all_fractions = [credit for _, credit in (*credits, *severity_credits)]
        if any(not Decimal("0") <= credit <= Decimal("1") for credit in all_fractions):
            raise ScoringConfigError(f"Rule {rule_id} credit fractions must be between 0 and 1")
        rules.append(
            RulePolicy(
                id=rule_id,
                category_id=category_id,
                weight=_decimal(table.get("weight"), f"{rule_id}.weight"),
                credits=credits,
                warning_severity_credits=severity_credits,
            )
        )
    _unique([rule.id for rule in rules], "rule IDs")
    if any(rule.weight <= 0 for rule in rules):
        raise ScoringConfigError("Rule weights must be positive")
    for category in categories:
        assigned = sum(
            (rule.weight for rule in rules if rule.category_id == category.id), Decimal("0")
        )
        if assigned != category.weight:
            raise ScoringConfigError(
                f"Rule weights for {category.id} total {assigned}, expected {category.weight}"
            )

    grades: list[tuple[Grade, int]] = []
    for table in _tables(data, "grades"):
        try:
            grade = Grade(_text(table, "grade", "grade"))
        except ValueError as exc:
            raise ScoringConfigError("Grade band uses an unknown grade") from exc
        grades.append((grade, _integer(table, "minimum_score", grade.value)))
    _unique([grade.value for grade, _ in grades], "grade bands")
    if [grade for grade, _ in grades] != [Grade.A, Grade.B, Grade.C, Grade.D, Grade.F]:
        raise ScoringConfigError("Grade bands must be ordered A, B, C, D, F")
    thresholds = [minimum for _, minimum in grades]
    if thresholds != sorted(thresholds, reverse=True) or len(set(thresholds)) != len(thresholds):
        raise ScoringConfigError("Grade thresholds must be unique and descending")
    if thresholds[0] > 100 or thresholds[-1] != 0 or any(value < 0 for value in thresholds):
        raise ScoringConfigError("Grade thresholds must span 0 through at most 100")

    rule_ids = {rule.id for rule in rules}
    caps: list[CapPolicy] = []
    for table in _tables(data, "caps"):
        rule_id = _text(table, "rule_id", "cap")
        if rule_id not in rule_ids:
            raise ScoringConfigError(f"Cap references unknown rule ID {rule_id}")
        try:
            status = FindingStatus(_text(table, "status", f"cap.{rule_id}"))
        except ValueError as exc:
            raise ScoringConfigError(f"Cap for {rule_id} has an invalid status") from exc
        if status not in _SCORABLE_STATUSES:
            raise ScoringConfigError(f"Cap for {rule_id} cannot use {status}")
        maximum_score = _integer(table, "maximum_score", f"cap.{rule_id}")
        if not 0 <= maximum_score <= 100:
            raise ScoringConfigError(f"Cap for {rule_id} must be between 0 and 100")
        caps.append(
            CapPolicy(
                rule_id=rule_id,
                status=status,
                maximum_score=maximum_score,
                reason=_text(table, "reason", f"cap.{rule_id}"),
            )
        )
    _unique([f"{cap.rule_id}:{cap.status.value}" for cap in caps], "cap triggers")

    essential = data.get("essential_error_rules")
    if not isinstance(essential, list) or any(not isinstance(item, str) for item in essential):
        raise ScoringConfigError("essential_error_rules must be an array of rule IDs")
    essential_rules = tuple(essential)
    _unique(list(essential_rules), "essential error rule IDs")
    unknown_essential = sorted(set(essential_rules) - rule_ids)
    if unknown_essential:
        raise ScoringConfigError(f"Essential error rules are unknown: {unknown_essential}")

    return ScoringConfig(
        scoring_version=version.strip(),
        minimum_coverage=minimum_coverage,
        categories=categories,
        rules=tuple(rules),
        grade_bands=tuple(grades),
        caps=tuple(caps),
        essential_error_rules=essential_rules,
    )


def load_scoring_config(path: Path | None = None) -> ScoringConfig:
    """Load the packaged policy or an explicitly supplied test/deployment policy."""
    try:
        if path is None:
            content = files("webguard.scoring").joinpath("weights.toml").read_text(encoding="utf-8")
        else:
            content = path.read_text(encoding="utf-8")
        data = tomllib.loads(content)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ScoringConfigError("Scoring configuration could not be loaded") from exc
    return _parse_config(data)
