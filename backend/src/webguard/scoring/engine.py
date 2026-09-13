"""Deterministic, coverage-aware scoring over completed rule outcomes."""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal

from webguard.domain.enums import FindingStatus, Grade, RuleEvaluationState
from webguard.domain.models import (
    AppliedScoreCap,
    CategoryScore,
    Finding,
    RuleContribution,
    RuleExclusion,
    ScanError,
    ScoreBreakdown,
)
from webguard.scanner.registry import CheckRegistry
from webguard.scoring.config import ScoringConfig, load_scoring_config

_ZERO = Decimal("0")
_ONE = Decimal("1")
_THREE_PLACES = Decimal("0.001")


class ScoringInputError(ValueError):
    """Raised when rule outcomes cannot be reconciled deterministically."""


def _bounded(value: Decimal) -> Decimal:
    return value.quantize(_THREE_PLACES, rounding=ROUND_HALF_UP)


class ScoringEngine:
    """Apply one validated scoring policy to one immutable set of rule outcomes."""

    def __init__(
        self,
        registry: CheckRegistry,
        config: ScoringConfig | None = None,
    ) -> None:
        self._registry = registry
        self.config = config or load_scoring_config()
        self.config.validate_registry(registry)

    def grade_for_score(self, score: int) -> Grade:
        if not 0 <= score <= 100:
            raise ValueError("Score must be between 0 and 100")
        return next(
            grade for grade, minimum in self.config.grade_bands if score >= minimum
        )

    def score(
        self,
        findings: tuple[Finding, ...],
        errors: tuple[ScanError, ...],
    ) -> ScoreBreakdown:
        finding_map = self._unique_findings(findings)
        error_map = self._unique_rule_errors(errors)
        overlap = sorted(finding_map.keys() & error_map.keys())
        if overlap:
            raise ScoringInputError(f"Rules cannot have findings and errors together: {overlap}")

        category_map = self.config.category_map
        contributions: list[RuleContribution] = []
        exclusions: list[RuleExclusion] = []
        states: dict[str, RuleEvaluationState] = {}
        for policy in self.config.rules:
            category = category_map[policy.category_id]
            finding = finding_map.get(policy.id)
            error = error_map.get(policy.id)
            if error is not None:
                state = RuleEvaluationState.ERROR
                reason = error.message
                exclusion_reason = "Rule evaluation failed; its points were excluded."
                contribution = RuleContribution(
                    rule_id=policy.id,
                    category=category.name,
                    state=state,
                    configured_points=policy.weight,
                    available_points=_ZERO,
                    earned_points=_ZERO,
                    deduction=_ZERO,
                    reason=reason,
                    exclusion_reason=exclusion_reason,
                )
                exclusions.append(
                    RuleExclusion(
                        rule_id=policy.id,
                        state=RuleEvaluationState.ERROR,
                        reason=exclusion_reason,
                    )
                )
            elif finding is None or finding.evaluation_state == "NOT_APPLICABLE":
                state = RuleEvaluationState.NOT_APPLICABLE
                reason = (
                    finding.description
                    if finding is not None
                    else "The rule was not applicable to the available observations."
                )
                exclusion_reason = "Rule was not applicable; no points were awarded or deducted."
                contribution = RuleContribution(
                    rule_id=policy.id,
                    category=category.name,
                    state=state,
                    configured_points=policy.weight,
                    available_points=_ZERO,
                    earned_points=_ZERO,
                    deduction=_ZERO,
                    reason=reason,
                    exclusion_reason=exclusion_reason,
                )
                exclusions.append(
                    RuleExclusion(
                        rule_id=policy.id,
                        state=RuleEvaluationState.NOT_APPLICABLE,
                        reason=exclusion_reason,
                    )
                )
            else:
                if finding.status is FindingStatus.ERROR:
                    raise ScoringInputError("ERROR findings must be represented as ScanError")
                state = RuleEvaluationState(finding.status.value)
                credit = policy.credit(finding.status, finding.severity)
                earned = _bounded(policy.weight * credit)
                contribution = RuleContribution(
                    rule_id=policy.id,
                    category=category.name,
                    state=state,
                    configured_points=policy.weight,
                    available_points=policy.weight,
                    earned_points=earned,
                    deduction=_bounded(policy.weight - earned),
                    credit_fraction=credit,
                    reason=finding.description,
                )
            contributions.append(contribution)
            states[policy.id] = state

        categories: list[CategoryScore] = []
        active_category_weight = _ZERO
        normalized_contribution_total = _ZERO
        for category in self.config.categories:
            items = [item for item in contributions if item.category == category.name]
            applicable = sum(
                (
                    item.configured_points
                    for item in items
                    if item.state is not RuleEvaluationState.NOT_APPLICABLE
                ),
                _ZERO,
            )
            evaluated = sum((item.available_points for item in items), _ZERO)
            earned = sum((item.earned_points for item in items), _ZERO)
            coverage = _bounded(evaluated / applicable) if applicable else None
            normalized = _bounded(earned / evaluated) if evaluated else None
            normalized_contribution = (
                _bounded(category.weight * earned / evaluated) if evaluated else _ZERO
            )
            if evaluated:
                active_category_weight += category.weight
                normalized_contribution_total += category.weight * earned / evaluated
            categories.append(
                CategoryScore(
                    category=category.name,
                    configured_weight=category.weight,
                    applicable_points=applicable,
                    evaluated_points=evaluated,
                    available_points=evaluated,
                    earned_points=earned,
                    deductions=_bounded(evaluated - earned),
                    normalized_score=normalized,
                    earned_normalized_contribution=normalized_contribution,
                    coverage=coverage,
                )
            )

        applicable_total = sum(
            (
                item.configured_points
                for item in contributions
                if item.state is not RuleEvaluationState.NOT_APPLICABLE
            ),
            _ZERO,
        )
        evaluated_total = sum((item.available_points for item in contributions), _ZERO)
        earned_total = sum((item.earned_points for item in contributions), _ZERO)
        coverage = _bounded(evaluated_total / applicable_total) if applicable_total else _ZERO
        withholding_reasons: list[str] = []
        if coverage < self.config.minimum_coverage:
            withholding_reasons.append(
                f"Evaluated coverage {coverage} is below the configured minimum "
                f"{self.config.minimum_coverage}."
            )
        essential_errors = [
            rule_id
            for rule_id in self.config.essential_error_rules
            if states[rule_id] is RuleEvaluationState.ERROR
        ]
        if essential_errors:
            withholding_reasons.append(
                "Essential transport rules could not be evaluated: " + ", ".join(essential_errors)
            )
        if not evaluated_total and not withholding_reasons:
            withholding_reasons.append("No configured rule produced an evaluated outcome.")

        raw_score: Decimal | None = None
        final_score: int | None = None
        grade: Grade | None = None
        applied_cap: AppliedScoreCap | None = None
        if not withholding_reasons:
            if not active_category_weight:
                raise ScoringInputError("No active category weight was available")
            raw_score = _bounded(
                normalized_contribution_total / active_category_weight * Decimal("100")
            )
            final_score = int(raw_score.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
            triggered_caps = [
                cap
                for cap in self.config.caps
                if states[cap.rule_id].value == cap.status.value
                and final_score > cap.maximum_score
            ]
            if triggered_caps:
                cap = min(triggered_caps, key=lambda item: item.maximum_score)
                final_score = cap.maximum_score
                applied_cap = AppliedScoreCap(
                    rule_id=cap.rule_id,
                    trigger_status=cap.status,
                    maximum_score=cap.maximum_score,
                    reason=cap.reason,
                )
            grade = self.grade_for_score(final_score)

        explanation = (
            "Scan incomplete — insufficient coverage for a reliable score."
            if withholding_reasons
            else (
                f"Score calculated with scoring ruleset {self.config.scoring_version} at "
                f"{coverage * 100}% evaluated coverage."
                + (f" {applied_cap.reason}" if applied_cap is not None else "")
            )
        )
        return ScoreBreakdown(
            raw_score=raw_score,
            score=final_score,
            grade=grade,
            scoring_version=self.config.scoring_version,
            configured_points=Decimal("100"),
            applicable_points=applicable_total,
            evaluated_points=evaluated_total,
            available_points=evaluated_total,
            earned_points=earned_total,
            deductions=_bounded(evaluated_total - earned_total),
            coverage=coverage,
            categories=tuple(categories),
            rule_contributions=tuple(contributions),
            exclusions=tuple(exclusions),
            cap=applied_cap,
            withholding_reasons=tuple(withholding_reasons),
            explanation=explanation,
        )

    def _unique_findings(self, findings: tuple[Finding, ...]) -> dict[str, Finding]:
        known = self.config.rule_map
        result: dict[str, Finding] = {}
        for finding in findings:
            if finding.id not in known:
                raise ScoringInputError(f"Finding uses unknown scoring rule ID: {finding.id}")
            if finding.id in result:
                raise ScoringInputError(f"Duplicate finding for rule: {finding.id}")
            result[finding.id] = finding
        return result

    def _unique_rule_errors(self, errors: tuple[ScanError, ...]) -> dict[str, ScanError]:
        known = self.config.rule_map
        result: dict[str, ScanError] = {}
        for error in errors:
            if error.rule_id is None:
                continue
            if error.rule_id not in known:
                raise ScoringInputError(f"Error uses unknown scoring rule ID: {error.rule_id}")
            if error.rule_id in result:
                raise ScoringInputError(f"Duplicate error for rule: {error.rule_id}")
            result[error.rule_id] = error
        return result
