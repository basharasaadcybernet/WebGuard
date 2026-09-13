"""Validated, serialization-safe contracts for WebGuard."""

from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StringConstraints,
    field_validator,
    model_validator,
)

from webguard.domain.enums import (
    FindingStatus,
    Grade,
    HttpScheme,
    RuleEvaluationState,
    ScanErrorKind,
    ScanState,
    Severity,
)

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_RULE_ID = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$")

ShortText = Annotated[str, StringConstraints(min_length=1, max_length=200, strip_whitespace=True)]
LongText = Annotated[str, StringConstraints(min_length=1, max_length=4000, strip_whitespace=True)]
Points = Annotated[Decimal, Field(ge=0, le=1000, max_digits=7, decimal_places=3)]
Fraction = Annotated[Decimal, Field(ge=0, le=1, max_digits=4, decimal_places=3)]


def _validate_redacted_url(value: str) -> str:
    """Ensure a public contract URL cannot contain credentials or raw query values."""
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ValueError("Public URL is malformed") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Public URL must be an absolute HTTP or HTTPS URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("Public URL cannot contain credentials or a fragment")
    if parsed.query and parsed.query != "[redacted]":
        raise ValueError("Public URL query values must be redacted")
    return value


class ContractModel(BaseModel):
    """Strict base model for stable public contracts."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class ScanRequest(ContractModel):
    """Untrusted request entering the scanner boundary."""

    url: Annotated[str, StringConstraints(min_length=1, max_length=2048)]

    @field_validator("url")
    @classmethod
    def reject_control_characters(cls, value: str) -> str:
        if _CONTROL_CHARACTERS.search(value) or "\r" in value or "\n" in value:
            raise ValueError("URL cannot contain control characters")
        return value


class NormalizedTarget(ContractModel):
    """Canonical target with its sensitive query excluded from serialization."""

    scheme: HttpScheme
    hostname: Annotated[str, StringConstraints(min_length=1, max_length=253)]
    port: Annotated[int, Field(ge=1, le=65535)]
    path: Annotated[str, StringConstraints(min_length=1, max_length=4096)] = "/"
    query: Annotated[str, StringConstraints(max_length=4096)] = Field(
        default="", exclude=True, repr=False
    )
    display_url: Annotated[str, StringConstraints(min_length=1, max_length=4096)]

    @field_validator("display_url")
    @classmethod
    def validate_display_url(cls, value: str) -> str:
        return _validate_redacted_url(value)

    @property
    def request_url(self) -> str:
        """Return the internal URL used for a request, including its query."""
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        default_port = 80 if self.scheme is HttpScheme.HTTP else 443
        authority = host if self.port == default_port else f"{host}:{self.port}"
        query = f"?{self.query}" if self.query else ""
        return f"{self.scheme.value}://{authority}{self.path}{query}"


class Evidence(ContractModel):
    """Bounded, presentation-safe evidence for a finding."""

    label: ShortText
    value: Annotated[str, StringConstraints(min_length=1, max_length=1024)]
    source_url: Annotated[str, StringConstraints(min_length=1, max_length=4096)] | None = None

    @field_validator("label", "value", "source_url")
    @classmethod
    def reject_unsafe_text(cls, value: str | None) -> str | None:
        if value is not None and (
            _CONTROL_CHARACTERS.search(value) or "\r" in value or "\n" in value
        ):
            raise ValueError("Evidence cannot contain control characters or newlines")
        return value

    @field_validator("source_url")
    @classmethod
    def validate_source_url(cls, value: str | None) -> str | None:
        return _validate_redacted_url(value) if value is not None else None


class FetchHop(ContractModel):
    """Safe metadata for one request in a redirect chain."""

    index: Annotated[int, Field(ge=0, le=20)]
    request_url: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    destination_ip: IPvAnyAddress
    method: Literal["GET"] = "GET"
    status_code: Annotated[int, Field(ge=100, le=599)]
    response_bytes: Annotated[int, Field(ge=0)]
    elapsed_ms: Annotated[int, Field(ge=0)]
    redirect_location: Annotated[str, StringConstraints(max_length=4096)] | None = None

    @field_validator("request_url", "redirect_location")
    @classmethod
    def validate_public_urls(cls, value: str | None) -> str | None:
        return _validate_redacted_url(value) if value is not None else None


class Finding(ContractModel):
    """Structured outcome produced by a future rule implementation."""

    id: Annotated[str, StringConstraints(min_length=3, max_length=100)]
    title: ShortText
    category: ShortText
    status: FindingStatus
    evaluation_state: Literal["APPLICABLE", "NOT_APPLICABLE"] = "APPLICABLE"
    severity: Severity | None = None
    description: LongText
    evidence: tuple[Evidence, ...] = ()
    recommendation: LongText | None = None
    references: tuple[AnyHttpUrl, ...] = ()

    @field_validator("id")
    @classmethod
    def validate_rule_id(cls, value: str) -> str:
        if not _RULE_ID.fullmatch(value):
            raise ValueError("Finding id must be a stable dotted lowercase identifier")
        return value

    @model_validator(mode="after")
    def validate_severity(self) -> Finding:
        if self.status in {FindingStatus.PASS, FindingStatus.ERROR} and self.severity is not None:
            raise ValueError("PASS and ERROR findings do not carry a security severity")
        if self.status in {FindingStatus.WARNING, FindingStatus.FAIL} and self.severity is None:
            raise ValueError("WARNING and FAIL findings require a severity")
        if self.evaluation_state == "NOT_APPLICABLE" and self.status is not FindingStatus.INFO:
            raise ValueError("NOT_APPLICABLE findings must use informational status")
        return self


class CategoryScore(ContractModel):
    """Transparent points, normalization, and coverage for one scoring category."""

    category: ShortText
    configured_weight: Points
    applicable_points: Points
    evaluated_points: Points
    available_points: Points
    earned_points: Points
    deductions: Points
    normalized_score: Fraction | None = None
    earned_normalized_contribution: Points
    coverage: Fraction | None = None

    @model_validator(mode="after")
    def validate_point_relationships(self) -> CategoryScore:
        if self.applicable_points > self.configured_weight:
            raise ValueError("Applicable points cannot exceed configured weight")
        if self.evaluated_points > self.applicable_points:
            raise ValueError("Evaluated points cannot exceed applicable points")
        if self.available_points != self.evaluated_points:
            raise ValueError("Available points must equal evaluated points")
        if self.earned_points > self.evaluated_points:
            raise ValueError("Earned points cannot exceed evaluated points")
        if self.deductions != self.evaluated_points - self.earned_points:
            raise ValueError("Category deductions must equal available minus earned points")
        if self.earned_normalized_contribution > self.configured_weight:
            raise ValueError("Normalized contribution cannot exceed configured category weight")
        if (self.coverage is None) != (self.applicable_points == 0):
            raise ValueError("Category coverage is absent only when the category is not applicable")
        if (self.normalized_score is None) != (self.evaluated_points == 0):
            raise ValueError("Category normalized score requires evaluated points")
        return self


class RuleContribution(ContractModel):
    """One deterministic rule's transparent scoring contribution or exclusion."""

    rule_id: Annotated[
        str,
        StringConstraints(
            min_length=3,
            max_length=100,
            pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
        ),
    ]
    category: ShortText
    state: RuleEvaluationState
    configured_points: Points
    available_points: Points
    earned_points: Points
    deduction: Points
    credit_fraction: Fraction | None = None
    reason: LongText
    exclusion_reason: LongText | None = None

    @model_validator(mode="after")
    def validate_contribution(self) -> RuleContribution:
        excluded = self.state in {
            RuleEvaluationState.ERROR,
            RuleEvaluationState.NOT_APPLICABLE,
        }
        if excluded:
            if any(
                value != 0
                for value in (self.available_points, self.earned_points, self.deduction)
            ):
                raise ValueError("Excluded rules cannot contribute points or deductions")
            if self.credit_fraction is not None or self.exclusion_reason is None:
                raise ValueError("Excluded rules require only an exclusion reason")
        else:
            if self.available_points != self.configured_points:
                raise ValueError("Evaluated rules make all configured points available")
            if self.earned_points + self.deduction != self.available_points:
                raise ValueError("Rule deduction must reconcile available and earned points")
            if self.credit_fraction is None or self.exclusion_reason is not None:
                raise ValueError("Evaluated rules require credit and cannot have an exclusion")
        return self


class RuleExclusion(ContractModel):
    """Explicit reason that one configured rule did not enter the score denominator."""

    rule_id: Annotated[
        str,
        StringConstraints(
            min_length=3,
            max_length=100,
            pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
        ),
    ]
    state: Literal[RuleEvaluationState.ERROR, RuleEvaluationState.NOT_APPLICABLE]
    reason: LongText


class AppliedScoreCap(ContractModel):
    """One configured safety cap that changed the published score."""

    rule_id: Annotated[
        str,
        StringConstraints(
            min_length=3,
            max_length=100,
            pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
        ),
    ]
    trigger_status: FindingStatus
    maximum_score: Annotated[int, Field(ge=0, le=100)]
    reason: LongText


class ScoreBreakdown(ContractModel):
    """Transparent, coverage-aware result of one versioned scoring calculation."""

    raw_score: Points | None = None
    score: Annotated[int, Field(ge=0, le=100)] | None = None
    grade: Grade | None = None
    scoring_version: ShortText
    configured_points: Points = Decimal("100")
    applicable_points: Points
    evaluated_points: Points
    available_points: Points
    earned_points: Points
    deductions: Points
    coverage: Fraction
    categories: tuple[CategoryScore, ...] = ()
    rule_contributions: tuple[RuleContribution, ...] = ()
    exclusions: tuple[RuleExclusion, ...] = ()
    cap: AppliedScoreCap | None = None
    withholding_reasons: tuple[ShortText, ...] = ()
    explanation: Annotated[str, StringConstraints(min_length=1, max_length=4000)]

    @model_validator(mode="after")
    def validate_totals(self) -> ScoreBreakdown:
        if len({self.raw_score is None, self.score is None, self.grade is None}) != 1:
            raise ValueError("Raw score, final score, and grade must be present together")
        if self.applicable_points > self.configured_points:
            raise ValueError("Applicable points cannot exceed configured points")
        if self.evaluated_points > self.applicable_points:
            raise ValueError("Evaluated points cannot exceed applicable points")
        if self.available_points != self.evaluated_points:
            raise ValueError("Available points must equal evaluated points")
        if self.earned_points > self.evaluated_points:
            raise ValueError("Earned points cannot exceed evaluated points")
        if self.deductions != self.evaluated_points - self.earned_points:
            raise ValueError("Deductions must equal available minus earned points")
        if (self.score is None) != bool(self.withholding_reasons):
            raise ValueError("Withheld scores require explicit withholding reasons")
        if self.score is None and self.cap is not None:
            raise ValueError("A withheld score cannot have an applied cap")
        if self.cap is not None and self.score is not None and self.score > self.cap.maximum_score:
            raise ValueError("Final score cannot exceed its applied cap")
        return self


class ScanMetadata(ContractModel):
    """Operational metadata without persisted request content."""

    scan_id: UUID = Field(default_factory=uuid4)
    started_at: datetime
    finished_at: datetime
    duration_ms: Annotated[int, Field(ge=0)]
    webguard_version: ShortText
    ruleset_version: ShortText
    redirect_count: Annotated[int, Field(ge=0, le=20)] = 0
    state: ScanState

    @field_validator("started_at", "finished_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Scan timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_time_order(self) -> ScanMetadata:
        if self.finished_at < self.started_at:
            raise ValueError("finished_at cannot be earlier than started_at")
        return self


class ScanError(ContractModel):
    """Safe operational error that is explicitly not a vulnerability finding."""

    kind: ScanErrorKind
    code: Annotated[
        str,
        StringConstraints(
            min_length=3,
            max_length=100,
            pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
        ),
    ]
    message: ShortText
    rule_id: (
        Annotated[
            str,
            StringConstraints(
                min_length=3,
                max_length=100,
                pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
            ),
        ]
        | None
    ) = None

    @field_validator("message")
    @classmethod
    def reject_unsafe_message(cls, value: str) -> str:
        if _CONTROL_CHARACTERS.search(value) or "\r" in value or "\n" in value:
            raise ValueError("Scan error message cannot contain controls or newlines")
        return value

    @model_validator(mode="after")
    def validate_rule_relationship(self) -> ScanError:
        if (self.kind is ScanErrorKind.CHECK) != (self.rule_id is not None):
            raise ValueError("Only check errors carry a rule identifier")
        return self


DISCLAIMER = (
    "This score reflects only the security controls tested by WebGuard and does not prove "
    "that the website is free of vulnerabilities."
)


class ScanResult(ContractModel):
    """Top-level result shared by the future CLI, API, UI, and reporters."""

    target: NormalizedTarget | None
    hops: tuple[FetchHop, ...] = ()
    findings: tuple[Finding, ...] = ()
    errors: tuple[ScanError, ...] = ()
    score: ScoreBreakdown | None = None
    metadata: ScanMetadata
    disclaimer: Literal[
        "This score reflects only the security controls tested by WebGuard and does not prove "
        "that the website is free of vulnerabilities."
    ] = (
        "This score reflects only the security controls tested by WebGuard and does not prove "
        "that the website is free of vulnerabilities."
    )
