from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

import pytest

from webguard.checks import default_check_registry
from webguard.domain.enums import FindingStatus, Grade, ScanErrorKind, Severity
from webguard.domain.models import Evidence, Finding, ScanError
from webguard.scoring import (
    ScoringConfigError,
    ScoringEngine,
    ScoringInputError,
    load_scoring_config,
)


@dataclass(frozen=True)
class SyntheticProfile:
    name: str
    outcomes: dict[str, tuple[FindingStatus, Severity | None]]
    errors: frozenset[str] = frozenset()
    not_applicable: frozenset[str] = frozenset()


AVERAGE_OUTCOMES: dict[str, tuple[FindingStatus, Severity | None]] = {
    "transport.tls_expiry": (FindingStatus.WARNING, Severity.MEDIUM),
    "headers.strict_transport_security": (FindingStatus.WARNING, Severity.LOW),
    "headers.content_security_policy": (FindingStatus.WARNING, Severity.MEDIUM),
    "cookies.secure": (FindingStatus.WARNING, Severity.LOW),
    "cookies.http_only": (FindingStatus.INFO, Severity.INFO),
    "cookies.same_site": (FindingStatus.WARNING, Severity.LOW),
    "content.mixed_content": (FindingStatus.WARNING, Severity.MEDIUM),
    "hygiene.security_txt": (FindingStatus.INFO, Severity.INFO),
    "hygiene.server_disclosure": (FindingStatus.WARNING, Severity.LOW),
    "hygiene.x_powered_by": (FindingStatus.INFO, Severity.INFO),
}

PROFILES = (
    SyntheticProfile(name="excellent_site", outcomes={}),
    SyntheticProfile(name="average_site", outcomes=AVERAGE_OUTCOMES),
    SyntheticProfile(
        name="weak_site",
        outcomes={
            check.metadata.rule_id: (FindingStatus.FAIL, Severity.HIGH)
            for check in default_check_registry()
        },
    ),
    SyntheticProfile(
        name="transport_broken",
        outcomes={"transport.https_available": (FindingStatus.FAIL, Severity.MEDIUM)},
    ),
    SyntheticProfile(
        name="low_coverage_site",
        outcomes={},
        errors=frozenset(
            {
                "headers.strict_transport_security",
                "headers.content_security_policy",
                "headers.x_content_type_options",
                "headers.referrer_policy",
                "headers.permissions_policy",
                "headers.clickjacking_protection",
            }
        ),
    ),
)


def scorer() -> ScoringEngine:
    return ScoringEngine(default_check_registry())


def test_default_configuration_matches_frozen_registry_and_approved_weights() -> None:
    calculator = scorer()
    assert [(category.name, category.weight) for category in calculator.config.categories] == [
        ("Transport Security", Decimal("30")),
        ("Security Headers", Decimal("35")),
        ("Cookie Security", Decimal("15")),
        ("Content Protection", Decimal("10")),
        ("Information Disclosure / Hygiene", Decimal("10")),
    ]
    assert {rule.id: rule.weight for rule in calculator.config.rules} == {
        "transport.https_available": Decimal("10"),
        "transport.http_redirect": Decimal("4"),
        "transport.tls_validity": Decimal("6"),
        "transport.tls_hostname": Decimal("4"),
        "transport.tls_expiry": Decimal("3"),
        "transport.https_downgrade": Decimal("3"),
        "headers.strict_transport_security": Decimal("7"),
        "headers.content_security_policy": Decimal("10"),
        "headers.x_content_type_options": Decimal("5"),
        "headers.referrer_policy": Decimal("4"),
        "headers.permissions_policy": Decimal("2"),
        "headers.clickjacking_protection": Decimal("7"),
        "cookies.secure": Decimal("7"),
        "cookies.http_only": Decimal("3"),
        "cookies.same_site": Decimal("5"),
        "content.mixed_content": Decimal("10"),
        "hygiene.security_txt": Decimal("4"),
        "hygiene.server_disclosure": Decimal("3"),
        "hygiene.x_powered_by": Decimal("3"),
    }
    assert calculator.config.minimum_coverage == Decimal("0.700")
    assert calculator.config.grade_bands == (
        (Grade.A, 90),
        (Grade.B, 80),
        (Grade.C, 70),
        (Grade.D, 60),
        (Grade.F, 0),
    )
    assert len(calculator.config.caps) == 3


def inputs(
    profile: SyntheticProfile,
    *,
    evidence_secret: str | None = None,
) -> tuple[tuple[Finding, ...], tuple[ScanError, ...]]:
    findings: list[Finding] = []
    errors: list[ScanError] = []
    for check in default_check_registry():
        rule_id = check.metadata.rule_id
        if rule_id in profile.errors:
            errors.append(
                ScanError(
                    kind=ScanErrorKind.CHECK,
                    code="check.evaluation_failed",
                    message="Synthetic controlled evaluation error.",
                    rule_id=rule_id,
                )
            )
            continue
        if rule_id in profile.not_applicable:
            findings.append(
                Finding(
                    id=rule_id,
                    title=check.metadata.title,
                    category=check.metadata.category,
                    status=FindingStatus.INFO,
                    severity=Severity.INFO,
                    evaluation_state="NOT_APPLICABLE",
                    description="Synthetic rule was not applicable.",
                )
            )
            continue
        status, severity = profile.outcomes.get(rule_id, (FindingStatus.PASS, None))
        findings.append(
            Finding(
                id=rule_id,
                title=check.metadata.title,
                category=check.metadata.category,
                status=status,
                severity=severity,
                description=f"Synthetic {status.value} outcome for {rule_id}.",
                evidence=(
                    (Evidence(label="Secret", value=evidence_secret),)
                    if evidence_secret is not None and rule_id == "headers.content_security_policy"
                    else ()
                ),
            )
        )
    return tuple(findings), tuple(errors)


@pytest.mark.parametrize(
    ("profile_name", "raw", "final", "grade", "coverage"),
    [
        ("excellent_site", Decimal("100.000"), 100, Grade.A, Decimal("1.000")),
        ("average_site", Decimal("69.750"), 70, Grade.C, Decimal("1.000")),
        ("weak_site", Decimal("0.000"), 0, Grade.F, Decimal("1.000")),
        ("transport_broken", Decimal("90.000"), 59, Grade.F, Decimal("1.000")),
        ("low_coverage_site", None, None, None, Decimal("0.650")),
    ],
)
def test_named_regression_profiles(
    profile_name: str,
    raw: Decimal | None,
    final: int | None,
    grade: Grade | None,
    coverage: Decimal,
) -> None:
    profile = next(item for item in PROFILES if item.name == profile_name)
    findings, errors = inputs(profile)
    result = scorer().score(findings, errors)
    assert result.raw_score == raw
    assert result.score == final
    assert result.grade is grade
    assert result.coverage == coverage


def test_perfect_posture_exposes_full_transparent_breakdown() -> None:
    result = scorer().score(*inputs(PROFILES[0]))
    assert result.scoring_version == "1.0"
    assert result.configured_points == Decimal("100")
    assert result.applicable_points == Decimal("100")
    assert result.evaluated_points == Decimal("100")
    assert result.available_points == Decimal("100")
    assert result.earned_points == Decimal("100")
    assert result.deductions == Decimal("0")
    assert result.exclusions == ()
    assert result.cap is None
    assert len(result.categories) == 5
    assert len(result.rule_contributions) == 19


def test_realistic_mixture_has_exact_rule_and_category_math() -> None:
    profile = next(item for item in PROFILES if item.name == "average_site")
    result = scorer().score(*inputs(profile))
    assert result.earned_points == Decimal("69.750")
    assert result.deductions == Decimal("30.250")
    categories = {category.category: category for category in result.categories}
    assert categories["Transport Security"].earned_points == Decimal("28.500")
    assert categories["Security Headers"].earned_points == Decimal("24.000")
    assert categories["Cookie Security"].earned_points == Decimal("8.250")
    assert categories["Content Protection"].earned_points == Decimal("2.500")
    assert categories["Information Disclosure / Hygiene"].earned_points == Decimal("6.500")


@pytest.mark.parametrize(
    ("outcomes", "raw", "final"),
    [
        (
            {"transport.tls_validity": (FindingStatus.FAIL, Severity.HIGH)},
            Decimal("94.000"),
            59,
        ),
        (
            {"headers.content_security_policy": (FindingStatus.WARNING, Severity.MEDIUM)},
            Decimal("92.500"),
            93,
        ),
        (
            {"headers.strict_transport_security": (FindingStatus.WARNING, Severity.LOW)},
            Decimal("96.500"),
            97,
        ),
        (
            {
                "cookies.secure": (FindingStatus.WARNING, Severity.LOW),
                "cookies.http_only": (FindingStatus.INFO, Severity.INFO),
                "cookies.same_site": (FindingStatus.WARNING, Severity.LOW),
            },
            Decimal("93.250"),
            93,
        ),
        (
            {"content.mixed_content": (FindingStatus.WARNING, Severity.MEDIUM)},
            Decimal("92.500"),
            93,
        ),
    ],
)
def test_individual_failure_and_warning_effects(
    outcomes: dict[str, tuple[FindingStatus, Severity | None]],
    raw: Decimal,
    final: int,
) -> None:
    result = scorer().score(*inputs(SyntheticProfile("condition", outcomes)))
    assert result.raw_score == raw
    assert result.score == final


def test_no_cookies_excludes_category_without_free_points_or_penalty() -> None:
    cookie_ids = frozenset({"cookies.secure", "cookies.http_only", "cookies.same_site"})
    profile = SyntheticProfile("no_cookies", {}, not_applicable=cookie_ids)
    result = scorer().score(*inputs(profile))
    cookie_category = next(
        category for category in result.categories if category.category == "Cookie Security"
    )
    assert result.score == 100
    assert result.applicable_points == Decimal("85")
    assert result.available_points == Decimal("85")
    assert cookie_category.applicable_points == 0
    assert cookie_category.earned_points == 0
    assert cookie_category.coverage is None
    assert {item.rule_id for item in result.exclusions} == cookie_ids


def test_one_error_reduces_coverage_but_is_not_pass_or_deduction() -> None:
    profile = SyntheticProfile("one_error", {}, errors=frozenset({"content.mixed_content"}))
    result = scorer().score(*inputs(profile))
    contribution = next(
        item for item in result.rule_contributions if item.rule_id == "content.mixed_content"
    )
    assert result.coverage == Decimal("0.900")
    assert result.score == 100
    assert contribution.state.value == "ERROR"
    assert contribution.available_points == 0
    assert contribution.earned_points == 0
    assert contribution.deduction == 0
    content_category = next(
        category for category in result.categories if category.category == "Content Protection"
    )
    assert content_category.coverage == Decimal("0.000")
    assert content_category.normalized_score is None


def test_multiple_errors_withhold_score_below_coverage_threshold() -> None:
    profile = next(item for item in PROFILES if item.name == "low_coverage_site")
    result = scorer().score(*inputs(profile))
    assert result.coverage == Decimal("0.650")
    assert result.raw_score is None
    assert result.score is None
    assert result.grade is None
    assert result.cap is None
    assert result.withholding_reasons
    assert result.explanation == "Scan incomplete — insufficient coverage for a reliable score."


def test_essential_transport_error_withholds_even_above_minimum_coverage() -> None:
    profile = SyntheticProfile(
        "essential_error",
        {},
        errors=frozenset({"transport.https_available"}),
    )
    result = scorer().score(*inputs(profile))
    assert result.coverage == Decimal("0.900")
    assert result.score is None
    assert "transport.https_available" in result.withholding_reasons[-1]


@pytest.mark.parametrize(
    ("score", "grade"),
    [
        (90, Grade.A),
        (89, Grade.B),
        (80, Grade.B),
        (79, Grade.C),
        (70, Grade.C),
        (69, Grade.D),
        (60, Grade.D),
        (59, Grade.F),
    ],
)
def test_grade_boundaries(score: int, grade: Grade) -> None:
    assert scorer().grade_for_score(score) is grade


def test_transport_cap_reports_raw_final_and_reason() -> None:
    profile = next(item for item in PROFILES if item.name == "transport_broken")
    result = scorer().score(*inputs(profile))
    assert result.raw_score == Decimal("90")
    assert result.score == 59
    assert result.grade is Grade.F
    assert result.cap is not None
    assert result.cap.rule_id == "transport.https_available"
    assert result.cap.maximum_score == 59
    assert "capped at F" in result.cap.reason


def test_same_inputs_are_exactly_deterministic() -> None:
    profile = next(item for item in PROFILES if item.name == "average_site")
    findings, errors = inputs(profile)
    calculator = scorer()
    first = calculator.score(findings, errors)
    second = calculator.score(findings, errors)
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()


def test_scoring_serialization_does_not_copy_finding_evidence() -> None:
    secret = "token=do-not-copy-this"
    result = scorer().score(*inputs(PROFILES[0], evidence_secret=secret))
    serialized = result.model_dump_json()
    assert secret not in serialized
    assert '"scoring_version":"1.0"' in serialized
    assert '"rule_contributions"' in serialized


def _write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "weights.toml"
    path.write_text(content, encoding="utf-8")
    return path


def _base_config_text() -> str:
    return (
        Path(__file__).parents[2]
        / "src"
        / "webguard"
        / "scoring"
        / "weights.toml"
    ).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda text: text.replace(
                'name = "Transport Security"\nweight = "30"',
                'name = "Transport Security"\nweight = "31"',
            ),
            "Category weights must total exactly 100",
        ),
        (
            lambda text: text.replace(
                'id = "hygiene.x_powered_by"\ncategory = "hygiene"',
                'id = "unknown.rule"\ncategory = "hygiene"',
            ),
            "Scoring rule IDs do not match registry",
        ),
        (
            lambda text: text.replace(
                'id = "hygiene.x_powered_by"\ncategory = "hygiene"',
                'id = "hygiene.server_disclosure"\ncategory = "hygiene"',
            ),
            "Duplicate rule IDs",
        ),
        (
            lambda text: text.replace(
                'credits = { PASS = "1", INFO = "0.5", WARNING = "0.25", FAIL = "0" }',
                'credits = { PASS = "1", INFO = "0.5", WARNING = "1.5", FAIL = "0" }',
            ),
            "credit fractions must be between 0 and 1",
        ),
        (
            lambda text: text.replace("minimum_score = 90", "minimum_score = 80"),
            "Grade thresholds must be unique and descending",
        ),
    ],
)
def test_invalid_configuration_fails_clearly(
    tmp_path: Path,
    mutator: Callable[[str], str],
    message: str,
) -> None:
    changed = mutator(_base_config_text())
    config = None
    try:
        config = load_scoring_config(_write_config(tmp_path, changed))
    except ScoringConfigError as error:
        assert message in str(error)
        return
    with pytest.raises(ScoringConfigError, match=message):
        ScoringEngine(default_check_registry(), config)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda text: text.replace('scoring_version = "1.0"\n', ""),
            "scoring_version must be non-empty text",
        ),
        (
            lambda text: text.replace('minimum_coverage = "0.700"', "minimum_coverage = true"),
            "minimum_coverage must be numeric",
        ),
        (
            lambda text: text.replace('minimum_coverage = "0.700"', 'minimum_coverage = "1.1"'),
            "minimum_coverage must be between 0 and 1",
        ),
        (
            lambda text: text.replace("[[categories]]", "[[policy_categories]]"),
            "categories must be an array of tables",
        ),
        (
            lambda text: text.replace('name = "Security Headers"', 'name = "Transport Security"'),
            "Duplicate category names",
        ),
        (
            lambda text: text.replace(
                'name = "Transport Security"\nweight = "30"',
                'name = "Transport Security"\nweight = "0"',
            ),
            "Category weights must be positive",
        ),
        (
            lambda text: text.replace('name = "Transport Security"', 'name = ""'),
            "category.name must be non-empty text",
        ),
        (
            lambda text: text.replace(
                'id = "hygiene.x_powered_by"\ncategory = "hygiene"',
                'id = "hygiene.x_powered_by"\ncategory = "unknown"',
            ),
            "references unknown category",
        ),
        (
            lambda text: text.replace(
                'credits = { PASS = "1", INFO = "1", WARNING = "0.5", FAIL = "0" }',
                'credits = "invalid"',
                1,
            ),
            "credits must be a table",
        ),
        (
            lambda text: text.replace(
                'credits = { PASS = "1", INFO = "1", WARNING = "0.5", FAIL = "0" }',
                'credits = { PASS = "1", INFO = "1", WARN = "0.5", FAIL = "0" }',
                1,
            ),
            "invalid credit status",
        ),
        (
            lambda text: text.replace(
                'credits = { PASS = "1", INFO = "1", WARNING = "0.5", FAIL = "0" }',
                'credits = { PASS = "1", INFO = "1", FAIL = "0" }',
                1,
            ),
            "must configure PASS, INFO, WARNING, and FAIL credits",
        ),
        (
            lambda text: text.replace(
                'credits = { PASS = "1", INFO = "1", WARNING = "0.5", FAIL = "0" }',
                'credits = { PASS = "0.5", INFO = "1", WARNING = "0.5", FAIL = "0" }',
                1,
            ),
            "must give PASS full credit and FAIL zero",
        ),
        (
            lambda text: text.replace(
                'warning_severity_credits = { LOW = "0.5", MEDIUM = "0.25", HIGH = "0" }',
                'warning_severity_credits = "invalid"',
            ),
            "warning_severity_credits must be a table",
        ),
        (
            lambda text: text.replace(
                'warning_severity_credits = { LOW = "0.5", MEDIUM = "0.25", HIGH = "0" }',
                'warning_severity_credits = { UNKNOWN = "0.5" }',
            ),
            "invalid warning severity",
        ),
        (
            lambda text: text.replace(
                'id = "hygiene.x_powered_by"\ncategory = "hygiene"\nweight = "3"',
                'id = "hygiene.x_powered_by"\ncategory = "hygiene"\nweight = "0"',
            ),
            "Rule weights must be positive",
        ),
        (
            lambda text: text.replace(
                'id = "hygiene.x_powered_by"\ncategory = "hygiene"\nweight = "3"',
                'id = "hygiene.x_powered_by"\ncategory = "hygiene"\nweight = "2"',
            ),
            "Rule weights for hygiene total 9, expected 10",
        ),
    ],
)
def test_additional_invalid_rule_and_category_configuration(
    tmp_path: Path,
    mutator: Callable[[str], str],
    message: str,
) -> None:
    with pytest.raises(ScoringConfigError, match=message):
        load_scoring_config(_write_config(tmp_path, mutator(_base_config_text())))


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda text: text.replace('grade = "A"', 'grade = "Z"', 1),
            "Grade band uses an unknown grade",
        ),
        (
            lambda text: text.replace("minimum_score = 90", "minimum_score = true", 1),
            "A.minimum_score must be an integer",
        ),
        (
            lambda text: text.replace(
                '[[grades]]\ngrade = "A"\nminimum_score = 90\n\n'
                '[[grades]]\ngrade = "B"\nminimum_score = 80',
                '[[grades]]\ngrade = "B"\nminimum_score = 90\n\n'
                '[[grades]]\ngrade = "A"\nminimum_score = 80',
            ),
            "Grade bands must be ordered A, B, C, D, F",
        ),
        (
            lambda text: text.replace("minimum_score = 0", "minimum_score = -1", 1),
            "Grade thresholds must span 0 through at most 100",
        ),
        (
            lambda text: text.replace("minimum_score = 90", "minimum_score = 101", 1),
            "Grade thresholds must span 0 through at most 100",
        ),
        (
            lambda text: text.replace(
                'rule_id = "transport.https_available"', 'rule_id = "unknown.rule"', 1
            ),
            "Cap references unknown rule ID",
        ),
        (
            lambda text: text.replace('status = "FAIL"', 'status = "NOPE"', 1),
            "has an invalid status",
        ),
        (
            lambda text: text.replace('status = "FAIL"', 'status = "ERROR"', 1),
            "cannot use ERROR",
        ),
        (
            lambda text: text.replace("maximum_score = 59", "maximum_score = true", 1),
            "maximum_score must be an integer",
        ),
        (
            lambda text: text.replace("maximum_score = 59", "maximum_score = 101", 1),
            "must be between 0 and 100",
        ),
        (
            lambda text: text.replace(
                'rule_id = "transport.tls_validity"',
                'rule_id = "transport.https_available"',
                1,
            ),
            "Duplicate cap triggers",
        ),
        (
            lambda text: text.replace(
                'essential_error_rules = [\n'
                '  "transport.https_available",\n'
                '  "transport.tls_validity",\n'
                '  "transport.tls_hostname",\n'
                "]",
                'essential_error_rules = "transport.https_available"',
            ),
            "essential_error_rules must be an array of rule IDs",
        ),
        (
            lambda text: text.replace(
                '  "transport.tls_validity",', '  "transport.https_available",', 1
            ),
            "Duplicate essential error rule IDs",
        ),
        (
            lambda text: text.replace(
                '  "transport.https_available",', '  "unknown.rule",', 1
            ),
            "Essential error rules are unknown",
        ),
    ],
)
def test_additional_invalid_grade_cap_and_coverage_configuration(
    tmp_path: Path,
    mutator: Callable[[str], str],
    message: str,
) -> None:
    with pytest.raises(ScoringConfigError, match=message):
        load_scoring_config(_write_config(tmp_path, mutator(_base_config_text())))


def test_unreadable_and_malformed_configuration_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ScoringConfigError, match="could not be loaded"):
        load_scoring_config(tmp_path / "missing.toml")
    with pytest.raises(ScoringConfigError, match="could not be loaded"):
        load_scoring_config(_write_config(tmp_path, "not = [valid toml"))


def test_duplicate_and_conflicting_rule_outcomes_fail_closed() -> None:
    findings, errors = inputs(PROFILES[0])
    with pytest.raises(ScoringInputError, match="Duplicate finding"):
        scorer().score((*findings, findings[0]), errors)
    conflict = ScanError(
        kind=ScanErrorKind.CHECK,
        code="check.evaluation_failed",
        message="Synthetic conflict.",
        rule_id=findings[0].id,
    )
    with pytest.raises(ScoringInputError, match="findings and errors"):
        scorer().score(findings, (conflict,))


def test_invalid_score_and_unreconciled_inputs_fail_closed() -> None:
    calculator = scorer()
    with pytest.raises(ValueError, match="between 0 and 100"):
        calculator.grade_for_score(101)

    findings, _ = inputs(PROFILES[0])
    unknown_finding = findings[0].model_copy(update={"id": "unknown.rule"})
    with pytest.raises(ScoringInputError, match="unknown scoring rule ID"):
        calculator.score((unknown_finding,), ())

    error_finding = findings[0].model_copy(
        update={"status": FindingStatus.ERROR, "severity": None}
    )
    with pytest.raises(ScoringInputError, match="ERROR findings"):
        calculator.score((error_finding,), ())

    unknown_error = ScanError(
        kind=ScanErrorKind.CHECK,
        code="check.evaluation_failed",
        message="Synthetic unknown rule error.",
        rule_id="unknown.rule",
    )
    with pytest.raises(ScoringInputError, match="unknown scoring rule ID"):
        calculator.score((), (unknown_error,))

    duplicate_error = ScanError(
        kind=ScanErrorKind.CHECK,
        code="check.evaluation_failed",
        message="Synthetic duplicate rule error.",
        rule_id="content.mixed_content",
    )
    with pytest.raises(ScoringInputError, match="Duplicate error"):
        calculator.score((), (duplicate_error, duplicate_error))


def test_non_rule_error_is_ignored_and_missing_rule_is_explicitly_excluded() -> None:
    findings, _ = inputs(PROFILES[0])
    omitted = "hygiene.x_powered_by"
    network_error = ScanError(
        kind=ScanErrorKind.NETWORK,
        code="network.connection_failed",
        message="Synthetic network error without a rule.",
    )
    result = scorer().score(
        tuple(finding for finding in findings if finding.id != omitted),
        (network_error,),
    )
    exclusion = next(item for item in result.exclusions if item.rule_id == omitted)
    assert exclusion.state.value == "NOT_APPLICABLE"
    assert result.coverage == Decimal("1.000")
    assert result.score == 100
