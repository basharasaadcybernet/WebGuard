from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from webguard.cli.app import ExitCode, create_app
from webguard.domain.enums import ScanErrorKind, ScanState
from webguard.domain.models import ScanError

runner = CliRunner()


def app_for(result):  # type: ignore[no-untyped-def]
    return create_app(lambda request: result)


def test_help_and_version_commands() -> None:
    app = create_app()
    help_result = runner.invoke(app, ["--help"])
    version_result = runner.invoke(app, ["version"])
    assert help_result.exit_code == ExitCode.SUCCESS
    assert "Safe, passive web security posture auditing" in help_result.stdout
    assert "scan" in help_result.stdout
    assert version_result.exit_code == ExitCode.SUCCESS
    assert version_result.stdout.strip() == "CyberNet WebGuard 0.1.0.dev0"


def test_completed_human_scan_is_professional_and_successful(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    result = runner.invoke(app_for(make_scan_result()), ["scan", "https://example.com"])
    assert result.exit_code == ExitCode.SUCCESS
    for expected in (
        "CyberNet WebGuard",
        "Web Security Posture Auditor",
        "Target",
        "Status",
        "COMPLETED",
        "93 / 100",
        "Grade",
        "Severity Summary",
        "Category Summary",
        "Findings",
        "Content-Security-Policy needs improvement",
        "Recommendation",
        "Important",
    ):
        assert expected in result.stdout
    assert result.stderr == ""


def test_invalid_target_returns_two_without_network_or_traceback() -> None:
    result = runner.invoke(create_app(), ["scan", "not-a-url"])
    assert result.exit_code == ExitCode.INVALID_INPUT
    assert "FAILED" in result.stdout
    assert "Operational Errors" in result.stdout
    assert "traceback" not in (result.stdout + result.stderr).lower()


def test_partial_and_failed_scan_exit_codes_and_errors(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    partial = runner.invoke(
        app_for(make_scan_result(state=ScanState.PARTIAL, score_mode="withheld")),
        ["scan", "https://example.com"],
    )
    failed = runner.invoke(
        app_for(make_scan_result(state=ScanState.FAILED, score_mode="withheld")),
        ["scan", "https://example.com"],
    )
    assert partial.exit_code == ExitCode.PARTIAL_SCAN
    assert failed.exit_code == ExitCode.SCAN_FAILURE
    assert "Operational Errors" in partial.stdout
    assert "Operational Errors" in failed.stdout
    assert "Score" in failed.stdout and "Not available" in failed.stdout


def test_target_failure_maps_to_invalid_input(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    failed = make_scan_result(state=ScanState.FAILED, score_mode="withheld")
    target_error = ScanError(
        kind=ScanErrorKind.TARGET,
        code="target.rejected",
        message="The target was rejected by URL safety policy.",
    )
    failed = failed.model_copy(update={"errors": (target_error,)})
    result = runner.invoke(app_for(failed), ["scan", "https://example.com"])
    assert result.exit_code == ExitCode.INVALID_INPUT
    assert "target.rejected" in result.stdout


def test_withheld_and_capped_scores_are_not_recalculated(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    withheld = runner.invoke(
        app_for(make_scan_result(score_mode="withheld")),
        ["scan", "https://example.com"],
    )
    capped = runner.invoke(
        app_for(make_scan_result(score_mode="capped")),
        ["scan", "https://example.com"],
    )
    assert "Not available" in withheld.stdout
    assert "insufficient coverage" in withheld.stdout.lower()
    assert "Score: 0" not in withheld.stdout
    assert "Raw score" in capped.stdout
    assert "92.5" in capped.stdout
    assert "59 / 100" in capped.stdout
    assert "TLS certificate trust failed" in capped.stdout


def test_json_stdout_contains_only_valid_json(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    result = runner.invoke(
        app_for(make_scan_result()),
        ["scan", "https://example.com", "--format", "json"],
    )
    assert result.exit_code == ExitCode.SUCCESS
    document = json.loads(result.stdout)
    assert document["report_schema_version"] == "1.0"
    assert document["completion_state"] == "COMPLETED"
    assert "CyberNet WebGuard" not in result.stdout
    assert result.stderr == ""


def test_json_output_file_is_new_and_stdout_stays_empty(make_scan_result, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    destination = tmp_path / "result.json"
    result = runner.invoke(
        app_for(make_scan_result()),
        [
            "scan",
            "https://example.com",
            "--format",
            "json",
            "--output",
            str(destination),
        ],
    )
    assert result.exit_code == ExitCode.SUCCESS
    assert result.stdout == ""
    assert "JSON report written" in result.stderr
    assert json.loads(destination.read_text(encoding="utf-8"))["score"]["score"] == 93


def test_html_report_is_created_alongside_human_output(make_scan_result, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    destination = tmp_path / "report.html"
    result = runner.invoke(
        app_for(make_scan_result()),
        ["scan", "https://example.com", "--report", str(destination)],
    )
    assert result.exit_code == ExitCode.SUCCESS
    assert destination.exists()
    assert "HTML report written" in result.stdout
    assert "Web Security Posture Assessment" in destination.read_text(encoding="utf-8")


def test_json_and_html_can_be_generated_together_without_corrupting_stdout(
    make_scan_result, tmp_path: Path  # type: ignore[no-untyped-def]
) -> None:
    destination = tmp_path / "report.html"
    result = runner.invoke(
        app_for(make_scan_result()),
        [
            "scan",
            "https://example.com",
            "--format",
            "json",
            "--report",
            str(destination),
        ],
    )
    assert result.exit_code == ExitCode.SUCCESS
    assert json.loads(result.stdout)["report_schema_version"] == "1.0"
    assert "HTML report written" in result.stderr
    assert destination.exists()


def test_cli_rejects_incoherent_or_existing_output_paths(make_scan_result, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    existing = tmp_path / "result.json"
    existing.write_text("keep", encoding="utf-8")
    wrong_mode = runner.invoke(
        app_for(make_scan_result()),
        ["scan", "https://example.com", "--output", str(tmp_path / "new.json")],
    )
    overwrite = runner.invoke(
        app_for(make_scan_result()),
        [
            "scan",
            "https://example.com",
            "--format",
            "json",
            "--output",
            str(existing),
        ],
    )
    assert wrong_mode.exit_code == ExitCode.INVALID_INPUT
    assert "requires --format json" in wrong_mode.stderr
    assert overwrite.exit_code == ExitCode.INVALID_INPUT
    assert "will not overwrite" in overwrite.stderr
    assert existing.read_text(encoding="utf-8") == "keep"


def test_cli_internal_error_is_safe_and_deterministic() -> None:
    def crash(request):  # type: ignore[no-untyped-def]
        raise RuntimeError("secret stack detail")

    result = runner.invoke(create_app(crash), ["scan", "https://example.com"])
    assert result.exit_code == ExitCode.INTERNAL_ERROR
    assert "internal error" in result.stderr.lower()
    assert "secret stack detail" not in (result.stdout + result.stderr)
    assert "traceback" not in (result.stdout + result.stderr).lower()


def test_human_output_does_not_leak_internal_target_query(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    result = runner.invoke(app_for(make_scan_result()), ["scan", "https://example.com"])
    assert "private-value" not in result.stdout
    assert "[redacted]" in result.stdout
