from __future__ import annotations

import json
from pathlib import Path

import pytest

from webguard.domain.enums import ScanState
from webguard.reporting import (
    HtmlReportRenderer,
    HtmlReportTheme,
    JsonReportRenderer,
    ReportBuilder,
    ReportWriteError,
    write_new_report,
)


def test_report_builder_uses_public_scan_contract_and_stable_schema(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    result = make_scan_result()
    report = ReportBuilder().build(result)
    assert report.report_schema_version == "1.0"
    assert report.webguard_version == result.metadata.webguard_version
    assert report.completion_state is ScanState.COMPLETED
    assert report.target == result.target
    assert [item.severity.value for item in report.severity_summary] == [
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    ]
    assert [item.count for item in report.severity_summary] == [0, 1, 0, 0]
    assert len(report.findings) == 1


def test_json_is_deterministic_versioned_and_automation_ready(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    report = ReportBuilder().build(make_scan_result())
    renderer = JsonReportRenderer()
    first = renderer.render(report)
    second = renderer.render(report)
    assert first == second
    data = json.loads(first)
    assert data["report_schema_version"] == "1.0"
    assert data["webguard_version"] == "0.1.0"
    assert data["completion_state"] == "COMPLETED"
    assert data["scan_metadata"]["ruleset_version"] == "0.1"
    assert data["score"]["scoring_version"] == "1.0"
    assert data["score"]["score"] == 93
    assert data["findings"][0]["id"] == "headers.content_security_policy"
    assert data["operational_errors"] == []


def test_json_excludes_internal_network_and_sensitive_target_data(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    payload = JsonReportRenderer().render(ReportBuilder().build(make_scan_result()))
    assert "private-value" not in payload
    assert "destination_ip" not in payload
    assert "pinned" not in payload.lower()
    assert "response_bytes" not in payload
    assert "raw_body" not in payload
    assert "traceback" not in payload.lower()
    assert "[redacted]" in payload


def test_json_keeps_operational_errors_separate_from_findings(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    report = ReportBuilder().build(
        make_scan_result(state=ScanState.PARTIAL, score_mode="withheld")
    )
    data = json.loads(JsonReportRenderer().render(report))
    assert data["completion_state"] == "PARTIAL"
    assert data["findings"][0]["status"] == "WARNING"
    assert data["operational_errors"][0]["kind"] == "NETWORK"
    assert data["operational_errors"][0]["code"] == "network.endpoint_unavailable"


@pytest.mark.parametrize(
    ("score_mode", "expected_score", "expected_grade"),
    [("capped", 59, "F"), ("withheld", None, None)],
)
def test_json_preserves_capped_and_withheld_score_semantics(
    make_scan_result,  # type: ignore[no-untyped-def]
    score_mode: str,
    expected_score: int | None,
    expected_grade: str | None,
) -> None:
    data = json.loads(
        JsonReportRenderer().render(ReportBuilder().build(make_scan_result(score_mode=score_mode)))
    )
    assert data["score"]["score"] == expected_score
    assert data["score"]["grade"] == expected_grade
    if score_mode == "capped":
        assert data["score"]["raw_score"] == "92.5"
        assert data["score"]["cap"]["reason"]
    else:
        assert data["score"]["withholding_reasons"]


def test_html_contains_complete_professional_report_sections(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    html = HtmlReportRenderer().render(ReportBuilder().build(make_scan_result()))
    for expected in (
        "Web Security Posture Assessment",
        "Posture summary",
        "Severity summary",
        "Category breakdown",
        "Findings summary",
        "Detailed findings",
        "Operational errors and limitations",
        "Methodology and scope",
        "Technical references",
        "Important limitation",
        "Content-Security-Policy needs improvement",
        "Available",
        "Earned",
        "Deduction",
        "developer.mozilla.org",
    ):
        assert expected in html
    assert '<meta http-equiv="Content-Security-Policy"' in html
    assert "script-src &#x27;none&#x27;" in html
    assert "This score reflects only the security controls tested by WebGuard" in html


def test_html_is_deterministic_offline_and_print_friendly(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    report = ReportBuilder().build(make_scan_result())
    renderer = HtmlReportRenderer()
    assert renderer.render(report) == renderer.render(report)
    html = renderer.render(report)
    assert "@media print" in html
    assert "<script" not in html.lower()
    assert "<link" not in html.lower()
    assert "cdn" not in html.lower()
    assert "fetch(" not in html.lower()


def test_html_palette_is_safely_replaceable_for_future_rebranding(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    report = ReportBuilder().build(make_scan_result())
    html = HtmlReportRenderer(HtmlReportTheme(accent="#123456")).render(report)
    assert "--accent:#123456" in html
    with pytest.raises(ValueError, match="six-digit hexadecimal"):
        HtmlReportTheme(accent="red;}</style><script>alert(1)</script>")


@pytest.mark.parametrize("state", [ScanState.PARTIAL, ScanState.FAILED])
def test_html_distinguishes_operational_errors_from_findings(
    make_scan_result, state: ScanState  # type: ignore[no-untyped-def]
) -> None:
    html = HtmlReportRenderer().render(
        ReportBuilder().build(make_scan_result(state=state, score_mode="withheld"))
    )
    assert state.value in html
    assert "NETWORK — network.endpoint_unavailable" in html
    assert "Score</span><strong>Not available" in html


def test_html_displays_raw_final_score_and_cap_reason(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    html = HtmlReportRenderer().render(
        ReportBuilder().build(make_scan_result(score_mode="capped"))
    )
    assert "Raw score" in html
    assert "92.5" in html
    assert "59 / 100" in html
    assert "Score cap applied" in html
    assert "TLS certificate trust failed" in html


def test_report_file_creation_and_no_overwrite_policy(make_scan_result, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    html = HtmlReportRenderer().render(ReportBuilder().build(make_scan_result()))
    destination = tmp_path / "report.html"
    assert write_new_report(destination, html, suffix=".html") == destination
    assert destination.read_text(encoding="utf-8") == html
    with pytest.raises(ReportWriteError, match="will not overwrite"):
        write_new_report(destination, html, suffix=".html")


def test_report_file_rejects_wrong_extension_and_missing_parent(tmp_path: Path) -> None:
    with pytest.raises(ReportWriteError, match=r"\.html extension"):
        write_new_report(tmp_path / "report.txt", "content", suffix=".html")
    with pytest.raises(ReportWriteError, match="parent directory"):
        write_new_report(tmp_path / "missing" / "report.html", "content", suffix=".html")


def test_report_file_wraps_permission_failure(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    def denied(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise PermissionError

    monkeypatch.setattr(Path, "open", denied)
    with pytest.raises(ReportWriteError, match="could not write"):
        write_new_report(tmp_path / "report.html", "content", suffix=".html")
