"""Self-contained, injection-safe HTML rendering for WebGuard reports."""

# ruff: noqa: E501 -- HTML and CSS literals remain readable as report fragments.

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from decimal import Decimal
from html import escape
from urllib.parse import urlsplit

from webguard.domain.enums import RuleEvaluationState
from webguard.domain.models import Finding, RuleContribution, ScoreBreakdown
from webguard.reporting.models import ReportDocument

_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'none'; "
    "connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
)
_HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


@dataclass(frozen=True, slots=True)
class HtmlReportTheme:
    """Small safe color palette that can be replaced without changing report data."""

    ink: str = "#17202a"
    muted: str = "#667085"
    line: str = "#d8dee8"
    paper: str = "#ffffff"
    soft: str = "#f5f7fa"
    accent: str = "#245c73"
    high: str = "#a82b2b"
    medium: str = "#a45d0a"
    low: str = "#756600"
    info: str = "#315f86"

    def __post_init__(self) -> None:
        if any(not _HEX_COLOR.fullmatch(getattr(self, item.name)) for item in fields(self)):
            raise ValueError("HTML report theme colors must use six-digit hexadecimal values")


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _number(value: Decimal | int) -> str:
    rendered = format(value, "f") if isinstance(value, Decimal) else str(value)
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def _percentage(value: Decimal) -> str:
    return f"{_number(value * 100)}%"


def _safe_link(url: object, label: str | None = None) -> str:
    rendered = str(url)
    try:
        if urlsplit(rendered).scheme.lower() not in {"http", "https"}:
            return _e(label or "Invalid reference URL")
    except ValueError:
        return _e(label or "Invalid reference URL")
    return f'<a href="{_e(rendered)}" rel="noreferrer noopener">{_e(label or rendered)}</a>'


class HtmlReportRenderer:
    """Render a deterministic offline report with no executable JavaScript."""

    def __init__(self, theme: HtmlReportTheme | None = None) -> None:
        self._theme = theme or HtmlReportTheme()

    def render(self, report: ReportDocument) -> str:
        target = report.target.display_url if report.target is not None else "Unavailable"
        score = report.score
        return "".join(
            (
                '<!doctype html>\n<html lang="en"><head>',
                '<meta charset="utf-8">',
                '<meta name="viewport" content="width=device-width,initial-scale=1">',
                f'<meta http-equiv="Content-Security-Policy" content="{_e(_CSP)}">',
                f"<title>WebGuard Security Posture Report — {_e(target)}</title>",
                f"<style>{self._styles()}</style></head><body>",
                '<main class="report">',
                self._cover(report, target),
                self._posture_summary(report, score),
                self._severity_summary(report),
                self._category_summary(score),
                self._findings_summary(report),
                self._finding_details(report, score),
                self._operational_errors(report),
                self._methodology(report),
                self._references(report),
                f'<section class="disclaimer"><h2>Important limitation</h2><p>{_e(report.disclaimer)}</p></section>',
                "</main></body></html>\n",
            )
        )

    @staticmethod
    def _cover(report: ReportDocument, target: str) -> str:
        metadata = report.scan_metadata
        return (
            '<header class="cover">'
            '<p class="eyebrow">CyberNet WebGuard</p>'
            "<h1>Web Security Posture Assessment</h1>"
            '<p class="lede">A bounded, passive review of externally visible controls.</p>'
            '<dl class="metadata">'
            f"<div><dt>Target</dt><dd>{_e(target)}</dd></div>"
            f"<div><dt>State</dt><dd>{_e(report.completion_state.value)}</dd></div>"
            f"<div><dt>Started</dt><dd>{_e(metadata.started_at.isoformat())}</dd></div>"
            f"<div><dt>Finished</dt><dd>{_e(metadata.finished_at.isoformat())}</dd></div>"
            f"<div><dt>Duration</dt><dd>{metadata.duration_ms} ms</dd></div>"
            f"<div><dt>Scan ID</dt><dd>{_e(metadata.scan_id)}</dd></div>"
            f"<div><dt>WebGuard</dt><dd>{_e(report.webguard_version)}</dd></div>"
            f"<div><dt>Report schema</dt><dd>{_e(report.report_schema_version)}</dd></div>"
            f"<div><dt>Ruleset</dt><dd>{_e(metadata.ruleset_version)}</dd></div>"
            "</dl></header>"
        )

    @staticmethod
    def _posture_summary(report: ReportDocument, score: ScoreBreakdown | None) -> str:
        if score is None:
            score_body = (
                '<div class="metric"><span>Score</span><strong>Not available</strong></div>'
                '<p class="note">No scoring breakdown was produced for this scan.</p>'
            )
        elif score.score is None:
            reasons = "".join(f"<li>{_e(reason)}</li>" for reason in score.withholding_reasons)
            score_body = (
                '<div class="metric"><span>Score</span><strong>Not available</strong></div>'
                f'<div class="metric"><span>Coverage</span><strong>{_percentage(score.coverage)}</strong></div>'
                f'<div class="notice"><b>{_e(score.explanation)}</b><ul>{reasons}</ul></div>'
            )
        else:
            grade = score.grade.value if score.grade is not None else "N/A"
            raw = (
                f'<div class="metric"><span>Raw score</span><strong>{_number(score.raw_score or Decimal(0))}</strong></div>'
                if score.cap is not None
                else ""
            )
            cap = (
                f'<div class="notice"><b>Score cap applied</b><p>{_e(score.cap.reason)}</p></div>'
                if score.cap is not None
                else ""
            )
            score_body = (
                raw
                + f'<div class="metric"><span>Final score</span><strong>{score.score} / 100</strong></div>'
                + f'<div class="metric"><span>Grade</span><strong>{_e(grade)}</strong></div>'
                + f'<div class="metric"><span>Coverage</span><strong>{_percentage(score.coverage)}</strong></div>'
                + cap
            )
        return (
            '<section><div class="section-heading"><h2>Posture summary</h2>'
            f'<span class="state">{_e(report.completion_state.value)}</span></div>'
            f'<div class="metrics">{score_body}</div></section>'
        )

    @staticmethod
    def _severity_summary(report: ReportDocument) -> str:
        cards = "".join(
            '<div class="severity-card">'
            f'<span class="badge sev-{item.severity.value.lower()}">{_e(item.severity.value)}</span>'
            f"<strong>{item.count}</strong></div>"
            for item in report.severity_summary
        )
        return (
            f'<section><h2>Severity summary</h2><div class="severity-grid">{cards}</div></section>'
        )

    @staticmethod
    def _category_summary(score: ScoreBreakdown | None) -> str:
        if score is None:
            return '<section><h2>Category breakdown</h2><p class="empty">Unavailable.</p></section>'
        rows = "".join(
            "<tr>"
            f"<td>{_e(category.category)}</td>"
            f"<td>{_number(category.earned_normalized_contribution)} / {_number(category.configured_weight)}</td>"
            f"<td>{_number(category.applicable_points)}</td>"
            f"<td>{_number(category.evaluated_points)}</td>"
            f"<td>{_percentage(category.coverage) if category.coverage is not None else 'N/A'}</td>"
            "</tr>"
            for category in score.categories
        )
        return (
            '<section><h2>Category breakdown</h2><div class="table-wrap"><table>'
            "<thead><tr><th>Category</th><th>Contribution</th><th>Applicable</th>"
            f"<th>Evaluated</th><th>Coverage</th></tr></thead><tbody>{rows}</tbody></table></div></section>"
        )

    @staticmethod
    def _findings_summary(report: ReportDocument) -> str:
        if not report.findings:
            return (
                '<section><h2>Findings summary</h2><p class="empty">'
                "No non-pass outcomes were reported by the evaluated controls.</p></section>"
            )
        rows = "".join(
            "<tr>"
            f'<td><span class="badge sev-{(finding.severity.value if finding.severity else "INFO").lower()}">'
            f"{_e(finding.severity.value if finding.severity else 'INFO')}</span></td>"
            f"<td>{_e(finding.title)}<small>{_e(finding.id)}</small></td>"
            f"<td>{_e(finding.category)}</td><td>{_e(finding.status.value)}</td></tr>"
            for finding in report.findings
        )
        return (
            '<section><h2>Findings summary</h2><div class="table-wrap"><table>'
            f"<thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table></div></section>"
        )

    def _finding_details(
        self,
        report: ReportDocument,
        score: ScoreBreakdown | None,
    ) -> str:
        if not report.findings:
            return ""
        contributions = (
            {item.rule_id: item for item in score.rule_contributions} if score is not None else {}
        )
        cards = "".join(
            self._finding_card(finding, contributions.get(finding.id))
            for finding in report.findings
        )
        return (
            f'<section><h2>Detailed findings</h2><div class="finding-list">{cards}</div></section>'
        )

    @staticmethod
    def _finding_card(finding: Finding, contribution: RuleContribution | None) -> str:
        severity = finding.severity.value if finding.severity is not None else "INFO"
        evidence = "".join(
            "<div>"
            f"<dt>{_e(item.label)}</dt><dd>{_e(item.value)}"
            + (f"<br>{_safe_link(item.source_url, 'Evidence source')}" if item.source_url else "")
            + "</dd></div>"
            for item in finding.evidence
        )
        recommendation = (
            f"<h4>Recommendation</h4><p>{_e(finding.recommendation)}</p>"
            if finding.recommendation
            else '<h4>Recommendation</h4><p class="empty">No recommendation supplied.</p>'
        )
        references = "".join(
            f"<li>{_safe_link(reference)}</li>" for reference in finding.references
        )
        scoring = HtmlReportRenderer._scoring_impact(contribution)
        return (
            '<article class="finding">'
            '<div class="finding-heading">'
            f'<div><p class="rule">{_e(finding.id)}</p><h3>{_e(finding.title)}</h3></div>'
            f'<span class="badge sev-{severity.lower()}">{_e(severity)}</span></div>'
            '<dl class="inline-meta">'
            f"<div><dt>Status</dt><dd>{_e(finding.status.value)}</dd></div>"
            f"<div><dt>Category</dt><dd>{_e(finding.category)}</dd></div></dl>"
            f"<h4>Description</h4><p>{_e(finding.description)}</p>"
            f'<h4>Evidence</h4><dl class="evidence">{evidence or "<div><dd>No evidence supplied.</dd></div>"}</dl>'
            f"{recommendation}{scoring}"
            f'<h4>References</h4><ul class="references">{references or "<li>None supplied.</li>"}</ul>'
            "</article>"
        )

    @staticmethod
    def _scoring_impact(contribution: RuleContribution | None) -> str:
        if contribution is None:
            return ""
        if contribution.state in {
            RuleEvaluationState.NOT_EVALUATED,
            RuleEvaluationState.NOT_APPLICABLE,
        }:
            return (
                '<h4>Scoring</h4><p class="note">Excluded: '
                f"{_e(contribution.exclusion_reason or contribution.reason)}</p>"
            )
        return (
            '<h4>Scoring impact</h4><dl class="inline-meta">'
            f"<div><dt>Available</dt><dd>{_number(contribution.available_points)}</dd></div>"
            f"<div><dt>Earned</dt><dd>{_number(contribution.earned_points)}</dd></div>"
            f"<div><dt>Deduction</dt><dd>{_number(contribution.deduction)}</dd></div></dl>"
        )

    @staticmethod
    def _operational_errors(report: ReportDocument) -> str:
        if not report.operational_errors:
            body = '<p class="empty">No operational errors were recorded.</p>'
        else:
            body = (
                '<div class="error-list">'
                + "".join(
                    '<article class="error"><b>'
                    f"{_e(error.kind.value)} — {_e(error.code)}</b><p>{_e(error.message)}</p>"
                    + (f"<small>Rule: {_e(error.rule_id)}</small>" if error.rule_id else "")
                    + "</article>"
                    for error in report.operational_errors
                )
                + "</div>"
            )
        return f"<section><h2>Operational errors and limitations</h2>{body}</section>"

    @staticmethod
    def _methodology(report: ReportDocument) -> str:
        methodology = "".join(f"<li>{_e(item)}</li>" for item in report.methodology)
        limitations = "".join(f"<li>{_e(item)}</li>" for item in report.limitations)
        return (
            "<section><h2>Methodology and scope</h2>"
            f"<h3>What WebGuard tested</h3><ul>{methodology}</ul>"
            f"<h3>Limitations</h3><ul>{limitations}</ul></section>"
        )

    @staticmethod
    def _references(report: ReportDocument) -> str:
        unique = sorted(
            {str(reference) for finding in report.findings for reference in finding.references}
        )
        body = "".join(f"<li>{_safe_link(reference)}</li>" for reference in unique)
        return (
            "<section><h2>Technical references</h2>"
            f'<ul class="references">{body or "<li>No finding references supplied.</li>"}</ul></section>'
        )

    def _styles(self) -> str:
        theme = self._theme
        palette = (
            ":root{color-scheme:light;"
            f"--ink:{theme.ink};--muted:{theme.muted};--line:{theme.line};"
            f"--paper:{theme.paper};--soft:{theme.soft};--accent:{theme.accent};"
            f"--high:{theme.high};--medium:{theme.medium};--low:{theme.low};"
            f"--info:{theme.info}" + "}"
        )
        return palette + """
*{box-sizing:border-box}body{margin:0;background:#eef1f5;color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}.report{width:min(1080px,calc(100% - 32px));margin:32px auto}.cover,section{background:var(--paper);border:1px solid var(--line);border-radius:14px;padding:28px;margin:0 0 20px;box-shadow:0 5px 20px rgba(20,35,50,.05)}.cover{border-top:5px solid var(--accent)}h1{font-size:2rem;margin:.1rem 0}h2{font-size:1.3rem;margin:0 0 18px}h3{font-size:1.05rem;margin:.2rem 0}h4{font-size:.82rem;letter-spacing:.04em;text-transform:uppercase;margin:20px 0 6px}.eyebrow,.rule{color:var(--accent);font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin:0}.lede,.note,.empty,small{color:var(--muted)}.metadata,.inline-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:24px 0 0}.metadata div,.inline-meta div{background:var(--soft);border-radius:9px;padding:10px 12px}.metadata dt,.inline-meta dt,.evidence dt{color:var(--muted);font-size:.78rem;text-transform:uppercase}.metadata dd,.inline-meta dd,.evidence dd{margin:2px 0 0;overflow-wrap:anywhere}.section-heading,.finding-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.state,.badge{border-radius:999px;font-size:.76rem;font-weight:800;letter-spacing:.04em;padding:4px 9px}.state{background:#e7f0f4;color:var(--accent)}.metrics{display:flex;flex-wrap:wrap;gap:12px}.metric{min-width:150px;background:var(--soft);border-radius:10px;padding:15px}.metric span{display:block;color:var(--muted);font-size:.82rem}.metric strong{font-size:1.35rem}.notice{width:100%;border-left:4px solid var(--medium);background:#fff7eb;padding:12px 15px}.severity-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.severity-card{display:flex;justify-content:space-between;align-items:center;background:var(--soft);border-radius:10px;padding:14px}.sev-high{background:#fce8e8;color:var(--high)}.sev-medium{background:#fff0db;color:var(--medium)}.sev-low{background:#fbf5cc;color:var(--low)}.sev-info{background:#e7f0fa;color:var(--info)}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:11px 9px;vertical-align:top}th{color:var(--muted);font-size:.78rem;text-transform:uppercase}td small{display:block}.finding-list,.error-list{display:grid;gap:14px}.finding,.error{border:1px solid var(--line);border-radius:11px;padding:20px;break-inside:avoid}.finding p,.error p{overflow-wrap:anywhere}.evidence{display:grid;gap:8px}.evidence div{background:var(--soft);border-radius:8px;padding:10px 12px}.references{overflow-wrap:anywhere;padding-left:20px}a{color:var(--accent)}.disclaimer{border-left:5px solid var(--accent)}
@media(max-width:700px){.report{width:min(100% - 18px,1080px);margin:9px auto}.cover,section{padding:19px}.severity-grid{grid-template-columns:repeat(2,1fr)}h1{font-size:1.55rem}}
@media print{body{background:#fff}.report{width:100%;margin:0}.cover,section{box-shadow:none;border-color:#bbb;page-break-inside:auto}.finding{page-break-inside:avoid}a{color:inherit;text-decoration:none}}
"""
