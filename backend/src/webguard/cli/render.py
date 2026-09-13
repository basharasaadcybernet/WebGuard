"""Restrained Rich rendering for interactive WebGuard scans."""

from __future__ import annotations

from decimal import Decimal

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from webguard.domain.models import Finding, RuleContribution
from webguard.reporting.models import ReportDocument

_SEVERITY_STYLE = {
    "HIGH": "bold red",
    "MEDIUM": "bold dark_orange",
    "LOW": "bold yellow",
    "INFO": "bold blue",
}


def _number(value: Decimal) -> str:
    rendered = format(value, "f")
    return rendered.rstrip("0").rstrip(".") if "." in rendered else rendered


def _bounded(value: object, maximum: int = 320) -> str:
    rendered = str(value)
    return rendered if len(rendered) <= maximum else f"{rendered[: maximum - 1]}…"


class TerminalRenderer:
    """Present report data without changing any scan or score semantics."""

    def render(self, report: ReportDocument, console: Console) -> None:
        console.print(Text("CyberNet WebGuard", style="bold cyan"))
        console.print(Text("Web Security Posture Auditor", style="dim"))
        console.print()
        self._summary(report, console)
        self._severity(report, console)
        self._categories(report, console)
        self._findings(report, console)
        self._errors(report, console)
        console.print(
            Panel(
                Text(report.disclaimer),
                title="Important",
                border_style="cyan",
                padding=(0, 1),
            )
        )

    @staticmethod
    def _summary(report: ReportDocument, console: Console) -> None:
        target = report.target.display_url if report.target is not None else "Unavailable"
        table = Table.grid(padding=(0, 2))
        table.add_column(style="bold")
        table.add_column()
        table.add_row("Target", Text(target))
        table.add_row("Status", report.completion_state.value)
        score = report.score
        if score is None or score.score is None:
            table.add_row("Score", "Not available")
            if score is not None:
                table.add_row("Coverage", f"{_number(score.coverage * 100)}%")
                table.add_row("Reason", Text(score.explanation))
                for reason in score.withholding_reasons:
                    table.add_row("", Text(f"- {reason}", style="dim"))
        else:
            grade = score.grade.value if score.grade is not None else "N/A"
            if score.cap is not None and score.raw_score is not None:
                table.add_row("Raw score", _number(score.raw_score))
            table.add_row("Score", f"{score.score} / 100")
            table.add_row("Grade", grade)
            table.add_row("Coverage", f"{_number(score.coverage * 100)}%")
            if score.cap is not None:
                table.add_row("Cap reason", Text(score.cap.reason))
        console.print(Panel(table, border_style="cyan", padding=(0, 1)))

    @staticmethod
    def _severity(report: ReportDocument, console: Console) -> None:
        table = Table(title="Severity Summary", show_header=False, box=None, padding=(0, 3))
        table.add_column()
        table.add_column(justify="right")
        for item in report.severity_summary:
            table.add_row(
                Text(item.severity.value, style=_SEVERITY_STYLE[item.severity.value]),
                str(item.count),
            )
        console.print(table)

    @staticmethod
    def _categories(report: ReportDocument, console: Console) -> None:
        if report.score is None:
            return
        table = Table(title="Category Summary", header_style="bold", show_lines=False)
        table.add_column("Category")
        table.add_column("Contribution", justify="right")
        table.add_column("Coverage", justify="right")
        for category in report.score.categories:
            coverage = (
                f"{_number(category.coverage * 100)}%" if category.coverage is not None else "N/A"
            )
            table.add_row(
                Text(category.category),
                f"{_number(category.earned_normalized_contribution)} / "
                f"{_number(category.configured_weight)}",
                coverage,
            )
        console.print(table)

    def _findings(self, report: ReportDocument, console: Console) -> None:
        console.print(Text("Findings", style="bold"))
        if not report.findings:
            console.print(Text("No non-pass outcomes were reported.", style="dim"))
            console.print()
            return
        contributions = (
            {item.rule_id: item for item in report.score.rule_contributions}
            if report.score is not None
            else {}
        )
        for finding in report.findings:
            console.print(self._finding_panel(finding, contributions.get(finding.id)))

    @staticmethod
    def _finding_panel(
        finding: Finding,
        contribution: RuleContribution | None,
    ) -> Panel:
        severity = finding.severity.value if finding.severity is not None else "INFO"
        lines: list[Text] = [
            Text.assemble(("Rule: ", "bold"), finding.id),
            Text.assemble(("Status: ", "bold"), finding.status.value),
            Text.assemble(("Category: ", "bold"), finding.category),
            Text(""),
            Text(_bounded(finding.description)),
        ]
        lines.append(Text("Evidence", style="bold"))
        if finding.evidence:
            for item in finding.evidence[:3]:
                lines.append(Text(f"- {item.label}: {_bounded(item.value)}"))
        else:
            lines.append(Text("No evidence supplied.", style="dim"))
        lines.append(Text("Recommendation", style="bold"))
        recommendation = Text(_bounded(finding.recommendation or "No recommendation supplied."))
        if finding.recommendation is None:
            recommendation.stylize("dim")
        lines.append(recommendation)
        if contribution is not None and contribution.available_points:
            lines.append(
                Text(
                    "Scoring: "
                    f"{_number(contribution.earned_points)} / "
                    f"{_number(contribution.available_points)}; "
                    f"deduction {_number(contribution.deduction)}",
                    style="dim",
                )
            )
        if finding.references:
            lines.append(Text(f"References: {len(finding.references)}", style="dim"))
        return Panel(
            Group(*lines),
            title=Text.assemble(
                (f"[{severity}] ", _SEVERITY_STYLE[severity]),
                finding.title,
            ),
            border_style="dim",
            padding=(0, 1),
        )

    @staticmethod
    def _errors(report: ReportDocument, console: Console) -> None:
        if not report.operational_errors:
            return
        table = Table(title="Operational Errors", header_style="bold red")
        table.add_column("Kind")
        table.add_column("Code")
        table.add_column("Rule")
        table.add_column("Message")
        for error in report.operational_errors:
            table.add_row(
                error.kind.value,
                error.code,
                error.rule_id or "—",
                Text(_bounded(error.message)),
            )
        console.print(table)
