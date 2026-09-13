"""Typer entry point for local WebGuard scans and reports."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.text import Text

from webguard import __version__
from webguard.cli.render import TerminalRenderer
from webguard.domain.enums import ScanErrorKind, ScanState
from webguard.domain.models import ScanRequest, ScanResult
from webguard.reporting import (
    HtmlReportRenderer,
    JsonReportRenderer,
    ReportBuilder,
    ReportWriteError,
    validate_new_report_path,
    write_new_report,
)
from webguard.scanner import ScanEngine


class ExitCode(IntEnum):
    SUCCESS = 0
    INVALID_INPUT = 2
    SCAN_FAILURE = 3
    PARTIAL_SCAN = 4
    INTERNAL_ERROR = 5


class OutputFormat(StrEnum):
    HUMAN = "human"
    JSON = "json"


ScanService = Callable[[ScanRequest], ScanResult]


def _default_scan_service(request: ScanRequest) -> ScanResult:
    return asyncio.run(ScanEngine().scan(request))


def exit_code_for(result: ScanResult) -> ExitCode:
    """Map software execution state to a stable process exit code."""
    if result.metadata.state is ScanState.COMPLETED:
        return ExitCode.SUCCESS
    if result.metadata.state is ScanState.PARTIAL:
        return ExitCode.PARTIAL_SCAN
    if any(error.kind is ScanErrorKind.TARGET for error in result.errors):
        return ExitCode.INVALID_INPUT
    return ExitCode.SCAN_FAILURE


def create_app(scan_service: ScanService | None = None) -> typer.Typer:
    """Create the small CLI application, allowing deterministic test injection."""
    runner = scan_service or _default_scan_service
    application = typer.Typer(
        name="webguard",
        help="Safe, passive web security posture auditing.",
        no_args_is_help=True,
        add_completion=False,
        pretty_exceptions_enable=False,
        rich_markup_mode=None,
    )

    @application.command()
    def version() -> None:
        """Show the installed WebGuard software version."""
        typer.echo(f"CyberNet WebGuard {__version__}")

    @application.command()
    def scan(
        target: Annotated[str, typer.Argument(help="Absolute HTTP or HTTPS target URL.")],
        output_format: Annotated[
            OutputFormat,
            typer.Option("--format", help="Terminal or structured JSON output."),
        ] = OutputFormat.HUMAN,
        report: Annotated[
            Path | None,
            typer.Option("--report", help="Create a new self-contained .html report."),
        ] = None,
        output: Annotated[
            Path | None,
            typer.Option("--output", help="Write JSON to a new .json file instead of stdout."),
        ] = None,
    ) -> None:
        """Run the frozen passive ruleset against one target."""
        if output is not None and output_format is not OutputFormat.JSON:
            _error("--output requires --format json.")
            raise typer.Exit(ExitCode.INVALID_INPUT)
        try:
            report_path = (
                validate_new_report_path(report, suffix=".html") if report is not None else None
            )
            output_path = (
                validate_new_report_path(output, suffix=".json") if output is not None else None
            )
            request = ScanRequest(url=target)
        except (ReportWriteError, ValidationError) as exc:
            _error(_public_input_error(exc))
            raise typer.Exit(ExitCode.INVALID_INPUT) from None

        try:
            result = runner(request)
            document = ReportBuilder().build(result)
            json_content = JsonReportRenderer().render(document)
            html_content = (
                HtmlReportRenderer().render(document) if report_path is not None else None
            )
            if report_path is not None and html_content is not None:
                write_new_report(report_path, html_content, suffix=".html")
            if output_path is not None:
                write_new_report(output_path, json_content, suffix=".json")
        except ReportWriteError as exc:
            _error(str(exc))
            raise typer.Exit(ExitCode.INVALID_INPUT) from None
        except Exception:
            _error("WebGuard encountered an internal error and could not complete the command.")
            raise typer.Exit(ExitCode.INTERNAL_ERROR) from None

        if output_format is OutputFormat.JSON:
            if output_path is None:
                typer.echo(json_content, nl=False)
            else:
                typer.echo(f"JSON report written to {output_path}", err=True)
            if report_path is not None:
                typer.echo(f"HTML report written to {report_path}", err=True)
        else:
            console = Console(file=sys.stdout, markup=False, highlight=False)
            TerminalRenderer().render(document, console)
            if report_path is not None:
                console.print(Text(f"HTML report written to {report_path}", style="dim"))
        raise typer.Exit(exit_code_for(result))

    return application


def _public_input_error(error: Exception) -> str:
    if isinstance(error, ReportWriteError):
        return str(error)
    return "The target URL is invalid. Provide an absolute HTTP or HTTPS URL."


def _error(message: str) -> None:
    typer.echo(f"Error: {message}", err=True)


app = create_app()


def main() -> None:
    """Run the installed console entry point."""
    app()
