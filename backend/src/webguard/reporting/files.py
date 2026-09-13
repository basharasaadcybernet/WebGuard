"""Conservative local-file handling for generated reports."""

from __future__ import annotations

from pathlib import Path


class ReportWriteError(ValueError):
    """Raised when a requested report destination is unsafe or unavailable."""


def validate_new_report_path(path: Path, *, suffix: str) -> Path:
    """Validate an explicit user path without creating directories or overwriting files."""
    destination = path.expanduser()
    if destination.suffix.lower() != suffix:
        raise ReportWriteError(f"Output file must use the {suffix} extension.")
    if not destination.parent.exists() or not destination.parent.is_dir():
        raise ReportWriteError("Output parent directory does not exist.")
    if destination.exists():
        raise ReportWriteError("Output file already exists; WebGuard will not overwrite it.")
    return destination


def write_new_report(path: Path, content: str, *, suffix: str) -> Path:
    """Create one UTF-8 report exclusively, preserving the no-overwrite policy."""
    destination = validate_new_report_path(path, suffix=suffix)
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    except FileExistsError as exc:
        raise ReportWriteError(
            "Output file already exists; WebGuard will not overwrite it."
        ) from exc
    except OSError as exc:
        raise ReportWriteError("WebGuard could not write the requested output file.") from exc
    return destination
