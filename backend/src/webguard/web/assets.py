"""Locations for frontend files bundled in the Python package."""

from pathlib import Path


def static_directory() -> Path:
    """Return the installed frontend directory and fail clearly if packaging is incomplete."""
    directory = Path(__file__).with_name("static")
    required = (directory / "index.html", directory / "assets", directory / "brand")
    if not all(path.exists() for path in required):
        raise RuntimeError("The bundled WebGuard web interface is missing from this installation.")
    return directory
