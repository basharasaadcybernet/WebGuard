"""Installed development server entry point for the WebGuard API."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    """Run one local development process; production should invoke Uvicorn explicitly."""
    host = os.environ.get("WEBGUARD_BIND_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("WEBGUARD_BIND_PORT", "8000"))
    except ValueError as exc:
        raise SystemExit("WEBGUARD_BIND_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("WEBGUARD_BIND_PORT must be between 1 and 65535")
    uvicorn.run(
        "webguard.api:create_app",
        factory=True,
        host=host,
        port=port,
        proxy_headers=False,
    )
