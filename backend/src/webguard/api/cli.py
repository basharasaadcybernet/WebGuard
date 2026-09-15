"""Installed development server entry point for the WebGuard API."""

from __future__ import annotations

import logging

import uvicorn

from webguard.api.config import ApiSettings


def main() -> None:
    """Run one configured API process with proxy trust disabled unless explicitly allowlisted."""
    try:
        settings = ApiSettings.from_env()
    except ValueError as exc:
        raise SystemExit(f"Invalid WebGuard configuration: {exc}") from exc

    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("webguard.api").setLevel(settings.log_level)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    uvicorn.run(
        "webguard.api:create_app",
        factory=True,
        host=settings.bind_host,
        port=settings.bind_port,
        log_level=settings.log_level.lower(),
        access_log=False,
        server_header=False,
        proxy_headers=settings.trust_forwarded_headers,
        forwarded_allow_ips=",".join(settings.trusted_proxies),
        workers=1,
    )
