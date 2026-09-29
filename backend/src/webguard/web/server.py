"""Safe single-process local server for the bundled WebGuard interface."""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import webbrowser
from collections.abc import Callable

import uvicorn

from webguard.api.app import create_app
from webguard.api.config import ApiSettings

BrowserOpener = Callable[[str], bool]


class LocalWebError(ValueError):
    """A public, actionable local-server configuration error."""


def run_local_web(
    host: str = "127.0.0.1",
    port: int | None = None,
    open_browser: bool = True,
    *,
    browser_opener: BrowserOpener = webbrowser.open,
) -> None:
    """Run the bundled UI and API on one loopback origin until interrupted."""
    normalized_host = _normalize_loopback_host(host)
    selected_port = _select_port(normalized_host, port)
    url_host = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    url = f"http://{url_host}:{selected_port}"
    settings = ApiSettings(
        bind_host=normalized_host,
        bind_port=selected_port,
        allowed_hosts=("127.0.0.1", "localhost", "::1"),
        cors_origins=(url,),
        docs_enabled=False,
    )

    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("webguard.api").setLevel(settings.log_level)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    print(f"WebGuard web interface: {url}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    if open_browser:
        timer = threading.Timer(0.5, _open_browser, args=(url, browser_opener))
        timer.daemon = True
        timer.start()

    try:
        uvicorn.run(
            create_app(settings=settings),
            host=normalized_host,
            port=selected_port,
            log_level=settings.log_level.lower(),
            access_log=False,
            server_header=False,
            proxy_headers=False,
            forwarded_allow_ips="",
            workers=1,
        )
    except SystemExit as exc:
        raise LocalWebError(f"The local web server could not start on {url}.") from exc


def _normalize_loopback_host(host: str) -> str:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return normalized
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError as exc:
        raise LocalWebError("--host must be 127.0.0.1, localhost, or ::1.") from exc
    if not address.is_loopback:
        raise LocalWebError("--host must be a loopback address; public or LAN binding is disabled.")
    return address.compressed


def _select_port(host: str, requested: int | None) -> int:
    if requested is not None and not 1 <= requested <= 65535:
        raise LocalWebError("--port must be between 1 and 65535.")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    bind_host = "127.0.0.1" if host == "localhost" else host
    try:
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.bind((bind_host, requested or 0))
            return int(listener.getsockname()[1])
    except OSError as exc:
        if requested is not None:
            raise LocalWebError(
                f"Port {requested} is unavailable on {host}. Choose another --port."
            ) from exc
        raise LocalWebError("WebGuard could not select an available local port.") from exc


def _open_browser(url: str, opener: BrowserOpener) -> None:
    try:
        opener(url)
    except Exception:
        logging.getLogger("webguard.web").warning(
            "The browser could not be opened automatically; open %s manually.", url
        )
