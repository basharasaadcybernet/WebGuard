"""Bundled local web-server behavior."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from webguard.web.assets import static_directory
from webguard.web.server import (
    LocalWebError,
    _normalize_loopback_host,
    _select_port,
    run_local_web,
)


def test_static_interface_contains_built_entrypoint_and_assets() -> None:
    directory = static_directory()

    assert (directory / "index.html").is_file()
    assert any((directory / "assets").glob("*.js"))
    assert any((directory / "assets").glob("*.css"))
    assert (directory / "brand" / "logo.svg").is_file()


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "example.com", ""])
def test_web_server_rejects_non_loopback_hosts(host: str) -> None:
    with pytest.raises(LocalWebError, match=r"loopback|127\.0\.0\.1"):
        _normalize_loopback_host(host)


@pytest.mark.parametrize(
    ("provided", "expected"),
    [("127.0.0.1", "127.0.0.1"), ("localhost", "localhost"), ("::1", "::1")],
)
def test_web_server_accepts_supported_loopback_hosts(provided: str, expected: str) -> None:
    assert _normalize_loopback_host(provided) == expected


def test_web_server_selects_an_available_port() -> None:
    selected = _select_port("127.0.0.1", None)

    assert 1 <= selected <= 65535


def test_web_server_rejects_an_occupied_explicit_port() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        occupied = int(listener.getsockname()[1])
        with pytest.raises(LocalWebError, match=str(occupied)):
            _select_port("127.0.0.1", occupied)


def test_web_server_builds_one_safe_local_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(app: object, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr("webguard.web.server.uvicorn.run", fake_run)
    run_local_web("127.0.0.1", None, False)

    assert captured["host"] == "127.0.0.1"
    assert isinstance(captured["port"], int)
    assert captured["access_log"] is False
    assert captured["server_header"] is False
    assert captured["proxy_headers"] is False
    assert captured["forwarded_allow_ips"] == ""
    assert captured["workers"] == 1
    assert Path(static_directory()).is_dir()


def test_web_server_schedules_the_default_browser(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[str] = []

    class ImmediateTimer:
        daemon = False

        def __init__(self, _delay: float, callback: object, args: tuple[object, ...]) -> None:
            self._callback = callback
            self._args = args

        def start(self) -> None:
            assert callable(self._callback)
            self._callback(*self._args)

    monkeypatch.setattr("webguard.web.server.threading.Timer", ImmediateTimer)
    monkeypatch.setattr("webguard.web.server.uvicorn.run", lambda *args, **kwargs: None)

    run_local_web("127.0.0.1", 8765, True, browser_opener=lambda url: opened.append(url) or True)

    assert opened == ["http://127.0.0.1:8765"]
