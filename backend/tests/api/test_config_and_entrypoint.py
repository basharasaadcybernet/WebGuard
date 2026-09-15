"""Configuration parsing, HTTP envelope edges, and API executable tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from webguard.api import ApiSettings, RuntimeEnvironment, create_app
from webguard.api.cli import main
from webguard.api.models import ScanApiRequest


def test_settings_load_all_supported_environment_values() -> None:
    configured = ApiSettings.from_env(
        {
            "WEBGUARD_ENV": "test",
            "WEBGUARD_BIND_HOST": "0.0.0.0",
            "WEBGUARD_BIND_PORT": "8080",
            "WEBGUARD_DEBUG": "on",
            "WEBGUARD_LOG_LEVEL": "warning",
            "WEBGUARD_MAX_CONCURRENT_SCANS": "7",
            "WEBGUARD_SCAN_TIMEOUT_SECONDS": "45.5",
            "WEBGUARD_MAX_REQUEST_BODY_BYTES": "8192",
            "WEBGUARD_RATE_LIMIT_REQUESTS": "12",
            "WEBGUARD_RATE_LIMIT_WINDOW_SECONDS": "30",
            "WEBGUARD_RATE_LIMIT_MAX_CLIENTS": "500",
            "WEBGUARD_CORS_ORIGINS": "https://one.example, https://two.example",
            "WEBGUARD_ALLOWED_HOSTS": "api.example,localhost",
            "WEBGUARD_TRUSTED_PROXIES": "192.0.2.10, 198.51.100.0/24",
            "WEBGUARD_DOCS_ENABLED": "off",
        }
    )
    assert configured.environment is RuntimeEnvironment.TEST
    assert configured.bind_host == "0.0.0.0"
    assert configured.bind_port == 8080
    assert configured.debug
    assert configured.log_level == "WARNING"
    assert configured.max_concurrent_scans == 7
    assert configured.scan_timeout_seconds == 45.5
    assert configured.max_request_body_bytes == 8192
    assert configured.rate_limit_requests == 12
    assert configured.rate_limit_window_seconds == 30
    assert configured.rate_limit_max_clients == 500
    assert configured.cors_origins == ("https://one.example", "https://two.example")
    assert configured.allowed_hosts == ("api.example", "localhost")
    assert configured.trusted_proxies == ("192.0.2.10", "198.51.100.0/24")
    assert configured.trust_forwarded_headers
    assert not configured.docs_enabled


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("WEBGUARD_MAX_CONCURRENT_SCANS", "nope"),
        ("WEBGUARD_MAX_CONCURRENT_SCANS", "0"),
        ("WEBGUARD_SCAN_TIMEOUT_SECONDS", "never"),
        ("WEBGUARD_SCAN_TIMEOUT_SECONDS", "0"),
        ("WEBGUARD_DOCS_ENABLED", "perhaps"),
        ("WEBGUARD_ENV", "staging"),
        ("WEBGUARD_LOG_LEVEL", "verbose"),
        ("WEBGUARD_TRUSTED_PROXIES", "proxy.internal"),
        ("WEBGUARD_CORS_ORIGINS", ""),
        ("WEBGUARD_ALLOWED_HOSTS", ""),
    ],
)
def test_invalid_environment_configuration_fails_closed(name: str, value: str) -> None:
    with pytest.raises(ValueError, match=name):
        ApiSettings.from_env({name: value})


@pytest.mark.parametrize(
    "overrides",
    [
        {"cors_origins": ("*",)},
        {"allowed_hosts": ("*",)},
        {"cors_origins": ("localhost:5173",)},
        {"cors_origins": ("https://frontend.example.invalid/path",)},
        {"cors_origins": ()},
        {"allowed_hosts": ()},
        {"max_concurrent_scans": 0},
        {"max_concurrent_scans": 65},
        {"scan_timeout_seconds": 301},
        {"bind_host": "https://example.invalid"},
        {"environment": "production"},
    ],
)
def test_direct_settings_reject_unsafe_values(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ApiSettings(**overrides)  # type: ignore[arg-type]


def test_target_model_rejects_control_characters() -> None:
    with pytest.raises(ValidationError):
        ScanApiRequest(target="https://example.com/\nsecret")


def test_invalid_content_length_uses_stable_error() -> None:
    with TestClient(create_app(settings=ApiSettings())) as client:
        response = client.post(
            "/api/v1/scans",
            content=b"{}",
            headers={"content-length": "invalid"},
        )
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_REQUEST"


def test_unknown_path_and_wrong_method_use_stable_errors() -> None:
    with TestClient(create_app(settings=ApiSettings())) as client:
        missing = client.get("/api/v1/missing")
        wrong_method = client.put("/api/v1/health")
    assert missing.status_code == 404
    assert missing.json()["code"] == "NOT_FOUND"
    assert wrong_method.status_code == 405
    assert wrong_method.json()["code"] == "METHOD_NOT_ALLOWED"


def test_api_entrypoint_uses_safe_local_defaults(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def fake_run(app: str, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.delenv("WEBGUARD_BIND_HOST", raising=False)
    monkeypatch.delenv("WEBGUARD_BIND_PORT", raising=False)
    monkeypatch.setattr("webguard.api.cli.uvicorn.run", fake_run)
    main()
    assert captured == {
        "app": "webguard.api:create_app",
        "factory": True,
        "host": "127.0.0.1",
        "port": 8000,
        "log_level": "info",
        "access_log": False,
        "server_header": False,
        "proxy_headers": False,
        "forwarded_allow_ips": "",
        "workers": 1,
    }


@pytest.mark.parametrize("port", ["invalid", "0", "65536"])
def test_api_entrypoint_rejects_invalid_port(monkeypatch, port: str) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("WEBGUARD_BIND_PORT", port)
    with pytest.raises(SystemExit, match="WEBGUARD_BIND_PORT"):
        main()


def test_production_requires_explicit_network_facing_configuration() -> None:
    with pytest.raises(ValueError, match="WEBGUARD_BIND_HOST"):
        ApiSettings.from_env({"WEBGUARD_ENV": "production"})


def test_production_same_origin_configuration_is_fail_closed() -> None:
    configured = ApiSettings.from_env(
        {
            "WEBGUARD_ENV": "production",
            "WEBGUARD_BIND_HOST": "0.0.0.0",
            "WEBGUARD_ALLOWED_HOSTS": "webguard.example.invalid",
            "WEBGUARD_CORS_ORIGINS": "",
        }
    )
    assert configured.environment is RuntimeEnvironment.PRODUCTION
    assert configured.cors_origins == ()
    assert not configured.debug
    assert not configured.docs_enabled


@pytest.mark.parametrize(
    "overrides",
    [
        {"debug": True},
        {"log_level": "DEBUG"},
        {"allowed_hosts": ("localhost",)},
        {"allowed_hosts": ("10.0.0.1",)},
        {"cors_origins": ("http://webguard.example.invalid",)},
        {"cors_origins": ("https://localhost",)},
        {"trusted_proxies": ("*",)},
    ],
)
def test_production_rejects_dangerous_direct_settings(overrides: dict[str, object]) -> None:
    values: dict[str, object] = {
        "environment": RuntimeEnvironment.PRODUCTION,
        "allowed_hosts": ("webguard.example.invalid",),
        "cors_origins": (),
        "docs_enabled": False,
    }
    values.update(overrides)
    with pytest.raises(ValueError):
        ApiSettings(**values)  # type: ignore[arg-type]


def test_entrypoint_enables_forwarded_headers_only_for_allowlisted_proxy(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def fake_run(_app: str, **kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setenv("WEBGUARD_TRUSTED_PROXIES", "192.0.2.10")
    monkeypatch.setattr("webguard.api.cli.uvicorn.run", fake_run)
    main()
    assert captured["proxy_headers"] is True
    assert captured["forwarded_allow_ips"] == "192.0.2.10"
