"""Public API contracts, status semantics, CORS, and privacy tests."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable

import pytest
from fastapi.testclient import TestClient

from webguard.api import ApiSettings, RuntimeEnvironment, create_app
from webguard.domain.enums import FindingStatus, ScanState, Severity
from webguard.domain.models import Evidence, Finding, ScanRequest, ScanResult


def settings(**overrides: object) -> ApiSettings:
    values: dict[str, object] = {
        "max_concurrent_scans": 4,
        "scan_timeout_seconds": 2.0,
        "max_request_body_bytes": 4096,
        "rate_limit_requests": 100,
        "rate_limit_window_seconds": 60.0,
        "rate_limit_max_clients": 100,
        "cors_origins": ("http://localhost:5173",),
        "allowed_hosts": ("testserver",),
        "docs_enabled": True,
    }
    values.update(overrides)
    return ApiSettings(**values)  # type: ignore[arg-type]


def production_settings(**overrides: object) -> ApiSettings:
    values: dict[str, object] = {
        "environment": RuntimeEnvironment.PRODUCTION,
        "cors_origins": (),
        "allowed_hosts": ("webguard.example.invalid",),
        "docs_enabled": False,
    }
    values.update(overrides)
    return settings(**values)


def service_for(result: ScanResult) -> Callable[[ScanRequest], AsyncIterator[ScanResult]]:
    async def service(_request: ScanRequest) -> ScanResult:
        return result

    return service  # type: ignore[return-value]


def test_health_is_cheap_and_minimal(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    calls = 0

    async def service(_request: ScanRequest) -> ScanResult:
        nonlocal calls
        calls += 1
        return make_scan_result()

    with TestClient(create_app(settings=settings(), scan_service=service)) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert calls == 0
    assert response.headers["x-request-id"]


def test_api_responses_have_no_store_and_defensive_security_headers(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    app = create_app(
        settings=production_settings(),
        scan_service=service_for(make_scan_result()),  # type: ignore[arg-type]
    )
    with TestClient(app, base_url="https://webguard.example.invalid") as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"] == (
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-frame-options"] == "DENY"
    assert "camera=()" in response.headers["permissions-policy"]


def test_version_exposes_only_public_compatibility_fields(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    with TestClient(
        create_app(settings=settings(), scan_service=service_for(make_scan_result()))  # type: ignore[arg-type]
    ) as client:
        response = client.get("/api/v1/version")

    assert response.status_code == 200
    assert response.json() == {
        "webguard_version": "0.1.0.dev0",
        "api_version": "v1",
        "api_schema_version": "1.0",
        "report_schema_version": "1.0",
        "ruleset_version": "0.1.0-phase5b",
        "scoring_version": "1.0",
    }
    serialized = response.text.lower()
    assert "python" not in serialized
    assert "bashar" not in serialized
    assert "workspace" not in serialized


@pytest.mark.parametrize(
    ("state", "score_mode", "expected_score"),
    [
        (ScanState.COMPLETED, "normal", 93),
        (ScanState.PARTIAL, "normal", 93),
        (ScanState.FAILED, "withheld", None),
        (ScanState.COMPLETED, "withheld", None),
        (ScanState.COMPLETED, "capped", 59),
    ],
)
def test_scan_returns_shared_report_for_all_posture_states(
    make_scan_result, state: ScanState, score_mode: str, expected_score: int | None
) -> None:  # type: ignore[no-untyped-def]
    result = make_scan_result(state=state, score_mode=score_mode)
    with TestClient(
        create_app(settings=settings(), scan_service=service_for(result))  # type: ignore[arg-type]
    ) as client:
        response = client.post("/api/v1/scans", json={"target": "https://example.com"})

    assert response.status_code == 200
    body = response.json()
    assert body["api_version"] == "v1"
    assert body["api_schema_version"] == "1.0"
    assert body["request_id"] == response.headers["x-request-id"]
    assert body["report"]["report_schema_version"] == "1.0"
    assert body["report"]["completion_state"] == state.value
    assert body["report"]["score"]["score"] == expected_score
    assert body["report"]["disclaimer"].startswith("This score reflects only")
    assert body["report"]["limitations"]


def test_findings_category_and_rule_contributions_are_returned(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    finding = Finding(
        id="headers.content_security_policy",
        title="Policy missing",
        category="Security Headers",
        status=FindingStatus.FAIL,
        severity=Severity.HIGH,
        description="No enforced policy was observed.",
        evidence=(Evidence(label="Header", value="absent"),),
        recommendation="Deploy a restrictive policy.",
    )
    result = make_scan_result(finding=finding)
    with TestClient(
        create_app(settings=settings(), scan_service=service_for(result))  # type: ignore[arg-type]
    ) as client:
        response = client.post("/api/v1/scans", json={"target": "https://example.com"})

    report = response.json()["report"]
    assert report["findings"][0]["id"] == finding.id
    assert report["severity_summary"][0] == {"severity": "HIGH", "count": 1}
    assert report["score"]["categories"][0]["category"] == "Security Headers"
    assert report["score"]["rule_contributions"][0]["rule_id"] == finding.id


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"target": ""},
        {"target": "https://example.com", "tls_verify": False},
        {"target": "https://example.com", "headers": {"Authorization": "secret"}},
        {"target": "x" * 2049},
    ],
)
def test_malformed_or_overpowered_requests_use_stable_422(payload: dict[str, object]) -> None:
    async def must_not_run(_request: ScanRequest) -> ScanResult:
        raise AssertionError("invalid request reached ScanEngine")

    with TestClient(create_app(settings=settings(), scan_service=must_not_run)) as client:
        response = client.post("/api/v1/scans", json=payload)

    assert response.status_code == 422
    assert response.json()["code"] == "INVALID_REQUEST"
    assert response.json()["request_id"] == response.headers["x-request-id"]
    assert "input" not in response.json()


def test_request_body_limit_is_enforced_before_json_parsing(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    app = create_app(
        settings=settings(max_request_body_bytes=32),
        scan_service=service_for(make_scan_result()),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", content=b"x" * 33)

    assert response.status_code == 413
    assert response.json()["code"] == "REQUEST_TOO_LARGE"
    assert response.headers["cache-control"] == "no-store"


def test_scan_endpoint_rejects_non_json_content_type(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    app = create_app(
        settings=settings(), scan_service=service_for(make_scan_result())  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            content='{"target":"https://example.com"}',
            headers={"content-type": "text/plain"},
        )

    assert response.status_code == 415
    assert response.json()["code"] == "INVALID_REQUEST"


def test_scan_endpoint_rejects_duplicate_json_fields(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    app = create_app(
        settings=settings(), scan_service=service_for(make_scan_result())  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            content=(
                '{"target":"https://example.com",'
                '"target":"https://attacker.example"}'
            ),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_REQUEST"


def test_unknown_host_is_rejected_with_public_error(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    with TestClient(
        create_app(settings=settings(), scan_service=service_for(make_scan_result()))  # type: ignore[arg-type]
    ) as client:
        response = client.get("/api/v1/health", headers={"host": "attacker.invalid"})

    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_HOST"


def test_cors_allows_configured_origin_without_credentials(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    with TestClient(
        create_app(settings=settings(), scan_service=service_for(make_scan_result()))  # type: ignore[arg-type]
    ) as client:
        response = client.options(
            "/api/v1/scans",
            headers={
                "origin": "http://localhost:5173",
                "access-control-request-method": "POST",
                "access-control-request-headers": "content-type",
            },
        )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-credentials" not in response.headers


def test_cors_does_not_authorize_unknown_origin(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    with TestClient(
        create_app(settings=settings(), scan_service=service_for(make_scan_result()))  # type: ignore[arg-type]
    ) as client:
        response = client.get(
            "/api/v1/health", headers={"origin": "https://untrusted.example"}
        )

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-credentials" not in response.headers


def test_production_cors_allows_only_explicit_https_origin(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    app = create_app(
        settings=production_settings(cors_origins=("https://frontend.example.invalid",)),
        scan_service=service_for(make_scan_result()),  # type: ignore[arg-type]
    )
    with TestClient(app, base_url="https://webguard.example.invalid") as client:
        allowed = client.options(
            "/api/v1/scans",
            headers={
                "origin": "https://frontend.example.invalid",
                "access-control-request-method": "POST",
                "access-control-request-headers": "content-type",
            },
        )
        rejected = client.get(
            "/api/v1/health", headers={"origin": "https://untrusted.example.invalid"}
        )

    assert allowed.headers["access-control-allow-origin"] == "https://frontend.example.invalid"
    assert "access-control-allow-credentials" not in allowed.headers
    assert "access-control-allow-origin" not in rejected.headers


def test_response_never_serializes_sensitive_target_or_exception_data(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    result = make_scan_result()
    with TestClient(
        create_app(settings=settings(), scan_service=service_for(result)),  # type: ignore[arg-type]
        raise_server_exceptions=False,
    ) as client:
        response = client.post(
            "/api/v1/scans",
            json={"target": "https://example.com/account?token=private-value"},
            headers={"Authorization": "Bearer authorization-secret", "Cookie": "sid=cookie-secret"},
        )

    serialized = json.dumps(response.json())
    assert response.status_code == 200
    for secret in (
        "private-value",
        "authorization-secret",
        "cookie-secret",
        "destination_ip",
        "pinned",
        "Traceback",
        "C:\\\\Users",
    ):
        assert secret not in serialized


def test_scan_logging_uses_metadata_not_target_or_request_secrets(
    caplog, make_scan_result
) -> None:  # type: ignore[no-untyped-def]
    caplog.set_level("INFO", logger="webguard.api")
    app = create_app(
        settings=settings(), scan_service=service_for(make_scan_result())  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scans",
            json={"target": "https://example.com/account?token=private-value"},
            headers={"authorization": "Bearer private-authorization", "cookie": "sid=private"},
        )

    assert response.status_code == 200
    assert "API scan started request_id=" in caplog.text
    assert "API scan finished request_id=" in caplog.text
    assert "duration_ms=" in caplog.text
    assert "private-value" not in caplog.text
    assert "private-authorization" not in caplog.text


def test_unexpected_exception_is_sanitized_and_correlated() -> None:
    async def broken(_request: ScanRequest) -> ScanResult:
        raise RuntimeError(
            "Authorization: Bearer secret; C:\\Users\\private; https://site/?token=hidden"
        )

    app = create_app(settings=production_settings(), scan_service=broken)
    with TestClient(
        app,
        base_url="https://webguard.example.invalid",
        raise_server_exceptions=False,
    ) as client:
        response = client.post("/api/v1/scans", json={"target": "https://example.com"})

    assert response.status_code == 500
    assert response.json()["code"] == "INTERNAL_ERROR"
    assert response.json()["request_id"] == response.headers["x-request-id"]
    assert "secret" not in response.text
    assert "private" not in response.text
    assert "hidden" not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert app.debug is False


def test_openapi_documents_only_the_small_v1_surface(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    with TestClient(
        create_app(settings=settings(), scan_service=service_for(make_scan_result()))  # type: ignore[arg-type]
    ) as client:
        schema = client.get("/openapi.json").json()

    paths = set(schema["paths"])
    assert paths == {"/api/v1/health", "/api/v1/version", "/api/v1/scans"}
    scan_schema = schema["components"]["schemas"]["ScanApiRequest"]
    assert set(scan_schema["properties"]) == {"target"}


def test_docs_can_be_disabled(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    app = create_app(
        settings=settings(docs_enabled=False),
        scan_service=service_for(make_scan_result()),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
