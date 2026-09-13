"""SSRF-boundary and architecture checks through the REST adapter."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from webguard.api import create_app
from webguard.scanner import ScanEngine

from .test_api import settings


@pytest.mark.parametrize(
    "target",
    [
        "ftp://example.com/file",
        "https://user:password@example.com/",
        "https://example.com:8443/",
        "not a url",
    ],
)
def test_unsafe_targets_are_rejected_through_real_scan_engine(target: str) -> None:
    engine = ScanEngine()
    with TestClient(create_app(settings=settings(), scan_service=engine.scan)) as client:
        response = client.post("/api/v1/scans", json={"target": target})

    assert response.status_code == 422
    assert response.json()["code"] == "INVALID_TARGET"
    serialized = response.text
    assert "password" not in serialized
    assert "169.254.169.254" not in serialized
    assert "127.0.0.1" not in serialized
    assert "::1" not in serialized
    assert "Traceback" not in serialized


@pytest.mark.parametrize(
    "target",
    [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://10.1.2.3/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
    ],
)
def test_address_based_ssrf_rejection_is_a_safe_failed_scan(target: str) -> None:
    engine = ScanEngine()
    with TestClient(create_app(settings=settings(), scan_service=engine.scan)) as client:
        response = client.post("/api/v1/scans", json={"target": target})

    assert response.status_code == 200
    report = response.json()["report"]
    assert report["completion_state"] == "FAILED"
    assert report["operational_errors"]
    serialized = response.text
    assert "destination_ip" not in serialized
    assert "pinned" not in serialized.lower()
    assert "socket" not in serialized.lower()
    assert "Traceback" not in serialized


def test_api_package_cannot_import_network_clients_or_internal_networking() -> None:
    api_root = Path(__file__).parents[2] / "src" / "webguard" / "api"
    forbidden_roots = {"aiohttp", "httpcore", "httpx", "requests", "socket"}
    forbidden_internal = {
        "webguard.scanner.network",
        "webguard.security.client",
        "webguard.security.transport",
    }
    violations: list[str] = []

    for path in api_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name.split(".", 1)[0] in forbidden_roots or name in forbidden_internal:
                    violations.append(f"{path.name} imports {name}")

    assert not violations


def test_api_scan_route_delegates_to_scan_engine_and_report_builder() -> None:
    source = (Path(__file__).parents[2] / "src" / "webguard" / "api" / "app.py").read_text(
        encoding="utf-8"
    )
    assert "ScanEngine" in source
    assert "ReportBuilder" in source
    assert "SafeHttpClient" not in source
    assert "ScoringEngine" not in source
    assert "requests." not in source
