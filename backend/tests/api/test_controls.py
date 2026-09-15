"""Concurrency, rate, timeout, and cancellation regression tests."""

from __future__ import annotations

import asyncio
from typing import cast

import httpx
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

import webguard.api.app as api_app_module
from webguard.api import create_app
from webguard.api.app import ClientDisconnected, ScanTimedOut, execute_scan
from webguard.api.controls import ClientRateLimiter, ScanCapacity
from webguard.domain.models import ScanRequest, ScanResult

from .test_api import service_for, settings


@pytest.mark.asyncio
async def test_concurrency_limit_rejects_without_queueing(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    started = asyncio.Event()
    finish = asyncio.Event()

    async def slow(_request: ScanRequest) -> ScanResult:
        started.set()
        await finish.wait()
        return make_scan_result()

    app = create_app(settings=settings(max_concurrent_scans=1), scan_service=slow)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first = asyncio.create_task(
            client.post("/api/v1/scans", json={"target": "https://example.com"})
        )
        await asyncio.wait_for(started.wait(), timeout=1)
        second = await client.post(
            "/api/v1/scans", json={"target": "https://example.org"}
        )
        finish.set()
        first_response = await asyncio.wait_for(first, timeout=1)

    assert second.status_code == 503
    assert second.json()["code"] == "SERVICE_BUSY"
    assert first_response.status_code == 200
    assert app.state.scan_capacity.active == 0


def test_rate_limit_is_deterministic_and_ignores_forwarded_for(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    app = create_app(
        settings=settings(rate_limit_requests=1),
        scan_service=service_for(make_scan_result()),  # type: ignore[arg-type]
    )
    with TestClient(app) as client:
        first = client.post("/api/v1/scans", json={"target": "https://example.com"})
        second = client.post(
            "/api/v1/scans",
            json={"target": "https://example.org"},
            headers={"x-forwarded-for": "203.0.113.50"},
        )

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["code"] == "RATE_LIMITED"


@pytest.mark.asyncio
async def test_rate_limiter_memory_is_bounded() -> None:
    limiter = ClientRateLimiter(requests=5, window_seconds=60, max_clients=2, key=b"k" * 32)
    assert await limiter.allow("192.0.2.1")
    assert await limiter.allow("192.0.2.2")
    assert await limiter.allow("192.0.2.3")
    assert limiter.tracked_clients == 2


@pytest.mark.asyncio
async def test_rate_limiter_denies_within_window_and_allows_after_expiry() -> None:
    now = 10.0
    limiter = ClientRateLimiter(
        requests=1,
        window_seconds=5,
        max_clients=2,
        key=b"k" * 32,
        clock=lambda: now,
    )
    assert await limiter.allow("192.0.2.1")
    assert not await limiter.allow("192.0.2.1")
    now = 16.0
    assert await limiter.allow("192.0.2.1")


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ScanCapacity(0),
        lambda: ClientRateLimiter(requests=0, window_seconds=1, max_clients=1),
        lambda: ClientRateLimiter(requests=1, window_seconds=0, max_clients=1),
        lambda: ClientRateLimiter(requests=1, window_seconds=1, max_clients=0),
    ],
)
def test_controls_reject_non_positive_configuration(factory) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        factory()


@pytest.mark.asyncio
async def test_scan_capacity_releases_only_acquired_slots() -> None:
    capacity = ScanCapacity(1)
    assert await capacity.try_acquire()
    assert not await capacity.try_acquire()
    await capacity.release()
    assert capacity.active == 0
    with pytest.raises(RuntimeError, match="without an active scan"):
        await capacity.release()


@pytest.mark.asyncio
async def test_execute_scan_cancels_work_after_disconnect(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    cancelled = asyncio.Event()

    async def slow(_request: ScanRequest) -> ScanResult:
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
        return make_scan_result()

    class DisconnectedRequest:
        async def is_disconnected(self) -> bool:
            return True

    with pytest.raises(ClientDisconnected):
        await execute_scan(
            slow,
            ScanRequest(url="https://example.com"),
            cast(Request, DisconnectedRequest()),
            timeout_seconds=1,
            poll_seconds=0.001,
        )
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_execute_scan_cancels_work_after_timeout(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    cancelled = asyncio.Event()

    async def slow(_request: ScanRequest) -> ScanResult:
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
        return make_scan_result()

    class ConnectedRequest:
        async def is_disconnected(self) -> bool:
            return False

    with pytest.raises(ScanTimedOut):
        await execute_scan(
            slow,
            ScanRequest(url="https://example.com"),
            cast(Request, ConnectedRequest()),
            timeout_seconds=0.002,
            poll_seconds=0.001,
        )
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_execute_scan_cancels_child_when_request_task_is_cancelled(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def slow(_request: ScanRequest) -> ScanResult:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
        return make_scan_result()

    class ConnectedRequest:
        async def is_disconnected(self) -> bool:
            return False

    execution = asyncio.create_task(
        execute_scan(
            slow,
            ScanRequest(url="https://example.com"),
            cast(Request, ConnectedRequest()),
            timeout_seconds=10,
            poll_seconds=0.001,
        )
    )
    await asyncio.wait_for(started.wait(), timeout=1)
    execution.cancel()
    with pytest.raises(asyncio.CancelledError):
        await execution
    assert cancelled.is_set()


def test_capacity_is_released_after_timeout(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    cancelled = False

    async def slow(_request: ScanRequest) -> ScanResult:
        nonlocal cancelled
        try:
            await asyncio.Event().wait()
        finally:
            cancelled = True
        return make_scan_result()

    app = create_app(
        settings=settings(max_concurrent_scans=1, scan_timeout_seconds=0.01),
        scan_service=slow,
    )
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", json={"target": "https://example.com"})

    assert response.status_code == 504
    assert response.json()["code"] == "SCAN_TIMEOUT"
    assert cancelled
    assert app.state.scan_capacity.active == 0


def test_capacity_is_released_after_unexpected_failure(monkeypatch, make_scan_result) -> None:  # type: ignore[no-untyped-def]
    async def service(_request: ScanRequest) -> ScanResult:
        return make_scan_result()

    async def fail(*args: object, **kwargs: object) -> ScanResult:
        raise RuntimeError("private diagnostic")

    monkeypatch.setattr(api_app_module, "execute_scan", fail)
    app = create_app(settings=settings(max_concurrent_scans=1), scan_service=service)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/api/v1/scans", json={"target": "https://example.com"})

    assert response.status_code == 500
    assert app.state.scan_capacity.active == 0


def test_capacity_is_released_after_client_disconnect(monkeypatch, make_scan_result) -> None:  # type: ignore[no-untyped-def]
    async def service(_request: ScanRequest) -> ScanResult:
        return make_scan_result()

    async def disconnect(*args: object, **kwargs: object) -> ScanResult:
        raise ClientDisconnected

    monkeypatch.setattr(api_app_module, "execute_scan", disconnect)
    app = create_app(settings=settings(max_concurrent_scans=1), scan_service=service)
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", json={"target": "https://example.com"})

    assert response.status_code == 499
    assert response.json()["code"] == "CLIENT_DISCONNECTED"
    assert app.state.scan_capacity.active == 0
