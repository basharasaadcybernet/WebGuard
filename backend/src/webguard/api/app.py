"""FastAPI adapter over the existing ScanEngine and public report projection."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager, suppress
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from webguard import __version__
from webguard.api.config import ApiSettings
from webguard.api.controls import ClientRateLimiter, ScanCapacity
from webguard.api.middleware import (
    API_SECURITY_HEADERS,
    ApiBoundaryMiddleware,
    request_id_from_scope,
)
from webguard.api.models import (
    ApiErrorCode,
    ApiErrorResponse,
    HealthResponse,
    ScanApiRequest,
    ScanApiResponse,
    VersionResponse,
)
from webguard.checks import default_check_registry
from webguard.domain.enums import ScanErrorKind
from webguard.domain.models import ScanRequest, ScanResult
from webguard.reporting import REPORT_SCHEMA_VERSION, ReportBuilder
from webguard.scanner import ScanEngine
from webguard.scoring import load_scoring_config

logger = logging.getLogger("webguard.api")
ScanService = Callable[[ScanRequest], Coroutine[Any, Any, ScanResult]]


class ScanTimedOut(Exception):
    """The API-wide scan deadline expired."""


class ClientDisconnected(Exception):
    """The requesting client disconnected before scan completion."""


async def execute_scan(
    service: ScanService,
    scan_request: ScanRequest,
    request: Request,
    *,
    timeout_seconds: float,
    poll_seconds: float = 0.05,
) -> ScanResult:
    """Run one cancellable scan under a deadline and cancel orphaned work."""
    task: asyncio.Task[ScanResult] = asyncio.create_task(
        service(scan_request), name="webguard-api-scan"
    )
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    try:
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise ScanTimedOut
            done, _ = await asyncio.wait({task}, timeout=min(poll_seconds, remaining))
            if task in done:
                return task.result()
            if await request.is_disconnected():
                raise ClientDisconnected
    finally:
        if not task.done():
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task


def create_app(
    *,
    settings: ApiSettings | None = None,
    scan_service: ScanService | None = None,
) -> FastAPI:
    """Create one stateless API process with injectable scan execution for tests."""
    configured = settings or ApiSettings.from_env()
    service = scan_service or ScanEngine().scan
    capacity = ScanCapacity(configured.max_concurrent_scans)
    limiter = ClientRateLimiter(
        requests=configured.rate_limit_requests,
        window_seconds=configured.rate_limit_window_seconds,
        max_clients=configured.rate_limit_max_clients,
    )
    report_builder = ReportBuilder()
    registry = default_check_registry()
    scoring = load_scoring_config()

    @asynccontextmanager
    async def lifespan(_application: FastAPI) -> AsyncIterator[None]:
        logger.info("API process started")
        try:
            yield
        finally:
            logger.info("API process stopped")

    application = FastAPI(
        title="WebGuard API by Bashar Asaad",
        summary="Safe passive web security posture scanning.",
        description=(
            "A stateless adapter over WebGuard's protected ScanEngine. Security findings are "
            "returned as successful scan data, not HTTP execution errors."
        ),
        version=__version__,
        debug=configured.debug,
        docs_url="/docs" if configured.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if configured.docs_enabled else None,
        lifespan=lifespan,
    )
    application.state.settings = configured
    application.state.scan_capacity = capacity
    application.state.rate_limiter = limiter

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(configured.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Accept", "Content-Type"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )
    application.add_middleware(
        ApiBoundaryMiddleware,
        max_body_bytes=configured.max_request_body_bytes,
        allowed_hosts=configured.allowed_hosts,
    )

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, _error: RequestValidationError) -> JSONResponse:
        return _error_response(
            request,
            status_code=422,
            code=ApiErrorCode.INVALID_REQUEST,
            message="The request body is invalid.",
        )

    @application.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, error: StarletteHTTPException) -> JSONResponse:
        code = (
            ApiErrorCode.NOT_FOUND
            if error.status_code == 404
            else ApiErrorCode.METHOD_NOT_ALLOWED
            if error.status_code == 405
            else ApiErrorCode.INVALID_REQUEST
        )
        message = (
            "The requested API endpoint does not exist."
            if error.status_code == 404
            else "The HTTP method is not allowed for this endpoint."
            if error.status_code == 405
            else "The HTTP request could not be processed."
        )
        return _error_response(request, status_code=error.status_code, code=code, message=message)

    @application.exception_handler(Exception)
    async def unexpected_error(request: Request, _error: Exception) -> JSONResponse:
        request_id = request_id_from_scope(request.scope)
        logger.error("Unexpected API failure request_id=%s", request_id)
        return _error_response(
            request,
            status_code=500,
            code=ApiErrorCode.INTERNAL_ERROR,
            message="WebGuard encountered an internal error.",
        )

    @application.get(
        "/api/v1/health",
        response_model=HealthResponse,
        summary="Check API process health",
    )
    async def health() -> HealthResponse:
        return HealthResponse()

    @application.get(
        "/api/v1/version",
        response_model=VersionResponse,
        summary="Get public compatibility versions",
    )
    async def version() -> VersionResponse:
        return VersionResponse(
            webguard_version=__version__,
            report_schema_version=REPORT_SCHEMA_VERSION,
            ruleset_version=registry.ruleset_version,
            scoring_version=scoring.scoring_version,
        )

    error_responses: dict[int | str, dict[str, Any]] = {
        400: {"model": ApiErrorResponse, "description": "Invalid HTTP request envelope"},
        413: {"model": ApiErrorResponse, "description": "Request body too large"},
        415: {"model": ApiErrorResponse, "description": "Unsupported request media type"},
        422: {"model": ApiErrorResponse, "description": "Invalid request or target"},
        429: {"model": ApiErrorResponse, "description": "Per-client rate limit exceeded"},
        499: {"model": ApiErrorResponse, "description": "Client disconnected"},
        503: {"model": ApiErrorResponse, "description": "Scan capacity is exhausted"},
        504: {"model": ApiErrorResponse, "description": "API scan deadline exceeded"},
        500: {"model": ApiErrorResponse, "description": "Unexpected internal failure"},
    }

    @application.post(
        "/api/v1/scans",
        response_model=ScanApiResponse,
        responses=error_responses,
        summary="Run one bounded passive posture scan",
        description=(
            "Runs the existing protected scanner once. A partial/failed posture result and "
            "negative security findings are returned as data when execution produced a report."
        ),
    )
    async def scan(payload: ScanApiRequest, request: Request) -> ScanApiResponse | JSONResponse:
        request_id = request_id_from_scope(request.scope)
        client_host = request.client.host if request.client is not None else "unknown"
        if not await limiter.allow(client_host):
            logger.warning("API scan rate rejected request_id=%s", request_id)
            return _error_response(
                request,
                status_code=429,
                code=ApiErrorCode.RATE_LIMITED,
                message="The scan rate limit has been reached. Try again later.",
            )
        if not await capacity.try_acquire():
            logger.warning("API scan capacity rejected request_id=%s", request_id)
            return _error_response(
                request,
                status_code=503,
                code=ApiErrorCode.SERVICE_BUSY,
                message="WebGuard is at scan capacity. Try again later.",
            )

        started_at = asyncio.get_running_loop().time()
        logger.info("API scan started request_id=%s", request_id)
        try:
            result = await execute_scan(
                service,
                ScanRequest(url=payload.target),
                request,
                timeout_seconds=configured.scan_timeout_seconds,
            )
        except ScanTimedOut:
            duration_ms = round((asyncio.get_running_loop().time() - started_at) * 1000)
            logger.warning(
                "API scan timed out request_id=%s duration_ms=%s", request_id, duration_ms
            )
            return _error_response(
                request,
                status_code=504,
                code=ApiErrorCode.SCAN_TIMEOUT,
                message="The scan exceeded the API execution deadline.",
            )
        except ClientDisconnected:
            duration_ms = round((asyncio.get_running_loop().time() - started_at) * 1000)
            logger.info(
                "API client disconnected request_id=%s duration_ms=%s",
                request_id,
                duration_ms,
            )
            return _error_response(
                request,
                status_code=499,
                code=ApiErrorCode.CLIENT_DISCONNECTED,
                message="The client disconnected before the scan completed.",
            )
        finally:
            await capacity.release()

        if any(error.kind is ScanErrorKind.TARGET for error in result.errors):
            logger.info("API scan rejected request_id=%s failure_class=target_policy", request_id)
            return _error_response(
                request,
                status_code=422,
                code=ApiErrorCode.INVALID_TARGET,
                message="The target was rejected by WebGuard's URL safety policy.",
            )

        duration_ms = round((asyncio.get_running_loop().time() - started_at) * 1000)
        logger.info(
            "API scan finished request_id=%s scan_id=%s state=%s duration_ms=%s",
            request_id,
            result.metadata.scan_id,
            result.metadata.state,
            duration_ms,
        )
        return ScanApiResponse(request_id=request_id, report=report_builder.build(result))

    return application


def _error_response(
    request: Request,
    *,
    status_code: int,
    code: ApiErrorCode,
    message: str,
) -> JSONResponse:
    request_id = request_id_from_scope(request.scope)
    body = ApiErrorResponse(code=code, message=message, request_id=request_id)
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(mode="json"),
        headers={"X-Request-ID": str(request_id), **API_SECURITY_HEADERS},
    )
