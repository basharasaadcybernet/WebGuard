"""Small ASGI guards for host validation, body size, and correlation IDs."""

from __future__ import annotations

import json
from collections import deque
from typing import Final, cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from webguard.api.models import ApiErrorCode, ApiErrorResponse

API_SECURITY_HEADERS: Final = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


class _DuplicateJsonKey(ValueError):
    """Internal signal for an ambiguous JSON object."""


def request_id_from_scope(scope: Scope) -> UUID:
    """Return the ID assigned at the outer HTTP boundary."""
    state = scope.get("state", {})
    value = state.get("request_id") if isinstance(state, dict) else None
    return value if isinstance(value, UUID) else uuid4()


class ApiBoundaryMiddleware:
    """Reject unsafe HTTP envelopes before request parsing or route execution."""

    def __init__(
        self, app: ASGIApp, *, max_body_bytes: int, allowed_hosts: tuple[str, ...]
    ) -> None:
        self._app = app
        self._max_body_bytes = max_body_bytes
        self._allowed_hosts = frozenset(host.lower() for host in allowed_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        request_id = uuid4()
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", ()))
                if not any(name.lower() == b"x-request-id" for name, _ in headers):
                    headers.append((b"x-request-id", str(request_id).encode("ascii")))
                if str(scope.get("path", "")).startswith("/api/"):
                    encoded = tuple(
                        (name.lower().encode("ascii"), value.encode("ascii"))
                        for name, value in API_SECURITY_HEADERS.items()
                    )
                    protected = {name for name, _ in encoded}
                    headers = [item for item in headers if item[0].lower() not in protected]
                    headers.extend(encoded)
                message["headers"] = headers
            await send(message)

        hosts = self._headers(scope, b"host")
        if len(hosts) != 1 or self._hostname(hosts[0]) not in self._allowed_hosts:
            await self._error(
                scope,
                receive,
                send_with_security_headers,
                status_code=400,
                code=ApiErrorCode.INVALID_HOST,
                message="The HTTP Host header is not permitted.",
                request_id=request_id,
            )
            return

        content_lengths = self._headers(scope, b"content-length")
        if len(content_lengths) > 1:
            await self._error(
                scope,
                receive,
                send_with_security_headers,
                status_code=400,
                code=ApiErrorCode.INVALID_REQUEST,
                message="The request contains conflicting length headers.",
                request_id=request_id,
            )
            return
        if content_lengths:
            try:
                declared_length = int(content_lengths[0])
            except ValueError:
                await self._error(
                    scope,
                    receive,
                    send_with_security_headers,
                    status_code=400,
                    code=ApiErrorCode.INVALID_REQUEST,
                    message="The request Content-Length is invalid.",
                    request_id=request_id,
                )
                return
            if declared_length < 0 or declared_length > self._max_body_bytes:
                await self._too_large(scope, receive, send_with_security_headers, request_id)
                return

        is_scan_post = scope.get("method") == "POST" and scope.get("path") == "/api/v1/scans"
        if is_scan_post:
            content_types = self._headers(scope, b"content-type")
            media_type = content_types[0].split(";", 1)[0].strip().lower() if content_types else ""
            if len(content_types) != 1 or media_type != "application/json":
                await self._error(
                    scope,
                    receive,
                    send_with_security_headers,
                    status_code=415,
                    code=ApiErrorCode.INVALID_REQUEST,
                    message="The scan endpoint accepts application/json only.",
                    request_id=request_id,
                )
                return

        buffered: deque[Message] = deque()
        total = 0
        while True:
            message = await receive()
            buffered.append(message)
            if message["type"] != "http.request":
                break
            total += len(message.get("body", b""))
            if total > self._max_body_bytes:
                await self._too_large(scope, receive, send_with_security_headers, request_id)
                return
            if not message.get("more_body", False):
                break

        if is_scan_post:
            body = b"".join(
                message.get("body", b"")
                for message in buffered
                if message["type"] == "http.request"
            )
            if self._contains_duplicate_json_key(body):
                await self._error(
                    scope,
                    receive,
                    send_with_security_headers,
                    status_code=400,
                    code=ApiErrorCode.INVALID_REQUEST,
                    message="The JSON request contains duplicate fields.",
                    request_id=request_id,
                )
                return

        async def replay_receive() -> Message:
            if buffered:
                return buffered.popleft()
            return await receive()

        await self._app(scope, replay_receive, send_with_security_headers)

    @staticmethod
    def _headers(scope: Scope, name: bytes) -> tuple[str, ...]:
        return tuple(
            cast(bytes, value).decode("latin-1")
            for key, value in scope.get("headers", ())
            if key.lower() == name
        )

    @staticmethod
    def _contains_duplicate_json_key(body: bytes) -> bool:
        def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise _DuplicateJsonKey(key)
                result[key] = value
            return result

        try:
            json.loads(body, object_pairs_hook=reject_duplicates)
        except _DuplicateJsonKey:
            return True
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        return False

    @staticmethod
    def _hostname(host: str) -> str:
        try:
            return (urlsplit(f"//{host}").hostname or "").lower()
        except ValueError:
            return ""

    async def _too_large(
        self, scope: Scope, receive: Receive, send: Send, request_id: UUID
    ) -> None:
        await self._error(
            scope,
            receive,
            send,
            status_code=413,
            code=ApiErrorCode.REQUEST_TOO_LARGE,
            message="The request body exceeds the configured limit.",
            request_id=request_id,
        )

    @staticmethod
    async def _error(
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        status_code: int,
        code: ApiErrorCode,
        message: str,
        request_id: UUID,
    ) -> None:
        response = JSONResponse(
            status_code=status_code,
            content=ApiErrorResponse(
                code=code, message=message, request_id=request_id
            ).model_dump(mode="json"),
        )
        await response(scope, receive, send)
