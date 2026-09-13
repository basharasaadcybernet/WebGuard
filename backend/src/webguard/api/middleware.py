"""Small ASGI guards for host validation, body size, and correlation IDs."""

from __future__ import annotations

from collections import deque
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from webguard.api.models import ApiErrorCode, ApiErrorResponse


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

        async def send_with_request_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", ()))
                if not any(name.lower() == b"x-request-id" for name, _ in headers):
                    headers.append((b"x-request-id", str(request_id).encode("ascii")))
                message["headers"] = headers
            await send(message)

        host = self._header(scope, b"host")
        if host is None or self._hostname(host) not in self._allowed_hosts:
            await self._error(
                scope,
                receive,
                send_with_request_id,
                status_code=400,
                code=ApiErrorCode.INVALID_HOST,
                message="The HTTP Host header is not permitted.",
                request_id=request_id,
            )
            return

        content_length = self._header(scope, b"content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                await self._error(
                    scope,
                    receive,
                    send_with_request_id,
                    status_code=400,
                    code=ApiErrorCode.INVALID_REQUEST,
                    message="The request Content-Length is invalid.",
                    request_id=request_id,
                )
                return
            if declared_length < 0 or declared_length > self._max_body_bytes:
                await self._too_large(scope, receive, send_with_request_id, request_id)
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
                await self._too_large(scope, receive, send_with_request_id, request_id)
                return
            if not message.get("more_body", False):
                break

        async def replay_receive() -> Message:
            if buffered:
                return buffered.popleft()
            return await receive()

        await self._app(scope, replay_receive, send_with_request_id)

    @staticmethod
    def _header(scope: Scope, name: bytes) -> str | None:
        for key, value in scope.get("headers", ()):
            if key.lower() == name:
                return cast(bytes, value).decode("latin-1")
        return None

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
