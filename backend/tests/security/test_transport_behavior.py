from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import AsyncIterator
from typing import Any

import httpcore
import httpx
import pytest

import webguard.security.transport as transport_module
from webguard.domain.enums import HttpScheme
from webguard.domain.models import NormalizedTarget
from webguard.security.config import NetworkLimits
from webguard.security.errors import (
    EndpointUnavailable,
    RequestTimedOut,
    ResponseTooLarge,
    TransportError,
)
from webguard.security.transport import (
    HttpxPinnedTransport,
    PinnedDestination,
    _extract_tls_certificate,
    _PinnedHTTPTransport,
    _PinnedNetworkBackend,
    _verified_ssl_context,
)


def destination() -> PinnedDestination:
    target = NormalizedTarget(
        scheme=HttpScheme.HTTPS,
        hostname="example.com",
        port=443,
        path="/resource",
        display_url="https://example.com/resource",
    )
    return PinnedDestination(target=target, ip_address=ipaddress.ip_address("8.8.8.8"))


class RecordingStream(httpx.AsyncByteStream):
    def __init__(
        self,
        chunks: tuple[bytes, ...] = (),
        failure: BaseException | None = None,
    ) -> None:
        self.chunks = chunks
        self.failure = failure
        self.closed = False
        self.iterated = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.iterated = True
        for chunk in self.chunks:
            yield chunk
        if self.failure is not None:
            raise self.failure

    async def aclose(self) -> None:
        self.closed = True


class RecordingMockTransport(httpx.MockTransport):
    def __init__(self, handler: Any) -> None:
        super().__init__(handler)
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True
        await super().aclose()


def install_mock_transport(
    monkeypatch: pytest.MonkeyPatch,
    handler: Any,
) -> RecordingMockTransport:
    mock = RecordingMockTransport(handler)
    monkeypatch.setattr(transport_module, "_PinnedHTTPTransport", lambda _: mock)
    return mock


@pytest.mark.asyncio
@pytest.mark.security
async def test_real_request_wrapper_preserves_origin_and_host_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = RecordingStream((b"ok",))
    observed: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        observed["url_host"] = request.url.host
        observed["host_header"] = request.headers["host"]
        observed["method"] = request.method
        return httpx.Response(
            200,
            headers={"Content-Length": "2"},
            stream=stream,
            extensions={"http_version": b"HTTP/1.1"},
        )

    mock = install_mock_transport(monkeypatch, handler)
    result = await HttpxPinnedTransport().request(destination(), NetworkLimits())

    assert result.body == b"ok"
    assert observed == {"url_host": "example.com", "host_header": "example.com", "method": "GET"}
    assert stream.closed
    assert mock.closed


@pytest.mark.asyncio
@pytest.mark.security
async def test_declared_oversized_response_is_rejected_without_reading_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = RecordingStream((b"not read",))

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "1025"}, stream=stream)

    install_mock_transport(monkeypatch, handler)
    with pytest.raises(ResponseTooLarge):
        await HttpxPinnedTransport().request(
            destination(), NetworkLimits(max_response_bytes=1024)
        )
    assert not stream.iterated
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.security
async def test_oversized_stream_is_stopped_and_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = RecordingStream((b"a" * 800, b"b" * 300))

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    install_mock_transport(monkeypatch, handler)
    with pytest.raises(ResponseTooLarge):
        await HttpxPinnedTransport().request(
            destination(), NetworkLimits(max_response_bytes=1024)
        )
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.security
@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (httpcore.ReadError("read failed"), TransportError),
        (httpcore.RemoteProtocolError("premature EOF"), TransportError),
        (httpcore.ReadTimeout("read timed out"), RequestTimedOut),
    ],
)
async def test_stream_failures_are_safe_and_resources_are_closed(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
    expected: type[Exception],
) -> None:
    stream = RecordingStream((b"partial",), failure=failure)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    mock = install_mock_transport(monkeypatch, handler)
    with pytest.raises(expected):
        await HttpxPinnedTransport().request(destination(), NetworkLimits())
    assert stream.closed
    assert mock.closed


@pytest.mark.asyncio
@pytest.mark.security
async def test_connection_error_is_mapped_without_leaking_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("internal socket detail", request=request)

    install_mock_transport(monkeypatch, handler)
    with pytest.raises(EndpointUnavailable, match="endpoint connection failed") as caught:
        await HttpxPinnedTransport().request(destination(), NetworkLimits())
    assert "internal socket detail" not in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.security
async def test_unrequested_compression_fails_closed_and_closes_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = RecordingStream((b"compressed",))

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=stream)

    install_mock_transport(monkeypatch, handler)
    with pytest.raises(TransportError, match="unrequested compressed"):
        await HttpxPinnedTransport().request(destination(), NetworkLimits())
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.security
async def test_malformed_content_length_still_uses_streamed_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = RecordingStream((b"bounded",))

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "not-a-number"}, stream=stream)

    install_mock_transport(monkeypatch, handler)
    result = await HttpxPinnedTransport().request(destination(), NetworkLimits())
    assert result.body == b"bounded"
    assert stream.closed


def test_verified_tls_context_requires_certificate_and_hostname_validation() -> None:
    context = _verified_ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_verified_certificate_expiration_is_reduced_to_safe_metadata() -> None:
    class Certificate:
        def getpeercert(self) -> dict[str, str]:
            return {"notAfter": "Jan 31 00:00:00 2027 GMT"}

    class NetworkStream:
        def get_extra_info(self, name: str) -> Certificate | None:
            return Certificate() if name == "ssl_object" else None

    response = httpx.Response(200, extensions={"network_stream": NetworkStream()})
    certificate = _extract_tls_certificate(response)

    assert certificate is not None
    assert certificate.not_after.isoformat() == "2027-01-31T00:00:00+00:00"


def test_tls_context_creation_fails_closed_if_verification_is_not_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InsecureContext:
        verify_mode = ssl.CERT_NONE
        check_hostname = False

    monkeypatch.setattr(
        transport_module.ssl,
        "create_default_context",
        lambda **_: InsecureContext(),
    )
    with pytest.raises(RuntimeError, match="verified TLS"):
        _verified_ssl_context()


class FakeCorePool:
    def __init__(self, response: httpcore.Response | None = None, **configuration: Any) -> None:
        self.configuration = configuration
        self.response = response
        self.requests: list[httpcore.Request] = []
        self.closed = False

    async def handle_async_request(self, request: httpcore.Request) -> httpcore.Response:
        self.requests.append(request)
        if self.response is None:
            raise AssertionError("No fake core response configured")
        return self.response

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.security
async def test_transport_pool_is_single_origin_verified_and_has_no_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pools: list[FakeCorePool] = []

    def pool_factory(**configuration: Any) -> FakeCorePool:
        pool = FakeCorePool(**configuration)
        pools.append(pool)
        return pool

    monkeypatch.setattr(transport_module.httpcore, "AsyncConnectionPool", pool_factory)
    transport = _PinnedHTTPTransport(destination())
    configuration = pools[0].configuration

    assert configuration["max_connections"] == 1
    assert configuration["max_keepalive_connections"] == 0
    assert configuration["retries"] == 0
    assert configuration["http1"] is True
    assert configuration["http2"] is False
    assert isinstance(configuration["network_backend"], _PinnedNetworkBackend)
    tls_context = configuration["ssl_context"]
    assert tls_context.verify_mode == ssl.CERT_REQUIRED
    assert tls_context.check_hostname is True

    await transport.aclose()
    assert pools[0].closed


class CoreBody:
    def __init__(self) -> None:
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b"core-body"

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
@pytest.mark.security
async def test_httpx_adapter_preserves_host_in_httpcore_request() -> None:
    body = CoreBody()
    core_response = httpcore.Response(
        200,
        headers=[(b"Content-Length", b"9")],
        content=body,
        extensions={"http_version": b"HTTP/1.1"},
    )
    transport = _PinnedHTTPTransport(destination())
    original_pool = transport._pool  # type: ignore[attr-defined]
    await original_pool.aclose()
    pool = FakeCorePool(response=core_response)
    transport._pool = pool  # type: ignore[assignment]

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        response = await client.get("https://example.com/resource")

    core_request = pool.requests[0]
    assert core_request.url.host == b"example.com"
    assert dict(core_request.headers)[b"Host"] == b"example.com"
    assert response.content == b"core-body"
    assert body.closed
    assert pool.closed


class FakeSocket:
    def __init__(self, *, option_error: bool = False) -> None:
        self.option_error = option_error
        self.closed = False
        self.blocking: bool | None = None

    def setblocking(self, value: bool) -> None:
        self.blocking = value

    def setsockopt(self, *option: Any) -> None:
        if self.option_error:
            raise OSError("invalid socket option")

    def close(self) -> None:
        self.closed = True


class FakeConnectLoop:
    def __init__(self, failure: BaseException | None = None) -> None:
        self.failure = failure
        self.address: Any = None

    async def sock_connect(self, raw_socket: FakeSocket, address: Any) -> None:
        self.address = address
        if self.failure is not None:
            raise self.failure


class DummyReader:
    async def read(self, max_bytes: int) -> bytes:
        return b""

    def at_eof(self) -> bool:
        return True


class DummyWriter:
    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, name: str) -> Any:
        return None


@pytest.mark.asyncio
@pytest.mark.security
async def test_pinned_backend_connects_to_numeric_ip_not_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_socket = FakeSocket()
    loop = FakeConnectLoop()
    monkeypatch.setattr(transport_module, "_create_tcp_socket", lambda _: raw_socket)
    monkeypatch.setattr(transport_module.asyncio, "get_running_loop", lambda: loop)

    async def open_connection(*, sock: Any) -> tuple[DummyReader, DummyWriter]:
        assert sock is raw_socket
        return DummyReader(), DummyWriter()

    monkeypatch.setattr(transport_module.asyncio, "open_connection", open_connection)
    backend = _PinnedNetworkBackend(destination())
    await backend.connect_tcp("example.com", 443, timeout=1)

    assert loop.address == ("8.8.8.8", 443)
    assert raw_socket.blocking is False


@pytest.mark.asyncio
@pytest.mark.security
@pytest.mark.parametrize(
    "failure",
    [OSError("connect failed"), TimeoutError("connect timed out")],
)
async def test_connect_failure_closes_raw_socket(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    raw_socket = FakeSocket()
    monkeypatch.setattr(transport_module, "_create_tcp_socket", lambda _: raw_socket)
    monkeypatch.setattr(
        transport_module.asyncio, "get_running_loop", lambda: FakeConnectLoop(failure)
    )
    backend = _PinnedNetworkBackend(destination())

    with pytest.raises((httpcore.ConnectError, httpcore.ConnectTimeout)):
        await backend.connect_tcp("example.com", 443, timeout=1)
    assert raw_socket.closed


@pytest.mark.asyncio
@pytest.mark.security
async def test_connect_cancellation_closes_raw_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_socket = FakeSocket()
    cancellation = asyncio.CancelledError()
    monkeypatch.setattr(transport_module, "_create_tcp_socket", lambda _: raw_socket)
    monkeypatch.setattr(
        transport_module.asyncio,
        "get_running_loop",
        lambda: FakeConnectLoop(cancellation),
    )
    backend = _PinnedNetworkBackend(destination())

    with pytest.raises(asyncio.CancelledError):
        await backend.connect_tcp("example.com", 443, timeout=1)
    assert raw_socket.closed


@pytest.mark.asyncio
@pytest.mark.security
async def test_socket_option_failure_closes_raw_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_socket = FakeSocket(option_error=True)
    monkeypatch.setattr(transport_module, "_create_tcp_socket", lambda _: raw_socket)
    backend = _PinnedNetworkBackend(destination())

    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp(
            "example.com",
            443,
            timeout=1,
            socket_options=((socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),),
        )
    assert raw_socket.closed
