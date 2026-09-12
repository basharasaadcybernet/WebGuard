"""HTTP transport that connects only to a previously validated IP address."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import ssl
import time
from collections.abc import AsyncIterable, AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpcore
import httpx

from webguard.domain.models import NormalizedTarget
from webguard.security.address_policy import IPAddress, PublicAddressPolicy
from webguard.security.config import NetworkLimits
from webguard.security.errors import (
    RequestTimedOut,
    ResponseTooLarge,
    TransportError,
)


def _verified_ssl_context() -> ssl.SSLContext:
    """Create a server-auth context and fail closed if hostname checks are unavailable."""
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    if context.verify_mode is not ssl.CERT_REQUIRED or not context.check_hostname:
        raise RuntimeError("A verified TLS client context could not be created")
    return context


def _create_tcp_socket(family: socket.AddressFamily) -> socket.socket:
    """Create the unconnected socket used by the pinned backend."""
    return socket.socket(family=family, type=socket.SOCK_STREAM)


@dataclass(frozen=True, slots=True)
class PinnedDestination:
    """A normalized target paired with the exact public IP to connect to."""

    target: NormalizedTarget
    ip_address: IPAddress


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """Internal bounded response; headers and body must never be logged directly."""

    status_code: int
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes = field(repr=False)
    elapsed_ms: int
    http_version: str

    def header_values(self, name: str) -> tuple[str, ...]:
        lowered = name.lower()
        return tuple(value for key, value in self.headers if key.lower() == lowered)


class PinnedTransport(Protocol):
    """Injectable low-level transport; it never accepts an arbitrary URL."""

    async def request(
        self,
        destination: PinnedDestination,
        limits: NetworkLimits,
    ) -> TransportResponse: ...


class _PinnedNetworkStream(httpcore.AsyncNetworkStream):
    """Asyncio stream that refuses TLS for any hostname other than the validated one."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        expected_hostname: str,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._expected_hostname = expected_hostname

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        try:
            async with asyncio.timeout(timeout):
                return await self._reader.read(max_bytes)
        except TimeoutError as exc:
            raise httpcore.ReadTimeout from exc
        except OSError as exc:
            raise httpcore.ReadError from exc

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        try:
            self._writer.write(buffer)
            async with asyncio.timeout(timeout):
                await self._writer.drain()
        except TimeoutError as exc:
            raise httpcore.WriteTimeout from exc
        except OSError as exc:
            raise httpcore.WriteError from exc

    async def aclose(self) -> None:
        self._writer.close()
        with contextlib.suppress(OSError):
            await self._writer.wait_closed()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if server_hostname != self._expected_hostname:
            await self.aclose()
            raise httpcore.ConnectError("TLS hostname did not match the validated target")
        try:
            async with asyncio.timeout(timeout):
                await self._writer.start_tls(
                    ssl_context,
                    server_hostname=server_hostname,
                    ssl_handshake_timeout=timeout,
                )
        except TimeoutError as exc:
            await self.aclose()
            raise httpcore.ConnectTimeout from exc
        except (OSError, ssl.SSLError) as exc:
            await self.aclose()
            raise httpcore.ConnectError from exc
        except BaseException:
            await self.aclose()
            raise
        return self

    def get_extra_info(self, info: str) -> Any:
        mapping = {
            "ssl_object": "ssl_object",
            "client_addr": "sockname",
            "server_addr": "peername",
            "socket": "socket",
        }
        if info == "is_readable":
            return not self._reader.at_eof()
        key = mapping.get(info)
        return self._writer.get_extra_info(key) if key is not None else None


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Open a TCP socket to the pinned numeric address without another DNS lookup."""

    def __init__(self, destination: PinnedDestination) -> None:
        PublicAddressPolicy().validate(destination.ip_address)
        self._destination = destination

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        target = self._destination.target
        if host.rstrip(".").lower() != target.hostname or port != target.port:
            raise httpcore.ConnectError("Connection origin did not match the validated target")
        if local_address is not None:
            raise httpcore.ConnectError("Binding a caller-selected local address is not permitted")

        address = self._destination.ip_address
        family = socket.AF_INET6 if isinstance(address, ipaddress.IPv6Address) else socket.AF_INET
        raw_socket = _create_tcp_socket(family)
        try:
            raw_socket.setblocking(False)
            for option in socket_options or ():
                raw_socket.setsockopt(*option)
            socket_address: tuple[str, int] | tuple[str, int, int, int]
            if family == socket.AF_INET6:
                socket_address = (str(address), port, 0, 0)
            else:
                socket_address = (str(address), port)

            async with asyncio.timeout(timeout):
                await asyncio.get_running_loop().sock_connect(raw_socket, socket_address)
            reader, writer = await asyncio.open_connection(sock=raw_socket)
        except TimeoutError as exc:
            raw_socket.close()
            raise httpcore.ConnectTimeout from exc
        except OSError as exc:
            raw_socket.close()
            raise httpcore.ConnectError from exc
        except BaseException:
            raw_socket.close()
            raise
        return _PinnedNetworkStream(reader, writer, target.hostname)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("Unix sockets are not permitted")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class _CoreResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: AsyncIterable[bytes]) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        close = getattr(self._stream, "aclose", None)
        if close is not None:
            await close()


class _PinnedHTTPTransport(httpx.AsyncBaseTransport):
    """httpx adapter over a one-origin httpcore pool and pinned backend."""

    def __init__(self, destination: PinnedDestination) -> None:
        self._destination = destination
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=_verified_ssl_context(),
            max_connections=1,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_PinnedNetworkBackend(destination),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        target = self._destination.target
        request_port = request.url.port
        if request_port is None:
            request_port = 443 if request.url.scheme == "https" else 80
        if (
            request.url.host != target.hostname
            or request_port != target.port
            or request.url.scheme != target.scheme.value
        ):
            raise httpx.ConnectError(
                "Request did not match the validated destination", request=request
            )
        if not isinstance(request.stream, httpx.AsyncByteStream):
            raise httpx.RequestError(
                "Only asynchronous request streams are permitted", request=request
            )

        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        response = await self._pool.handle_async_request(core_request)
        if not isinstance(response.stream, AsyncIterable):
            raise httpx.StreamError("Async transport received a synchronous stream")
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_CoreResponseStream(response.stream),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


class HttpxPinnedTransport:
    """Production transport with streaming limits and environment proxies disabled."""

    uses_environment_proxies = False

    async def request(
        self,
        destination: PinnedDestination,
        limits: NetworkLimits,
    ) -> TransportResponse:
        PublicAddressPolicy().validate(destination.ip_address)
        started = time.monotonic()
        timeout = httpx.Timeout(
            connect=limits.connect_timeout_seconds,
            read=limits.read_timeout_seconds,
            write=limits.write_timeout_seconds,
            pool=limits.pool_timeout_seconds,
        )
        transport = _PinnedHTTPTransport(destination)
        try:
            async with asyncio.timeout(limits.total_timeout_seconds):
                async with httpx.AsyncClient(
                    transport=transport,
                    timeout=timeout,
                    follow_redirects=False,
                    trust_env=False,
                ) as client, client.stream(
                    "GET",
                    destination.target.request_url,
                    headers={
                        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.1",
                        "Accept-Encoding": "identity",
                        "User-Agent": "CyberNet-WebGuard/0.1",
                    },
                ) as response:
                    content_encoding = response.headers.get("content-encoding", "identity").lower()
                    if content_encoding not in {"", "identity"}:
                        raise TransportError(
                            "Server returned an unrequested compressed response"
                        )
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            if int(declared) > limits.max_response_bytes:
                                raise ResponseTooLarge(
                                    "Response exceeded the configured size limit"
                                )
                        except ValueError:
                            pass

                    chunks: list[bytes] = []
                    received = 0
                    async for chunk in response.aiter_raw():
                        received += len(chunk)
                        if received > limits.max_response_bytes:
                            raise ResponseTooLarge("Response exceeded the configured size limit")
                        chunks.append(chunk)
                    elapsed_ms = round((time.monotonic() - started) * 1000)
                    return TransportResponse(
                        status_code=response.status_code,
                        headers=tuple(response.headers.multi_items()),
                        body=b"".join(chunks),
                        elapsed_ms=elapsed_ms,
                        http_version=response.http_version,
                    )
        except (TimeoutError, httpx.TimeoutException, httpcore.TimeoutException) as exc:
            raise RequestTimedOut("Request exceeded a configured timeout") from exc
        except ResponseTooLarge:
            raise
        except (httpx.HTTPError, httpcore.NetworkError, httpcore.ProtocolError, OSError) as exc:
            raise TransportError("Pinned network request failed") from exc
