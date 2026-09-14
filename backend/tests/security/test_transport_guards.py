import asyncio
import ipaddress
import os
import ssl
from typing import Any

import httpcore
import pytest

from webguard.domain.enums import HttpScheme
from webguard.domain.models import NormalizedTarget
from webguard.security.errors import (
    BlockedAddressError,
    TLSCertificateExpired,
    TLSCertificateUntrusted,
    TLSHandshakeFailed,
    TLSHostnameMismatch,
)
from webguard.security.transport import (
    HttpxPinnedTransport,
    PinnedDestination,
    _PinnedNetworkBackend,
    _PinnedNetworkStream,
)


class SlowReader:
    async def read(self, max_bytes: int) -> bytes:
        await asyncio.sleep(0.05)
        return b""

    def at_eof(self) -> bool:
        return False


class RecordingWriter:
    def __init__(self, tls_error: BaseException | None = None) -> None:
        self.hostname: str | None = None
        self.closed = False
        self.tls_error = tls_error

    def write(self, buffer: bytes) -> None:
        return None

    async def drain(self) -> None:
        return None

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        *,
        server_hostname: str | None,
        ssl_handshake_timeout: float | None,
    ) -> None:
        self.hostname = server_hostname
        if self.tls_error is not None:
            raise self.tls_error

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, name: str) -> Any:
        return None


def target() -> NormalizedTarget:
    return NormalizedTarget(
        scheme=HttpScheme.HTTPS,
        hostname="example.com",
        port=443,
        path="/",
        display_url="https://example.com/",
    )


@pytest.mark.asyncio
@pytest.mark.security
async def test_tls_stream_preserves_validated_hostname_for_sni() -> None:
    writer = RecordingWriter()
    stream = _PinnedNetworkStream(SlowReader(), writer, "example.com")  # type: ignore[arg-type]
    returned = await stream.start_tls(
        ssl.create_default_context(), server_hostname="example.com", timeout=1
    )
    assert returned is stream
    assert writer.hostname == "example.com"


@pytest.mark.asyncio
@pytest.mark.security
async def test_tls_stream_rejects_different_sni_hostname() -> None:
    writer = RecordingWriter()
    stream = _PinnedNetworkStream(SlowReader(), writer, "example.com")  # type: ignore[arg-type]
    with pytest.raises(httpcore.ConnectError, match="TLS hostname"):
        await stream.start_tls(ssl.create_default_context(), server_hostname="internal", timeout=1)
    assert writer.closed


@pytest.mark.asyncio
@pytest.mark.security
@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("certificate has expired", TLSCertificateExpired),
        ("hostname mismatch", TLSHostnameMismatch),
        ("self-signed certificate", TLSCertificateUntrusted),
    ],
)
async def test_tls_certificate_verification_failures_are_safely_classified(
    reason: str, expected: type[Exception]
) -> None:
    verification_error = ssl.SSLCertVerificationError(1, reason)
    writer = RecordingWriter(tls_error=verification_error)
    stream = _PinnedNetworkStream(SlowReader(), writer, "example.com")  # type: ignore[arg-type]

    with pytest.raises(expected) as caught:
        await stream.start_tls(
            ssl.create_default_context(), server_hostname="example.com", timeout=1
        )

    assert caught.value.__cause__ is verification_error
    assert writer.closed


@pytest.mark.asyncio
@pytest.mark.security
async def test_ambiguous_tls_failure_is_handshake_failure_not_certificate_guess() -> None:
    tls_error = ssl.SSLError("ambiguous internal handshake detail")
    writer = RecordingWriter(tls_error=tls_error)
    stream = _PinnedNetworkStream(SlowReader(), writer, "example.com")  # type: ignore[arg-type]

    with pytest.raises(TLSHandshakeFailed, match="TLS negotiation failed") as caught:
        await stream.start_tls(
            ssl.create_default_context(), server_hostname="example.com", timeout=1
        )

    assert "ambiguous internal handshake detail" not in str(caught.value)
    assert caught.value.__cause__ is tls_error
    assert writer.closed


@pytest.mark.asyncio
@pytest.mark.security
async def test_stream_read_timeout_maps_to_httpcore_timeout() -> None:
    stream = _PinnedNetworkStream(  # type: ignore[arg-type]
        SlowReader(), RecordingWriter(), "example.com"  # type: ignore[arg-type]
    )
    with pytest.raises(httpcore.ReadTimeout):
        await stream.read(10, timeout=0.001)


@pytest.mark.security
def test_pinned_backend_revalidates_destination_address() -> None:
    destination = PinnedDestination(target=target(), ip_address=ipaddress.ip_address("127.0.0.1"))
    with pytest.raises(BlockedAddressError):
        _PinnedNetworkBackend(destination)


def test_production_transport_declares_no_environment_proxy_use(monkeypatch: Any) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    assert os.environ["HTTPS_PROXY"]
    assert HttpxPinnedTransport.uses_environment_proxies is False
