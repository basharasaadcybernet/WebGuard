"""Immutable, trusted observations supplied to security checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from webguard.domain.models import NormalizedTarget
from webguard.security.address_policy import IPAddress
from webguard.security.budget import RequestBudget
from webguard.security.client import SafeFetchResult, SafeResponse
from webguard.security.redaction import redact_header, sanitize_text


@dataclass(frozen=True, slots=True)
class HeaderObservation:
    """A response header with secret-bearing values removed."""

    name: str
    value: str


@dataclass(frozen=True, slots=True)
class BodyObservation:
    """Bounded response bytes retained only inside the trusted scanner process."""

    content: bytes = field(repr=False)
    content_type: str | None = None

    @property
    def size(self) -> int:
        return len(self.content)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


@dataclass(frozen=True, slots=True)
class NetworkObservation:
    """Validated connection metadata; never copied wholesale into public output."""

    destination_ip: IPAddress
    http_version: str
    elapsed_ms: int
    tls_enabled: bool


@dataclass(frozen=True, slots=True)
class ResponseObservation:
    """One internal response in the validated redirect chain."""

    target: NormalizedTarget
    status_code: int
    headers: tuple[HeaderObservation, ...]
    body: BodyObservation
    network: NetworkObservation

    def header_values(self, name: str) -> tuple[str, ...]:
        lowered = name.lower()
        return tuple(header.value for header in self.headers if header.name == lowered)


@dataclass(frozen=True, slots=True)
class RequestBudgetState:
    """Immutable snapshot of the shared per-scan request budget."""

    maximum: int
    used: int
    remaining: int

    @classmethod
    def capture(cls, budget: RequestBudget) -> RequestBudgetState:
        return cls(maximum=budget.maximum, used=budget.used, remaining=budget.remaining)


@dataclass(frozen=True, slots=True)
class ScanNotice:
    """Safe context-building warning or error."""

    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Immutable validated observations available to each registered check."""

    target: NormalizedTarget
    landing_page: ResponseObservation
    redirect_chain: tuple[ResponseObservation, ...]
    request_budget: RequestBudgetState
    started_at: datetime
    observations_finished_at: datetime
    observed_https_downgrade: bool
    warnings: tuple[ScanNotice, ...] = ()
    errors: tuple[ScanNotice, ...] = ()


def _response_observation(response: SafeResponse) -> ResponseObservation:
    headers = tuple(
        HeaderObservation(
            name=sanitize_text(name.lower(), maximum=100),
            value=redact_header(name, value),
        )
        for name, value in response.response.headers
    )
    content_types = response.response.header_values("content-type")
    content_type = redact_header("content-type", content_types[0]) if content_types else None
    return ResponseObservation(
        target=response.target,
        status_code=response.response.status_code,
        headers=headers,
        body=BodyObservation(content=response.response.body, content_type=content_type),
        network=NetworkObservation(
            destination_ip=response.destination_ip,
            http_version=sanitize_text(response.response.http_version, maximum=30),
            elapsed_ms=response.response.elapsed_ms,
            tls_enabled=response.target.scheme.value == "https",
        ),
    )


def build_scan_context(
    *,
    target: NormalizedTarget,
    fetch_result: SafeFetchResult,
    budget: RequestBudget,
    started_at: datetime,
    observations_finished_at: datetime,
) -> ScanContext:
    """Convert boundary-owned responses into immutable scanner observations."""
    responses = tuple(_response_observation(response) for response in fetch_result.responses)
    return ScanContext(
        target=target,
        landing_page=responses[-1],
        redirect_chain=responses,
        request_budget=RequestBudgetState.capture(budget),
        started_at=started_at,
        observations_finished_at=observations_finished_at,
        observed_https_downgrade=fetch_result.observed_https_downgrade,
    )
