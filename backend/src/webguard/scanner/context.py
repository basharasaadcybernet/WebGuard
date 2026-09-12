"""Immutable, trusted observations supplied to security checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin

from webguard.domain.enums import HttpScheme
from webguard.domain.models import NormalizedTarget
from webguard.security.address_policy import IPAddress
from webguard.security.budget import RequestBudget
from webguard.security.client import SafeFetchResult, SafeResponse
from webguard.security.redaction import redact_header, redact_url, sanitize_text


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
    certificate_not_after: datetime | None = None


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
class ProbeFailure:
    """Safe classification for an observation request that did not complete."""

    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ProbeObservation:
    """Success or bounded failure from one approved scanner request."""

    requested_target: NormalizedTarget
    responses: tuple[ResponseObservation, ...] = ()
    failure: ProbeFailure | None = None

    @property
    def succeeded(self) -> bool:
        return bool(self.responses) and self.failure is None

    @property
    def final(self) -> ResponseObservation | None:
        return self.responses[-1] if self.responses else None

    @property
    def observed_https_downgrade(self) -> bool:
        pairs = zip(self.responses, self.responses[1:], strict=False)
        return any(
            current.target.scheme is HttpScheme.HTTPS and following.target.scheme is HttpScheme.HTTP
            for current, following in pairs
        )


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Immutable validated observations available to each registered check."""

    target: NormalizedTarget
    landing: ProbeObservation
    https_probe: ProbeObservation
    http_probe: ProbeObservation
    landing_page: ResponseObservation | None
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
            value=(
                redact_url(urljoin(response.target.request_url, value))
                if name.lower().strip() == "location"
                else redact_header(name, value)
            ),
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
            certificate_not_after=(
                response.response.tls_certificate.not_after
                if response.response.tls_certificate is not None
                else None
            ),
        ),
    )


def build_probe_observation(
    *,
    requested_target: NormalizedTarget,
    fetch_result: SafeFetchResult | None = None,
    failure: ProbeFailure | None = None,
) -> ProbeObservation:
    """Convert one protected fetch outcome into a check-facing observation."""
    if (fetch_result is None) == (failure is None):
        raise ValueError("A probe requires exactly one result or failure")
    responses = (
        tuple(_response_observation(response) for response in fetch_result.responses)
        if fetch_result is not None
        else ()
    )
    return ProbeObservation(
        requested_target=requested_target,
        responses=responses,
        failure=failure,
    )


def build_scan_context(
    *,
    target: NormalizedTarget,
    landing: ProbeObservation,
    https_probe: ProbeObservation,
    http_probe: ProbeObservation,
    budget: RequestBudget,
    started_at: datetime,
    observations_finished_at: datetime,
) -> ScanContext:
    """Convert boundary-owned responses into immutable scanner observations."""
    context_errors = tuple(
        ScanNotice(code=f"{name}.{probe.failure.code}", message=probe.failure.message)
        for name, probe in (
            ("landing", landing),
            ("https_probe", https_probe),
            ("http_probe", http_probe),
        )
        if probe.failure is not None
    )
    return ScanContext(
        target=target,
        landing=landing,
        https_probe=https_probe,
        http_probe=http_probe,
        landing_page=landing.final,
        redirect_chain=landing.responses,
        request_budget=RequestBudgetState.capture(budget),
        started_at=started_at,
        observations_finished_at=observations_finished_at,
        observed_https_downgrade=(
            landing.observed_https_downgrade or https_probe.observed_https_downgrade
        ),
        errors=context_errors,
    )
