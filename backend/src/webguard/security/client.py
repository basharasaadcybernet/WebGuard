"""High-level safe client that validates every request and redirect."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

from webguard.domain.enums import HttpScheme
from webguard.domain.models import FetchHop, NormalizedTarget
from webguard.security.address_policy import IPAddress, PublicAddressPolicy
from webguard.security.budget import RequestBudget
from webguard.security.config import NetworkLimits
from webguard.security.errors import RedirectPolicyError, ResponseTooLarge
from webguard.security.redaction import redact_url
from webguard.security.resolver import Resolver, SystemResolver
from webguard.security.transport import (
    HttpxPinnedTransport,
    PinnedDestination,
    PinnedTransport,
    TransportResponse,
)
from webguard.security.url_policy import URLPolicy

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True, slots=True)
class SafeResponse:
    """One validated response retained for future scanner observations."""

    target: NormalizedTarget
    destination_ip: IPAddress
    response: TransportResponse = field(repr=False)

    def to_hop(self, index: int) -> FetchHop:
        locations = self.response.header_values("location")
        absolute_location = urljoin(self.target.request_url, locations[0]) if locations else None
        return FetchHop(
            index=index,
            request_url=self.target.display_url,
            destination_ip=self.destination_ip,
            status_code=self.response.status_code,
            response_bytes=len(self.response.body),
            elapsed_ms=self.response.elapsed_ms,
            redirect_location=redact_url(absolute_location) if absolute_location else None,
        )


@dataclass(frozen=True, slots=True)
class SafeFetchResult:
    """A complete, validated redirect chain and final response."""

    responses: tuple[SafeResponse, ...]

    def __post_init__(self) -> None:
        if not self.responses:
            raise ValueError("A safe fetch result must contain at least one response")

    @property
    def final(self) -> SafeResponse:
        return self.responses[-1]

    @property
    def hops(self) -> tuple[FetchHop, ...]:
        return tuple(response.to_hop(index) for index, response in enumerate(self.responses))

    @property
    def observed_https_downgrade(self) -> bool:
        """Report whether a redirect changed from HTTPS to plaintext HTTP."""
        pairs = zip(self.responses, self.responses[1:], strict=False)
        return any(
            current.target.scheme is HttpScheme.HTTPS
            and following.target.scheme is HttpScheme.HTTP
            for current, following in pairs
        )


class SafeHttpClient:
    """The only supported entry point for future WebGuard HTTP access."""

    def __init__(
        self,
        *,
        limits: NetworkLimits | None = None,
        resolver: Resolver | None = None,
        transport: PinnedTransport | None = None,
        address_policy: PublicAddressPolicy | None = None,
    ) -> None:
        self._limits = limits or NetworkLimits()
        self._url_policy = URLPolicy(self._limits)
        self._resolver = resolver or SystemResolver(self._limits.dns_timeout_seconds)
        self._transport = transport or HttpxPinnedTransport()
        self._address_policy = address_policy or PublicAddressPolicy()

    async def fetch(self, raw_url: str, *, budget: RequestBudget | None = None) -> SafeFetchResult:
        """Fetch a URL while validating and pinning every destination."""
        request_budget = budget or RequestBudget(self._limits.max_requests)
        current = self._url_policy.normalize(raw_url)
        seen: set[str] = set()
        responses: list[SafeResponse] = []
        redirects_followed = 0

        while True:
            request_key = current.request_url
            if request_key in seen:
                raise RedirectPolicyError("Redirect loop detected")
            seen.add(request_key)

            await request_budget.consume()
            resolved = await self._resolver.resolve(current.hostname, current.port)
            public_addresses = self._address_policy.validate_all(resolved)
            destination = PinnedDestination(target=current, ip_address=public_addresses[0])
            response = await self._transport.request(destination, self._limits)
            if len(response.body) > self._limits.max_response_bytes:
                raise ResponseTooLarge("Response exceeded the configured size limit")

            responses.append(
                SafeResponse(
                    target=current,
                    destination_ip=destination.ip_address,
                    response=response,
                )
            )
            if response.status_code not in _REDIRECT_STATUSES:
                return SafeFetchResult(responses=tuple(responses))

            locations = response.header_values("location")
            if len(locations) != 1 or not locations[0].strip():
                raise RedirectPolicyError(
                    "Redirect response must contain one valid Location header"
                )
            if redirects_followed >= self._limits.max_redirects:
                raise RedirectPolicyError("Maximum redirect limit exceeded")

            redirected_url = urljoin(current.request_url, locations[0])
            current = self._url_policy.normalize(redirected_url)
            redirects_followed += 1

    def normalize(self, raw_url: str) -> NormalizedTarget:
        """Normalize a target through the same policy used immediately before fetching."""
        return self._url_policy.normalize(raw_url)
