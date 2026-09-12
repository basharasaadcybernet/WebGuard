import ipaddress

import pytest

from conftest import FakeResolver, FakeTransport, addresses, response
from webguard.security.budget import RequestBudget
from webguard.security.client import SafeHttpClient
from webguard.security.config import NetworkLimits
from webguard.security.errors import (
    BlockedAddressError,
    RedirectPolicyError,
    RequestBudgetExceeded,
    RequestTimedOut,
    ResponseTooLarge,
    URLPolicyError,
)
from webguard.security.transport import PinnedDestination, TransportResponse


@pytest.mark.asyncio
async def test_fetch_resolves_validates_and_pins_public_destination() -> None:
    resolver = FakeResolver([addresses("8.8.8.8")])
    transport = FakeTransport([response(body=b"hello")])
    result = await SafeHttpClient(resolver=resolver, transport=transport).fetch(
        "https://example.com/?token=secret"
    )

    assert resolver.calls == [("example.com", 443)]
    assert transport.destinations[0].ip_address == ipaddress.ip_address("8.8.8.8")
    assert result.final.response.body == b"hello"
    assert result.hops[0].request_url == "https://example.com/?[redacted]"
    assert "token=secret" not in result.hops[0].model_dump_json()


@pytest.mark.asyncio
@pytest.mark.security
async def test_fetch_once_does_not_follow_a_redirect_and_uses_shared_budget() -> None:
    resolver = FakeResolver([addresses("8.8.8.8")])
    transport = FakeTransport(
        [response(301, headers=(("Location", "https://example.com/secure"),))]
    )
    budget = RequestBudget(2)
    result = await SafeHttpClient(resolver=resolver, transport=transport).fetch_once(
        "http://example.com/", budget=budget
    )

    assert len(result.responses) == 1
    assert result.final.response.status_code == 301
    assert resolver.calls == [("example.com", 80)]
    assert budget.used == 1


@pytest.mark.asyncio
@pytest.mark.security
async def test_direct_localhost_target_is_blocked_before_transport() -> None:
    resolver = FakeResolver([addresses("127.0.0.1")])
    transport = FakeTransport([])
    with pytest.raises(BlockedAddressError):
        await SafeHttpClient(resolver=resolver, transport=transport).fetch("http://localhost/")
    assert not transport.destinations


@pytest.mark.asyncio
@pytest.mark.security
@pytest.mark.parametrize(
    "alternate_loopback",
    [
        "2130706433",
        "127.1",
        "0x7f000001",
        "0177.0.0.1",
    ],
)
async def test_alternate_loopback_names_are_blocked_after_resolution(
    alternate_loopback: str,
) -> None:
    resolver = FakeResolver([addresses("127.0.0.1")])
    transport = FakeTransport([])
    with pytest.raises(BlockedAddressError):
        await SafeHttpClient(resolver=resolver, transport=transport).fetch(
            f"http://{alternate_loopback}/"
        )
    assert not transport.destinations


@pytest.mark.asyncio
@pytest.mark.security
async def test_redirect_from_public_host_to_private_host_is_blocked_before_transport() -> None:
    resolver = FakeResolver([addresses("8.8.8.8"), addresses("127.0.0.1")])
    transport = FakeTransport(
        [response(302, headers=(("Location", "http://localhost/admin"),))]
    )

    with pytest.raises(BlockedAddressError):
        await SafeHttpClient(resolver=resolver, transport=transport).fetch("https://example.com/")

    assert len(transport.destinations) == 1
    assert resolver.calls[-1] == ("localhost", 80)


@pytest.mark.asyncio
@pytest.mark.security
@pytest.mark.parametrize(
    "location",
    [
        "https://user:password@example.net/private",
        "https://example.net/%0d%0aHost:internal",
        "//example.net:444/private",
    ],
)
async def test_unsafe_redirect_url_is_rejected_before_second_dns_lookup(location: str) -> None:
    resolver = FakeResolver([addresses("8.8.8.8")])
    transport = FakeTransport([response(302, headers=(("Location", location),))])

    with pytest.raises(URLPolicyError):
        await SafeHttpClient(resolver=resolver, transport=transport).fetch("https://example.com/")
    assert len(resolver.calls) == 1


@pytest.mark.asyncio
@pytest.mark.security
async def test_dns_rebinding_to_private_address_is_blocked_on_new_hop() -> None:
    resolver = FakeResolver([addresses("8.8.8.8"), addresses("10.0.0.5")])
    transport = FakeTransport([response(302, headers=(("Location", "/next"),))])

    with pytest.raises(BlockedAddressError):
        await SafeHttpClient(resolver=resolver, transport=transport).fetch("https://example.com/")

    assert resolver.calls == [("example.com", 443), ("example.com", 443)]
    assert len(transport.destinations) == 1


@pytest.mark.asyncio
@pytest.mark.security
async def test_redirect_loop_is_rejected() -> None:
    resolver = FakeResolver([addresses("8.8.8.8")])
    transport = FakeTransport([response(302, headers=(("Location", "/"),))])

    with pytest.raises(RedirectPolicyError, match="loop"):
        await SafeHttpClient(resolver=resolver, transport=transport).fetch("https://example.com/")


@pytest.mark.asyncio
@pytest.mark.security
async def test_excessive_redirects_are_rejected() -> None:
    limits = NetworkLimits(max_redirects=1)
    resolver = FakeResolver([addresses("8.8.8.8"), addresses("8.8.4.4")])
    transport = FakeTransport(
        [
            response(302, headers=(("Location", "/one"),)),
            response(302, headers=(("Location", "/two"),)),
        ]
    )

    with pytest.raises(RedirectPolicyError, match="Maximum"):
        await SafeHttpClient(limits=limits, resolver=resolver, transport=transport).fetch(
            "https://example.com/"
        )


@pytest.mark.asyncio
async def test_relative_redirect_is_revalidated_and_recorded() -> None:
    resolver = FakeResolver([addresses("8.8.8.8"), addresses("8.8.4.4")])
    transport = FakeTransport(
        [response(301, headers=(("Location", "/new?secret=yes"),)), response(200)]
    )
    result = await SafeHttpClient(resolver=resolver, transport=transport).fetch(
        "http://example.com/old"
    )

    assert len(result.responses) == 2
    assert result.final.target.request_url == "http://example.com/new?secret=yes"
    assert result.hops[0].redirect_location == "http://example.com/new?[redacted]"


@pytest.mark.asyncio
@pytest.mark.security
async def test_https_to_http_redirect_is_explicitly_observable() -> None:
    resolver = FakeResolver([addresses("8.8.8.8"), addresses("8.8.4.4")])
    transport = FakeTransport(
        [
            response(302, headers=(("Location", "http://example.com/fallback"),)),
            response(200),
        ]
    )
    result = await SafeHttpClient(resolver=resolver, transport=transport).fetch(
        "https://example.com/"
    )

    assert result.observed_https_downgrade is True
    assert result.hops[0].request_url.startswith("https://")
    assert result.hops[1].request_url.startswith("http://")


@pytest.mark.asyncio
async def test_ambiguous_redirect_location_is_rejected() -> None:
    resolver = FakeResolver([addresses("8.8.8.8")])
    transport = FakeTransport(
        [response(302, headers=(("Location", "/one"), ("Location", "/two")))]
    )
    with pytest.raises(RedirectPolicyError, match="one valid Location"):
        await SafeHttpClient(resolver=resolver, transport=transport).fetch("https://example.com/")


@pytest.mark.asyncio
async def test_request_budget_prevents_extra_network_attempt() -> None:
    resolver = FakeResolver([addresses("8.8.8.8"), addresses("8.8.4.4")])
    transport = FakeTransport([response(302, headers=(("Location", "/next"),))])

    with pytest.raises(RequestBudgetExceeded):
        await SafeHttpClient(resolver=resolver, transport=transport).fetch(
            "https://example.com/", budget=RequestBudget(1)
        )
    assert len(transport.destinations) == 1


@pytest.mark.asyncio
@pytest.mark.security
async def test_oversized_fake_response_is_rejected_defensively() -> None:
    limits = NetworkLimits(max_response_bytes=1024)
    resolver = FakeResolver([addresses("8.8.8.8")])
    transport = FakeTransport([response(body=b"x" * 1025)])

    with pytest.raises(ResponseTooLarge):
        await SafeHttpClient(limits=limits, resolver=resolver, transport=transport).fetch(
            "https://example.com/"
        )


class TimeoutTransport:
    async def request(
        self, destination: PinnedDestination, limits: NetworkLimits
    ) -> TransportResponse:
        raise RequestTimedOut("simulated bounded timeout")


@pytest.mark.asyncio
@pytest.mark.security
async def test_timeout_is_propagated_as_safe_boundary_error() -> None:
    resolver = FakeResolver([addresses("8.8.8.8")])
    with pytest.raises(RequestTimedOut, match="bounded timeout"):
        await SafeHttpClient(resolver=resolver, transport=TimeoutTransport()).fetch(
            "https://example.com/"
        )
