import pytest

from webguard.domain.enums import HttpScheme
from webguard.security.errors import URLPolicyError
from webguard.security.url_policy import URLPolicy


def test_normalizes_https_domain_and_redacts_query() -> None:
    target = URLPolicy().normalize("HTTPS://Example.COM./path?token=secret#ignored")
    assert target.scheme is HttpScheme.HTTPS
    assert target.hostname == "example.com"
    assert target.port == 443
    assert target.request_url == "https://example.com/path?token=secret"
    assert target.display_url == "https://example.com/path?[redacted]"


def test_normalizes_idna_hostname() -> None:
    target = URLPolicy().normalize("https://bücher.example/")
    assert target.hostname == "xn--bcher-kva.example"


def test_normalizes_ipv6_literal() -> None:
    target = URLPolicy().normalize("https://[2001:4860:4860::8888]/")
    assert target.hostname == "2001:4860:4860::8888"
    assert target.request_url == "https://[2001:4860:4860::8888]/"


@pytest.mark.parametrize(
    "raw_url",
    [
        "",
        " example.com",
        "https://example.com ",
        "example.com",
        "https:///missing-host",
        "https://exa mple.com",
        "https://example.com\\@evil.test/",
        "https://-bad.example/",
        "https://bad_.example/",
        "https://[::1",
        "https://[fe80::1%25eth0]/",
        "https://example.com/%0d%0aHost:internal",
        "https://example.com/?value=%00",
    ],
)
def test_rejects_malformed_urls(raw_url: str) -> None:
    with pytest.raises(URLPolicyError):
        URLPolicy().normalize(raw_url)


@pytest.mark.parametrize(
    "raw_url",
    [
        "https://user@example.com/",
        "https://user:password@example.com/",
        "https://example.com@evil.test/",
    ],
)
def test_rejects_url_credentials(raw_url: str) -> None:
    with pytest.raises(URLPolicyError, match="credentials"):
        URLPolicy().normalize(raw_url)


@pytest.mark.parametrize(
    "raw_url",
    [
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "javascript:alert(1)",
    ],
)
def test_rejects_non_http_schemes(raw_url: str) -> None:
    with pytest.raises(URLPolicyError, match="Only http and https"):
        URLPolicy().normalize(raw_url)


@pytest.mark.parametrize(
    "raw_url",
    [
        "https://example.com:444/",
        "http://example.com:8080/",
        "https://example.com:0/",
        "https://example.com:65536/",
        "https://example.com:not-a-port/",
    ],
)
def test_rejects_disallowed_or_invalid_ports(raw_url: str) -> None:
    with pytest.raises(URLPolicyError):
        URLPolicy().normalize(raw_url)


def test_allows_only_configured_default_ports() -> None:
    assert URLPolicy().normalize("http://example.com:80/").port == 80
    assert URLPolicy().normalize("https://example.com:443/").port == 443
