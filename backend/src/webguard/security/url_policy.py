"""Strict URL parsing and normalization before any network activity."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import SplitResult, unquote_to_bytes, urlsplit, urlunsplit

import idna

from webguard.domain.enums import HttpScheme
from webguard.domain.models import NormalizedTarget
from webguard.security.config import NetworkLimits
from webguard.security.errors import URLPolicyError

_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class URLPolicy:
    """Convert an untrusted URL into a canonical HTTP(S) target."""

    def __init__(self, limits: NetworkLimits | None = None) -> None:
        self._limits = limits or NetworkLimits()

    def normalize(self, raw_url: str) -> NormalizedTarget:
        if not raw_url or raw_url != raw_url.strip():
            raise URLPolicyError("URL must be non-empty and cannot have surrounding whitespace")
        if len(raw_url) > 2048:
            raise URLPolicyError("URL exceeds the maximum length")
        if _CONTROL_OR_SPACE.search(raw_url) or "\\" in raw_url:
            raise URLPolicyError(
                "URL contains forbidden whitespace, control characters, or backslashes"
            )

        try:
            parsed = urlsplit(raw_url, allow_fragments=True)
        except ValueError as exc:
            raise URLPolicyError("URL is malformed") from exc

        scheme = self._parse_scheme(parsed)
        if not parsed.netloc:
            raise URLPolicyError("URL must include a hostname")
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            raise URLPolicyError("URL credentials are not permitted")

        hostname = self._normalize_hostname(parsed.hostname)
        try:
            parsed_port = parsed.port
            port = parsed_port if parsed_port is not None else (
                443 if scheme is HttpScheme.HTTPS else 80
            )
        except ValueError as exc:
            raise URLPolicyError("URL contains an invalid port") from exc
        if port not in self._limits.allowed_ports:
            raise URLPolicyError("Destination port is not permitted")

        path = parsed.path or "/"
        if len(path) > 4096 or len(parsed.query) > 4096:
            raise URLPolicyError("URL path or query exceeds the maximum length")
        self._reject_decoded_controls(path, "path")
        self._reject_decoded_controls(parsed.query, "query")

        authority_host = f"[{hostname}]" if ":" in hostname else hostname
        default_port = 443 if scheme is HttpScheme.HTTPS else 80
        authority = authority_host if port == default_port else f"{authority_host}:{port}"
        display_query = "[redacted]" if parsed.query else ""
        display_url = urlunsplit((scheme.value, authority, path, display_query, ""))
        return NormalizedTarget(
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            query=parsed.query,
            display_url=display_url,
        )

    @staticmethod
    def _parse_scheme(parsed: SplitResult) -> HttpScheme:
        try:
            return HttpScheme(parsed.scheme.lower())
        except ValueError as exc:
            raise URLPolicyError("Only http and https URLs are permitted") from exc

    @staticmethod
    def _normalize_hostname(hostname: str | None) -> str:
        if not hostname:
            raise URLPolicyError("URL must include a valid hostname")
        hostname = hostname.rstrip(".").lower()
        if not hostname or "%" in hostname:
            raise URLPolicyError("Hostname is invalid")

        try:
            return ipaddress.ip_address(hostname).compressed
        except ValueError:
            pass

        try:
            ascii_hostname = idna.encode(hostname, uts46=True, std3_rules=True).decode("ascii")
        except idna.IDNAError as exc:
            raise URLPolicyError("Hostname is not valid IDNA") from exc
        if len(ascii_hostname) > 253:
            raise URLPolicyError("Hostname exceeds the DNS length limit")
        if any(not _HOST_LABEL.fullmatch(label) for label in ascii_hostname.split(".")):
            raise URLPolicyError("Hostname contains an invalid DNS label")
        return ascii_hostname

    @staticmethod
    def _reject_decoded_controls(value: str, component: str) -> None:
        decoded = unquote_to_bytes(value)
        if any(byte < 0x20 or byte == 0x7F for byte in decoded):
            raise URLPolicyError(f"URL {component} contains encoded control characters")
