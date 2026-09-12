"""Sanitizers for evidence and structured log context."""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urlsplit, urlunsplit

_SENSITIVE_KEYS = frozenset(
    {
        "access_token",
        "authorization",
        "cookie",
        "password",
        "proxy-authorization",
        "secret",
        "session",
        "set-cookie",
        "token",
        "x-api-key",
    }
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def sanitize_text(value: str, *, maximum: int = 1024) -> str:
    """Collapse controls and bound untrusted text before display or logging."""
    if maximum < 1:
        raise ValueError("maximum must be positive")
    cleaned = _CONTROL.sub(" ", value).strip()
    return cleaned if len(cleaned) <= maximum else f"{cleaned[: maximum - 1]}…"


def redact_url(raw_url: str) -> str:
    """Remove credentials, query values, and fragments from a URL."""
    try:
        parsed = urlsplit(raw_url)
        host = parsed.hostname
        if not parsed.scheme or not host:
            return "[invalid-url]"
        rendered_host = f"[{host}]" if ":" in host else host
        port = parsed.port
        authority = rendered_host if port is None else f"{rendered_host}:{port}"
        query = "[redacted]" if parsed.query else ""
        return sanitize_text(
            urlunsplit((parsed.scheme, authority, parsed.path or "/", query, "")), maximum=4096
        )
    except ValueError:
        return "[invalid-url]"


def redact_header(name: str, value: str) -> str:
    """Redact sensitive HTTP header values while preserving safe diagnostics."""
    lowered = name.lower().strip()
    if lowered == "set-cookie":
        parts = value.split(";")
        cookie_name, separator, _ = parts[0].partition("=")
        safe_name = sanitize_text(cookie_name, maximum=100) if separator else "cookie"
        safe_name = safe_name or "cookie"
        safe_attributes: list[str] = []
        for raw_attribute in parts[1:]:
            attribute, separator, attribute_value = raw_attribute.strip().partition("=")
            lowered_attribute = attribute.lower()
            if lowered_attribute == "secure":
                safe_attributes.append("Secure")
            elif lowered_attribute == "httponly":
                safe_attributes.append("HttpOnly")
            elif lowered_attribute == "samesite" and separator:
                same_site = sanitize_text(attribute_value, maximum=20)
                if same_site.lower() in {"strict", "lax", "none"}:
                    safe_attributes.append(f"SameSite={same_site}")
        suffix = "; " + "; ".join(safe_attributes) if safe_attributes else ""
        return f"{safe_name}=[redacted]{suffix}"
    if lowered in _SENSITIVE_KEYS:
        return "[redacted]"
    return sanitize_text(value)


def redact_mapping(values: Mapping[str, object]) -> dict[str, object]:
    """Return a shallow copy safe for structured logging."""
    redacted: dict[str, object] = {}
    for key, value in values.items():
        lowered = key.lower()
        if lowered in _SENSITIVE_KEYS:
            redacted[key] = "[redacted]"
        elif lowered.endswith("url") and isinstance(value, str):
            redacted[key] = redact_url(value)
        else:
            redacted[key] = value
    return redacted
