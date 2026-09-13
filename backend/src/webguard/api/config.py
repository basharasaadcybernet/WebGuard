"""Environment-backed, conservative API process settings."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal

API_VERSION: Final[Literal["v1"]] = "v1"
API_SCHEMA_VERSION: Final[Literal["1.0"]] = "1.0"


def _positive_int(source: Mapping[str, str], name: str, default: int, maximum: int) -> int:
    raw = source.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


def _positive_float(
    source: Mapping[str, str], name: str, default: float, maximum: float
) -> float:
    raw = source.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not 0 < value <= maximum:
        raise ValueError(f"{name} must be greater than zero and at most {maximum:g}")
    return value


def _boolean(source: Mapping[str, str], name: str, default: bool) -> bool:
    raw = source.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _csv(source: Mapping[str, str], name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = source.get(name)
    if raw is None:
        return default
    values = tuple(dict.fromkeys(part.strip() for part in raw.split(",") if part.strip()))
    if not values:
        raise ValueError(f"{name} must contain at least one value")
    return values


@dataclass(frozen=True, slots=True)
class ApiSettings:
    """Small process-local policy surface; scanner security is not configurable here."""

    max_concurrent_scans: int = 4
    scan_timeout_seconds: float = 90.0
    max_request_body_bytes: int = 4096
    rate_limit_requests: int = 10
    rate_limit_window_seconds: float = 60.0
    rate_limit_max_clients: int = 4096
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "testserver")
    docs_enabled: bool = True

    def __post_init__(self) -> None:
        positive_values = {
            "max_concurrent_scans": self.max_concurrent_scans,
            "scan_timeout_seconds": self.scan_timeout_seconds,
            "max_request_body_bytes": self.max_request_body_bytes,
            "rate_limit_requests": self.rate_limit_requests,
            "rate_limit_window_seconds": self.rate_limit_window_seconds,
            "rate_limit_max_clients": self.rate_limit_max_clients,
        }
        if any(value <= 0 for value in positive_values.values()):
            raise ValueError("API numeric settings must be positive")
        if "*" in self.cors_origins:
            raise ValueError("Wildcard CORS origins are not permitted")
        if "*" in self.allowed_hosts:
            raise ValueError("Wildcard allowed hosts are not permitted")
        if not self.cors_origins or not self.allowed_hosts:
            raise ValueError("CORS origins and allowed hosts cannot be empty")
        if any(not origin.startswith(("http://", "https://")) for origin in self.cors_origins):
            raise ValueError("CORS origins must be absolute HTTP or HTTPS origins")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> ApiSettings:
        """Load bounded settings without adding a general settings framework."""
        source = os.environ if environ is None else environ
        return cls(
            max_concurrent_scans=_positive_int(
                source, "WEBGUARD_MAX_CONCURRENT_SCANS", 4, 1024
            ),
            scan_timeout_seconds=_positive_float(
                source, "WEBGUARD_SCAN_TIMEOUT_SECONDS", 90.0, 3600.0
            ),
            max_request_body_bytes=_positive_int(
                source, "WEBGUARD_MAX_REQUEST_BODY_BYTES", 4096, 1024 * 1024
            ),
            rate_limit_requests=_positive_int(
                source, "WEBGUARD_RATE_LIMIT_REQUESTS", 10, 100000
            ),
            rate_limit_window_seconds=_positive_float(
                source, "WEBGUARD_RATE_LIMIT_WINDOW_SECONDS", 60.0, 86400.0
            ),
            rate_limit_max_clients=_positive_int(
                source, "WEBGUARD_RATE_LIMIT_MAX_CLIENTS", 4096, 1000000
            ),
            cors_origins=_csv(
                source, "WEBGUARD_CORS_ORIGINS", ("http://localhost:5173",)
            ),
            allowed_hosts=_csv(
                source,
                "WEBGUARD_ALLOWED_HOSTS",
                ("localhost", "127.0.0.1", "testserver"),
            ),
            docs_enabled=_boolean(source, "WEBGUARD_DOCS_ENABLED", True),
        )
