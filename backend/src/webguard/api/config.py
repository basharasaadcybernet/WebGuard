"""Environment-backed, conservative API process settings."""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal
from urllib.parse import urlsplit

API_VERSION: Final[Literal["v1"]] = "v1"
API_SCHEMA_VERSION: Final[Literal["1.0"]] = "1.0"
_LOG_LEVELS: Final = frozenset({"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"})
_HOST_PATTERN: Final = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


class RuntimeEnvironment(StrEnum):
    """Supported runtime profiles."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


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


def _csv(
    source: Mapping[str, str],
    name: str,
    default: tuple[str, ...],
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    raw = source.get(name)
    if raw is None:
        return default
    values = tuple(dict.fromkeys(part.strip() for part in raw.split(",") if part.strip()))
    if not values and not allow_empty:
        raise ValueError(f"{name} must contain at least one value")
    return values


def _runtime_environment(source: Mapping[str, str]) -> RuntimeEnvironment:
    raw = source.get("WEBGUARD_ENV", RuntimeEnvironment.DEVELOPMENT.value).strip().lower()
    try:
        return RuntimeEnvironment(raw)
    except ValueError as exc:
        raise ValueError("WEBGUARD_ENV must be development, test, or production") from exc


def _log_level(source: Mapping[str, str]) -> str:
    value = source.get("WEBGUARD_LOG_LEVEL", "INFO").strip().upper()
    if value not in _LOG_LEVELS:
        raise ValueError("WEBGUARD_LOG_LEVEL must be CRITICAL, ERROR, WARNING, INFO, or DEBUG")
    return value


def _valid_origin(origin: str) -> bool:
    try:
        parsed = urlsplit(origin)
        port = parsed.port
        return (
            parsed.scheme in {"http", "https"}
            and parsed.hostname is not None
            and "*" not in origin
            and _valid_host(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
            and (port is None or 1 <= port <= 65535)
        )
    except ValueError:
        return False


def _valid_host(host: str) -> bool:
    if not host or "://" in host or "/" in host or "*" in host:
        return False
    normalized = host.rstrip(".")
    try:
        ipaddress.ip_address(normalized)
        return True
    except ValueError:
        return _HOST_PATTERN.fullmatch(normalized) is not None


def _valid_proxy(proxy: str) -> bool:
    if proxy == "*":
        return False
    try:
        ipaddress.ip_network(proxy, strict=False)
        return True
    except ValueError:
        return False


def _public_hostname(host: str) -> bool:
    normalized = host.rstrip(".").lower()
    try:
        ipaddress.ip_address(normalized)
        return False
    except ValueError:
        return "." in normalized and normalized not in {"localhost", "testserver"}


@dataclass(frozen=True, slots=True)
class ApiSettings:
    """Small process-local policy surface; scanner security is not configurable here."""

    environment: RuntimeEnvironment = RuntimeEnvironment.DEVELOPMENT
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    debug: bool = False
    log_level: str = "INFO"
    max_concurrent_scans: int = 4
    scan_timeout_seconds: float = 90.0
    max_request_body_bytes: int = 4096
    rate_limit_requests: int = 10
    rate_limit_window_seconds: float = 60.0
    rate_limit_max_clients: int = 4096
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)
    allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "testserver")
    trusted_proxies: tuple[str, ...] = ()
    docs_enabled: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.environment, RuntimeEnvironment):
            raise ValueError("environment must be a RuntimeEnvironment")
        positive_values = {
            "bind_port": self.bind_port,
            "max_concurrent_scans": self.max_concurrent_scans,
            "scan_timeout_seconds": self.scan_timeout_seconds,
            "max_request_body_bytes": self.max_request_body_bytes,
            "rate_limit_requests": self.rate_limit_requests,
            "rate_limit_window_seconds": self.rate_limit_window_seconds,
            "rate_limit_max_clients": self.rate_limit_max_clients,
        }
        if any(value <= 0 for value in positive_values.values()):
            raise ValueError("API numeric settings must be positive")
        maximum_values = {
            "bind_port": (self.bind_port, 65535),
            "max_concurrent_scans": (self.max_concurrent_scans, 64),
            "scan_timeout_seconds": (self.scan_timeout_seconds, 300),
            "max_request_body_bytes": (self.max_request_body_bytes, 64 * 1024),
            "rate_limit_requests": (self.rate_limit_requests, 1000),
            "rate_limit_window_seconds": (self.rate_limit_window_seconds, 3600),
            "rate_limit_max_clients": (self.rate_limit_max_clients, 100000),
        }
        exceeded = [name for name, (value, maximum) in maximum_values.items() if value > maximum]
        if exceeded:
            raise ValueError("API numeric settings exceed safe maxima: " + ", ".join(exceeded))
        if self.bind_host != self.bind_host.strip() or not _valid_host(self.bind_host):
            raise ValueError("bind_host must be a non-empty host or address")
        if self.log_level not in _LOG_LEVELS:
            raise ValueError("log_level is invalid")
        if not self.allowed_hosts or any(not _valid_host(host) for host in self.allowed_hosts):
            raise ValueError("Allowed hosts must be explicit hostnames or IP addresses")
        if not self.cors_origins and self.environment is not RuntimeEnvironment.PRODUCTION:
            raise ValueError("CORS origins cannot be empty outside production")
        if any(not _valid_origin(origin) for origin in self.cors_origins):
            raise ValueError("CORS origins must be exact HTTP or HTTPS origins")
        if any(not _valid_proxy(proxy) for proxy in self.trusted_proxies):
            raise ValueError(
                "WEBGUARD_TRUSTED_PROXIES must contain explicit IP addresses or CIDR networks"
            )
        if self.environment is RuntimeEnvironment.PRODUCTION:
            if self.debug:
                raise ValueError("Debug mode is not permitted in production")
            if self.log_level == "DEBUG":
                raise ValueError("DEBUG logging is not permitted in production")
            if any(origin.startswith("http://") for origin in self.cors_origins):
                raise ValueError("Production CORS origins must use HTTPS")
            if any(not _public_hostname(host) for host in self.allowed_hosts):
                raise ValueError("Production allowed hosts must be explicit public hostnames")
            if any(
                not _public_hostname(urlsplit(origin).hostname or "")
                for origin in self.cors_origins
            ):
                raise ValueError("Production CORS origins must use public hostnames")

    @property
    def trust_forwarded_headers(self) -> bool:
        """Whether Uvicorn may honor proxy headers from configured peers."""
        return bool(self.trusted_proxies)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> ApiSettings:
        """Load bounded settings without adding a general settings framework."""
        source = os.environ if environ is None else environ
        environment = _runtime_environment(source)
        if environment is RuntimeEnvironment.PRODUCTION:
            required = ("WEBGUARD_BIND_HOST", "WEBGUARD_ALLOWED_HOSTS", "WEBGUARD_CORS_ORIGINS")
            missing = [name for name in required if name not in source]
            if missing:
                raise ValueError(
                    "Production configuration requires explicit values for " + ", ".join(missing)
                )
        return cls(
            environment=environment,
            bind_host=source.get("WEBGUARD_BIND_HOST", "127.0.0.1").strip(),
            bind_port=_positive_int(source, "WEBGUARD_BIND_PORT", 8000, 65535),
            debug=_boolean(source, "WEBGUARD_DEBUG", False),
            log_level=_log_level(source),
            max_concurrent_scans=_positive_int(
                source, "WEBGUARD_MAX_CONCURRENT_SCANS", 4, 64
            ),
            scan_timeout_seconds=_positive_float(
                source, "WEBGUARD_SCAN_TIMEOUT_SECONDS", 90.0, 300.0
            ),
            max_request_body_bytes=_positive_int(
                source, "WEBGUARD_MAX_REQUEST_BODY_BYTES", 4096, 64 * 1024
            ),
            rate_limit_requests=_positive_int(
                source, "WEBGUARD_RATE_LIMIT_REQUESTS", 10, 1000
            ),
            rate_limit_window_seconds=_positive_float(
                source, "WEBGUARD_RATE_LIMIT_WINDOW_SECONDS", 60.0, 3600.0
            ),
            rate_limit_max_clients=_positive_int(
                source, "WEBGUARD_RATE_LIMIT_MAX_CLIENTS", 4096, 100000
            ),
            cors_origins=_csv(
                source,
                "WEBGUARD_CORS_ORIGINS",
                ("http://localhost:5173",),
                allow_empty=environment is RuntimeEnvironment.PRODUCTION,
            ),
            allowed_hosts=_csv(
                source,
                "WEBGUARD_ALLOWED_HOSTS",
                ("localhost", "127.0.0.1", "testserver"),
            ),
            trusted_proxies=_csv(
                source, "WEBGUARD_TRUSTED_PROXIES", (), allow_empty=True
            ),
            docs_enabled=_boolean(
                source,
                "WEBGUARD_DOCS_ENABLED",
                environment is not RuntimeEnvironment.PRODUCTION,
            ),
        )
