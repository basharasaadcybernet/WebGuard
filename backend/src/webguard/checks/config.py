"""Configuration shared by WebGuard's real security checks."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuleConfig:
    """Conservative thresholds that affect finding classification."""

    tls_expiry_warning_days: int = 30
    security_txt_max_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        if self.tls_expiry_warning_days < 1:
            raise ValueError("TLS expiration warning threshold must be positive")
        if not 1024 <= self.security_txt_max_bytes <= 1024 * 1024:
            raise ValueError("security.txt parsing limit must be between 1 KiB and 1 MiB")


DEFAULT_RULE_CONFIG = RuleConfig()
