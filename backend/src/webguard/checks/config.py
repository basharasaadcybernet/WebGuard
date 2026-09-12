"""Configuration shared by WebGuard's real security checks."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuleConfig:
    """Conservative thresholds that affect finding classification."""

    tls_expiry_warning_days: int = 30

    def __post_init__(self) -> None:
        if self.tls_expiry_warning_days < 1:
            raise ValueError("TLS expiration warning threshold must be positive")


DEFAULT_RULE_CONFIG = RuleConfig()
