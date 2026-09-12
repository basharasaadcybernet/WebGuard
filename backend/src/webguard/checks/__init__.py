"""Explicit production rule set for WebGuard Phase 5A."""

from webguard.checks.config import DEFAULT_RULE_CONFIG, RuleConfig
from webguard.checks.headers import (
    ClickjackingProtectionCheck,
    ContentSecurityPolicyCheck,
    PermissionsPolicyCheck,
    ReferrerPolicyCheck,
    StrictTransportSecurityCheck,
    XContentTypeOptionsCheck,
)
from webguard.checks.transport import (
    HTTPRedirectCheck,
    HTTPSAvailabilityCheck,
    HTTPSDowngradeCheck,
    TLSExpiryCheck,
    TLSHostnameCheck,
    TLSValidityCheck,
)
from webguard.scanner.registry import CheckRegistry


def default_check_registry(config: RuleConfig = DEFAULT_RULE_CONFIG) -> CheckRegistry:
    """Build the explicit, deterministically ordered Phase 5A registry."""
    return CheckRegistry(
        (
            HTTPSAvailabilityCheck(),
            HTTPRedirectCheck(),
            TLSValidityCheck(),
            TLSHostnameCheck(),
            TLSExpiryCheck(config=config),
            HTTPSDowngradeCheck(),
            StrictTransportSecurityCheck(),
            ContentSecurityPolicyCheck(),
            XContentTypeOptionsCheck(),
            ReferrerPolicyCheck(),
            PermissionsPolicyCheck(),
            ClickjackingProtectionCheck(),
        ),
        ruleset_version="0.1.0-phase5a",
    )


__all__ = [
    "DEFAULT_RULE_CONFIG",
    "ClickjackingProtectionCheck",
    "ContentSecurityPolicyCheck",
    "HTTPRedirectCheck",
    "HTTPSAvailabilityCheck",
    "HTTPSDowngradeCheck",
    "PermissionsPolicyCheck",
    "ReferrerPolicyCheck",
    "RuleConfig",
    "StrictTransportSecurityCheck",
    "TLSExpiryCheck",
    "TLSHostnameCheck",
    "TLSValidityCheck",
    "XContentTypeOptionsCheck",
    "default_check_registry",
]
