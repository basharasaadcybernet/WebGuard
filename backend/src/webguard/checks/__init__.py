"""Explicit production rule set for WebGuard's complete v0.1 passive checks."""

from webguard.checks.config import DEFAULT_RULE_CONFIG, RuleConfig
from webguard.checks.content import MixedContentCheck
from webguard.checks.cookies import CookieHttpOnlyCheck, CookieSameSiteCheck, CookieSecureCheck
from webguard.checks.headers import (
    ClickjackingProtectionCheck,
    ContentSecurityPolicyCheck,
    PermissionsPolicyCheck,
    ReferrerPolicyCheck,
    StrictTransportSecurityCheck,
    XContentTypeOptionsCheck,
)
from webguard.checks.hygiene import (
    SecurityTxtCheck,
    ServerDisclosureCheck,
    XPoweredByDisclosureCheck,
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
    """Build the explicit, deterministically ordered Phase 5B registry."""
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
            CookieSecureCheck(),
            CookieHttpOnlyCheck(),
            CookieSameSiteCheck(),
            MixedContentCheck(),
            SecurityTxtCheck(config=config),
            ServerDisclosureCheck(),
            XPoweredByDisclosureCheck(),
        ),
        ruleset_version="0.1.0-phase5b",
    )


__all__ = [
    "DEFAULT_RULE_CONFIG",
    "ClickjackingProtectionCheck",
    "ContentSecurityPolicyCheck",
    "CookieHttpOnlyCheck",
    "CookieSameSiteCheck",
    "CookieSecureCheck",
    "HTTPRedirectCheck",
    "HTTPSAvailabilityCheck",
    "HTTPSDowngradeCheck",
    "MixedContentCheck",
    "PermissionsPolicyCheck",
    "ReferrerPolicyCheck",
    "RuleConfig",
    "SecurityTxtCheck",
    "ServerDisclosureCheck",
    "StrictTransportSecurityCheck",
    "TLSExpiryCheck",
    "TLSHostnameCheck",
    "TLSValidityCheck",
    "XContentTypeOptionsCheck",
    "XPoweredByDisclosureCheck",
    "default_check_registry",
]
