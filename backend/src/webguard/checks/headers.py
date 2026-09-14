"""Conservative HTTP response security-header checks."""

from __future__ import annotations

import re

from webguard.checks.common import finding_result
from webguard.domain.enums import FindingStatus, HttpScheme, Severity
from webguard.scanner.checks import CheckEvaluationError, CheckMetadata, CheckResult
from webguard.scanner.context import ResponseObservation, ScanContext

_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
_FEATURE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
_KNOWN_CSP_DIRECTIVES = frozenset(
    {
        "base-uri",
        "block-all-mixed-content",
        "child-src",
        "connect-src",
        "default-src",
        "font-src",
        "form-action",
        "frame-ancestors",
        "frame-src",
        "img-src",
        "media-src",
        "object-src",
        "plugin-types",
        "referrer",
        "report-to",
        "report-uri",
        "require-trusted-types-for",
        "sandbox",
        "script-src",
        "style-src",
        "trusted-types",
        "upgrade-insecure-requests",
        "worker-src",
    }
)


def _landing(context: ScanContext) -> ResponseObservation:
    response = context.landing_page
    if response is None:
        raise CheckEvaluationError("The landing response was unavailable")
    return response


def _is_html(response: ResponseObservation) -> bool:
    content_type = (response.body.content_type or "").lower()
    if "text/html" in content_type or "application/xhtml+xml" in content_type:
        return True
    prefix = response.body.content[:512].lstrip().lower()
    return prefix.startswith((b"<!doctype html", b"<html"))


def _csp_directive(response: ResponseObservation, name: str) -> tuple[str, ...] | None:
    policies = response.header_values("content-security-policy")
    for policy in policies:
        for raw_directive in policy.split(";"):
            parts = raw_directive.strip().split()
            if parts and parts[0].lower() == name:
                return tuple(part.lower() for part in parts[1:])
    return None


class StrictTransportSecurityCheck:
    metadata = CheckMetadata(
        rule_id="headers.strict_transport_security",
        title="Strict-Transport-Security",
        category="HTTP Security Headers",
        order=100,
        references=(
            _OWASP_HEADERS,
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security",
        ),
    )

    def is_applicable(self, context: ScanContext) -> bool:
        response = context.landing_page
        return response is None or response.target.scheme is HttpScheme.HTTPS

    def evaluate(self, context: ScanContext) -> CheckResult:
        response = _landing(context)
        values = response.header_values("strict-transport-security")
        source = response.target.display_url
        if not values:
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description=(
                    "The final HTTPS response did not declare HSTS. This is missing transport "
                    "hardening, not proof that the site is exploitable."
                ),
                evidence=(
                    "Strict-Transport-Security header was not present on the final HTTPS response."
                ),
                source_url=source,
                recommendation=(
                    "Add HSTS with a tested positive max-age after confirming HTTPS coverage."
                ),
            )
        if len(values) != 1:
            return self._malformed(
                response, "Multiple Strict-Transport-Security fields were present."
            )

        value = values[0]
        max_ages: list[str] = []
        include_subdomains = False
        for directive in value.split(";"):
            name, separator, directive_value = directive.strip().partition("=")
            lowered = name.lower()
            if lowered == "max-age" and separator:
                max_ages.append(directive_value.strip())
            elif lowered == "includesubdomains" and not separator:
                include_subdomains = True
        if len(max_ages) != 1 or not max_ages[0].isdigit():
            return self._malformed(response, f"Strict-Transport-Security: {value}")
        max_age = int(max_ages[0])
        if max_age == 0:
            return finding_result(
                self.metadata,
                status=FindingStatus.FAIL,
                severity=Severity.MEDIUM,
                description="HSTS was explicitly disabled with a zero max-age.",
                evidence=f"Strict-Transport-Security: {value}",
                source_url=source,
                recommendation="Set a positive HSTS max-age after validating HTTPS readiness.",
            )
        subdomain_note = " with includeSubDomains" if include_subdomains else ""
        return finding_result(
            self.metadata,
            status=FindingStatus.PASS,
            description="The HTTPS response declared HSTS with a positive max-age.",
            evidence=f"Strict-Transport-Security max-age={max_age}{subdomain_note}.",
            source_url=source,
            recommendation="Maintain HSTS and review its lifetime during deployment changes.",
        )

    def _malformed(self, response: ResponseObservation, evidence: str) -> CheckResult:
        return finding_result(
            self.metadata,
            status=FindingStatus.WARNING,
            severity=Severity.LOW,
            description="The HSTS field was present but its max-age could not be parsed reliably.",
            evidence=evidence,
            source_url=response.target.display_url,
            recommendation=(
                "Use one Strict-Transport-Security field with a numeric positive max-age."
            ),
        )


class ContentSecurityPolicyCheck:
    metadata = CheckMetadata(
        rule_id="headers.content_security_policy",
        title="Content-Security-Policy",
        category="HTTP Security Headers",
        order=110,
        references=(
            _OWASP_HEADERS,
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP",
        ),
    )

    def is_applicable(self, context: ScanContext) -> bool:
        response = context.landing_page
        return response is None or _is_html(response)

    def evaluate(self, context: ScanContext) -> CheckResult:
        response = _landing(context)
        values = response.header_values("content-security-policy")
        source = response.target.display_url
        if not values:
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.MEDIUM,
                description=(
                    "No enforced CSP was observed on the HTML response. CSP is defense in depth; "
                    "its absence alone does not prove an XSS vulnerability."
                ),
                evidence=(
                    "Content-Security-Policy header was not present on the final HTML response."
                ),
                source_url=source,
                recommendation="Deploy a tested, application-specific Content-Security-Policy.",
            )
        rendered = "; ".join(value.strip() for value in values)
        usable = any(
            parts
            and (
                parts[0].lower() in _KNOWN_CSP_DIRECTIVES
                or parts[0].lower().endswith("-src")
            )
            for value in values
            for directive in value.split(";")
            if (parts := directive.strip().split())
        )
        if not usable:
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.MEDIUM,
                description="The CSP field was empty or did not contain a usable directive.",
                evidence=f"Content-Security-Policy: {rendered or '[empty]'}",
                source_url=source,
                recommendation=(
                    "Define and test explicit CSP directives appropriate to the application."
                ),
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.PASS,
            description=(
                "A non-empty enforced CSP was present. This check does not claim that the policy "
                "fully prevents script injection."
            ),
            evidence=f"Content-Security-Policy: {rendered}",
            source_url=source,
            recommendation="Continue reviewing CSP directives against actual application behavior.",
        )


class XContentTypeOptionsCheck:
    metadata = CheckMetadata(
        rule_id="headers.x_content_type_options",
        title="X-Content-Type-Options",
        category="HTTP Security Headers",
        order=120,
        references=(
            _OWASP_HEADERS,
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options",
        ),
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        response = _landing(context)
        values = response.header_values("x-content-type-options")
        if len(values) == 1 and values[0].strip().lower() == "nosniff":
            return finding_result(
                self.metadata,
                status=FindingStatus.PASS,
                description="The response disables MIME type sniffing with nosniff.",
                evidence="X-Content-Type-Options: nosniff",
                source_url=response.target.display_url,
                recommendation="Continue sending nosniff on relevant responses.",
            )
        missing = not values
        return finding_result(
            self.metadata,
            status=FindingStatus.WARNING,
            severity=Severity.LOW,
            description=(
                "The response did not provide the recognized nosniff value. This is a missing or "
                "malformed hardening control, not proof of exploitable content handling."
            ),
            evidence=(
                "X-Content-Type-Options header was not present."
                if missing
                else f"X-Content-Type-Options: {', '.join(values)}"
            ),
            source_url=response.target.display_url,
            recommendation="Send exactly X-Content-Type-Options: nosniff.",
        )


class ReferrerPolicyCheck:
    metadata = CheckMetadata(
        rule_id="headers.referrer_policy",
        title="Referrer-Policy",
        category="HTTP Security Headers",
        order=130,
        references=(
            _OWASP_HEADERS,
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy",
        ),
    )
    _acceptable = frozenset(
        {
            "no-referrer",
            "origin",
            "origin-when-cross-origin",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
        }
    )
    _weak = frozenset({"no-referrer-when-downgrade", "unsafe-url"})

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        response = _landing(context)
        values = response.header_values("referrer-policy")
        if not values:
            return finding_result(
                self.metadata,
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                description=(
                    "No explicit Referrer-Policy was observed. Browser defaults may still limit "
                    "referrer data, so this is an informational hardening observation."
                ),
                evidence="Referrer-Policy header was not present.",
                source_url=response.target.display_url,
                recommendation="Set an explicit policy suited to the application's privacy needs.",
            )
        candidates = [item.strip().lower() for value in values for item in value.split(",")]
        recognized = [item for item in candidates if item in self._acceptable | self._weak]
        if not recognized:
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description="The explicit Referrer-Policy value was not recognized by this rule.",
                evidence=f"Referrer-Policy: {', '.join(values)}",
                source_url=response.target.display_url,
                recommendation="Use a standardized Referrer-Policy token supported by browsers.",
            )
        effective = recognized[-1]
        if effective in self._weak:
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description=(
                    "The explicit policy can disclose more referrer information than needed."
                ),
                evidence=f"Effective Referrer-Policy token: {effective}",
                source_url=response.target.display_url,
                recommendation="Consider a stricter policy after testing application requirements.",
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.PASS,
            description="The response declared a recognized privacy-conscious referrer policy.",
            evidence=f"Effective Referrer-Policy token: {effective}",
            source_url=response.target.display_url,
            recommendation="Retain the explicit policy and review it when integrations change.",
        )


class PermissionsPolicyCheck:
    metadata = CheckMetadata(
        rule_id="headers.permissions_policy",
        title="Permissions-Policy",
        category="HTTP Security Headers",
        order=140,
        references=(
            _OWASP_HEADERS,
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy",
        ),
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        response = _landing(context)
        values = response.header_values("permissions-policy")
        if not values:
            return finding_result(
                self.metadata,
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                description=(
                    "No Permissions-Policy was observed. This is optional browser-feature "
                    "hardening and is not automatically a significant vulnerability."
                ),
                evidence="Permissions-Policy header was not present.",
                source_url=response.target.display_url,
                recommendation=(
                    "Consider restricting unneeded browser features after application review."
                ),
            )
        value = ", ".join(values).strip()
        directives = [directive.strip() for directive in value.split(",")]
        malformed = not value or any(self._obviously_malformed(item) for item in directives)
        if malformed:
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description=(
                    "The Permissions-Policy field was obviously malformed. This check does not "
                    "judge whether each enabled feature is appropriate."
                ),
                evidence=f"Permissions-Policy: {value or '[empty]'}",
                source_url=response.target.display_url,
                recommendation=(
                    "Use valid feature-name=(allowlist) directives and test browser support."
                ),
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.PASS,
            description=(
                "A syntactically plausible Permissions-Policy was present. The allowed features "
                "were not judged against application intent."
            ),
            evidence=f"Permissions-Policy: {value}",
            source_url=response.target.display_url,
            recommendation="Review each feature allowlist against actual application requirements.",
        )

    @staticmethod
    def _obviously_malformed(directive: str) -> bool:
        feature, separator, allowlist = directive.partition("=")
        return (
            not separator
            or _FEATURE_NAME.fullmatch(feature.strip()) is None
            or (
                allowlist.strip() != "*"
                and (
                    not allowlist.strip().startswith("(")
                    or not allowlist.strip().endswith(")")
                    or allowlist.count("(") != allowlist.count(")")
                )
            )
        )


class ClickjackingProtectionCheck:
    metadata = CheckMetadata(
        rule_id="headers.clickjacking_protection",
        title="Clickjacking framing protection",
        category="HTTP Security Headers",
        order=150,
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors",
        ),
    )

    def is_applicable(self, context: ScanContext) -> bool:
        response = context.landing_page
        return response is None or _is_html(response)

    def evaluate(self, context: ScanContext) -> CheckResult:
        response = _landing(context)
        frame_ancestors = _csp_directive(response, "frame-ancestors")
        source = response.target.display_url
        if frame_ancestors is not None:
            rendered = " ".join(frame_ancestors) or "[empty]"
            if frame_ancestors == ("'none'",):
                return finding_result(
                    self.metadata,
                    status=FindingStatus.PASS,
                    description="CSP frame-ancestors blocks framing by all origins.",
                    evidence="Content-Security-Policy frame-ancestors 'none'.",
                    source_url=source,
                    recommendation="Retain the CSP framing restriction.",
                )
            if "'self'" in frame_ancestors and "*" not in frame_ancestors:
                return finding_result(
                    self.metadata,
                    status=FindingStatus.PASS,
                    description=(
                        "CSP frame-ancestors restricts framing and takes precedence over XFO."
                    ),
                    evidence=f"CSP frame-ancestors {rendered}.",
                    source_url=source,
                    recommendation=(
                        "Keep the explicit CSP allowlist as narrow as application needs permit."
                    ),
                )
            if not frame_ancestors or "*" in frame_ancestors:
                return finding_result(
                    self.metadata,
                    status=FindingStatus.WARNING,
                    severity=Severity.MEDIUM,
                    description=(
                        "CSP frame-ancestors did not provide a meaningful framing restriction."
                    ),
                    evidence=f"CSP frame-ancestors {rendered}.",
                    source_url=source,
                    recommendation=(
                        "Restrict frame-ancestors to none or the required trusted origins."
                    ),
                )
            return finding_result(
                self.metadata,
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                description=(
                    "CSP explicitly controls framing, but WebGuard does not determine whether its "
                    "listed origins are appropriate for this application."
                ),
                evidence=f"CSP frame-ancestors {rendered}.",
                source_url=source,
                recommendation=(
                    "Review frame-ancestors against the intended embedding origins."
                ),
            )

        values = response.header_values("x-frame-options")
        normalized = values[0].strip().upper() if len(values) == 1 else ""
        if normalized == "DENY":
            return finding_result(
                self.metadata,
                status=FindingStatus.PASS,
                description="X-Frame-Options prevents the response from being framed.",
                evidence="X-Frame-Options: DENY",
                source_url=source,
                recommendation="Retain DENY or migrate the restriction to CSP frame-ancestors.",
            )
        if normalized == "SAMEORIGIN":
            return finding_result(
                self.metadata,
                status=FindingStatus.PASS,
                description="X-Frame-Options allows framing only by the same origin.",
                evidence="X-Frame-Options: SAMEORIGIN",
                source_url=source,
                recommendation="Retain SAMEORIGIN if same-origin framing is required.",
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.WARNING,
            severity=Severity.MEDIUM,
            description=(
                "The HTML response lacked a recognized framing restriction. This is a missing "
                "defense and does not alone prove a practical clickjacking exploit."
            ),
            evidence=(
                "Neither CSP frame-ancestors nor X-Frame-Options was present."
                if not values
                else f"X-Frame-Options: {', '.join(values)}"
            ),
            source_url=source,
            recommendation="Set CSP frame-ancestors, or use DENY/SAMEORIGIN as an XFO fallback.",
        )
