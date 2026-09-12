"""Conservative checks for cookie attributes observed in the landing chain."""

from __future__ import annotations

from dataclasses import dataclass

from webguard.checks.common import finding_result
from webguard.domain.enums import FindingStatus, HttpScheme, Severity
from webguard.scanner.checks import CheckMetadata, CheckResult
from webguard.scanner.context import ScanContext

_COOKIE_REFERENCE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies"


@dataclass(frozen=True, slots=True)
class _Cookie:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    observed_over_https: bool
    source_url: str


def _observed_cookies(context: ScanContext) -> tuple[_Cookie, ...]:
    cookies: list[_Cookie] = []
    for response in context.redirect_chain:
        for value in response.header_values("set-cookie"):
            parts = [part.strip() for part in value.split(";")]
            name, separator, redacted_value = parts[0].partition("=")
            if not separator or redacted_value != "[redacted]":
                continue
            attributes: dict[str, str | None] = {}
            for raw_attribute in parts[1:]:
                attribute, has_value, attribute_value = raw_attribute.partition("=")
                attributes[attribute.strip().lower()] = (
                    attribute_value.strip().lower() if has_value else None
                )
            cookies.append(
                _Cookie(
                    name=name or "cookie",
                    secure="secure" in attributes,
                    http_only="httponly" in attributes,
                    same_site=attributes.get("samesite"),
                    observed_over_https=response.target.scheme is HttpScheme.HTTPS,
                    source_url=response.target.display_url,
                )
            )
    return tuple(cookies)


def _grouped_evidence(label: str, affected: tuple[_Cookie, ...], total: int) -> str:
    names = sorted({cookie.name for cookie in affected}, key=str.casefold)
    shown = names[:12]
    suffix = f", plus {len(names) - len(shown)} more" if len(names) > len(shown) else ""
    return (
        f"{label}: {', '.join(shown)}{suffix}. Affected observations: {len(affected)} of {total}."
    )


def _source(cookies: tuple[_Cookie, ...], context: ScanContext) -> str:
    return cookies[0].source_url if cookies else context.target.display_url


class CookieSecureCheck:
    metadata = CheckMetadata(
        rule_id="cookies.secure",
        title="Cookie Secure attribute",
        category="Cookie Security",
        order=200,
        references=(_COOKIE_REFERENCE,),
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return context.landing_page is not None

    def evaluate(self, context: ScanContext) -> CheckResult:
        cookies = _observed_cookies(context)
        source = _source(cookies, context)
        if not cookies:
            return finding_result(
                self.metadata,
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                description=(
                    "No Set-Cookie fields were observed in the validated landing chain, so this "
                    "attribute check was not applicable and awards no security credit."
                ),
                evidence="No cookies were observed in the landing response or redirect chain.",
                source_url=source,
                recommendation="No action is suggested from this observation alone.",
            )
        https_cookies = tuple(cookie for cookie in cookies if cookie.observed_over_https)
        if not https_cookies:
            return finding_result(
                self.metadata,
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                description="No cookie was set by an HTTPS response, so Secure was not assessed.",
                evidence=f"Observed cookies: {len(cookies)}; cookies set over HTTPS: 0.",
                source_url=source,
                recommendation=(
                    "Set sensitive cookies only over HTTPS and apply Secure as appropriate."
                ),
            )
        affected = tuple(cookie for cookie in https_cookies if not cookie.secure)
        if affected:
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description=(
                    "One or more cookies set over HTTPS omitted Secure. This is a transport "
                    "hardening concern; WebGuard does not infer that each cookie is sensitive."
                ),
                evidence=_grouped_evidence("Cookies missing Secure", affected, len(https_cookies)),
                source_url=affected[0].source_url,
                recommendation=(
                    "Apply Secure to cookies that should never be sent over plaintext HTTP."
                ),
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.PASS,
            description="Every cookie observed on an HTTPS response declared Secure.",
            evidence=(
                f"HTTPS cookie observations with Secure: {len(https_cookies)} of "
                f"{len(https_cookies)}."
            ),
            source_url=source,
            recommendation="Retain Secure on cookies intended for HTTPS-only transport.",
        )


class CookieHttpOnlyCheck:
    metadata = CheckMetadata(
        rule_id="cookies.http_only",
        title="Cookie HttpOnly attribute",
        category="Cookie Security",
        order=210,
        references=(_COOKIE_REFERENCE,),
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return context.landing_page is not None

    def evaluate(self, context: ScanContext) -> CheckResult:
        cookies = _observed_cookies(context)
        source = _source(cookies, context)
        if not cookies:
            return finding_result(
                self.metadata,
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                description=(
                    "No cookies were observed, so HttpOnly was not applicable and awards no "
                    "security credit."
                ),
                evidence="No cookies were observed in the landing response or redirect chain.",
                source_url=source,
                recommendation="No action is suggested from this observation alone.",
            )
        affected = tuple(cookie for cookie in cookies if not cookie.http_only)
        if affected:
            return finding_result(
                self.metadata,
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                description=(
                    "Some cookies omitted HttpOnly. This is informational because cookies used by "
                    "client-side code may intentionally be JavaScript-accessible, and the scan "
                    "does not determine each cookie's purpose."
                ),
                evidence=_grouped_evidence("Cookies missing HttpOnly", affected, len(cookies)),
                source_url=affected[0].source_url,
                recommendation="Apply HttpOnly to cookies that do not require JavaScript access.",
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.PASS,
            description="Every observed cookie declared HttpOnly.",
            evidence=f"Cookie observations with HttpOnly: {len(cookies)} of {len(cookies)}.",
            source_url=source,
            recommendation="Retain HttpOnly where client-side scripts do not need the cookie.",
        )


class CookieSameSiteCheck:
    metadata = CheckMetadata(
        rule_id="cookies.same_site",
        title="Cookie SameSite attribute",
        category="Cookie Security",
        order=220,
        references=(_COOKIE_REFERENCE,),
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return context.landing_page is not None

    def evaluate(self, context: ScanContext) -> CheckResult:
        cookies = _observed_cookies(context)
        source = _source(cookies, context)
        if not cookies:
            return finding_result(
                self.metadata,
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                description=(
                    "No cookies were observed, so SameSite was not applicable and awards no "
                    "security credit."
                ),
                evidence="No cookies were observed in the landing response or redirect chain.",
                source_url=source,
                recommendation="No action is suggested from this observation alone.",
            )
        missing = tuple(cookie for cookie in cookies if cookie.same_site is None)
        none_without_secure = tuple(
            cookie for cookie in cookies if cookie.same_site == "none" and not cookie.secure
        )
        if missing or none_without_secure:
            parts: list[str] = []
            if missing:
                parts.append(_grouped_evidence("Cookies missing SameSite", missing, len(cookies)))
            if none_without_secure:
                parts.append(
                    _grouped_evidence(
                        "Cookies using SameSite=None without Secure",
                        none_without_secure,
                        len(cookies),
                    )
                )
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description=(
                    "One or more cookies lacked explicit cross-site handling, or combined "
                    "SameSite=None without Secure. This is CSRF-related hardening evidence, not "
                    "proof of a CSRF vulnerability."
                ),
                evidence=" ".join(parts),
                source_url=(missing or none_without_secure)[0].source_url,
                recommendation=(
                    "Choose Strict, Lax, or None deliberately for each cookie; pair None with "
                    "Secure."
                ),
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.PASS,
            description=(
                "Every observed cookie declared Strict, Lax, or a Secure-backed None SameSite "
                "value."
            ),
            evidence=(
                "Cookie observations with an explicit usable SameSite value: "
                f"{len(cookies)} of {len(cookies)}."
            ),
            source_url=source,
            recommendation=(
                "Retain deliberate SameSite settings and review them with request flows."
            ),
        )
