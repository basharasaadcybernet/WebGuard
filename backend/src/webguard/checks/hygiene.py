"""Passive disclosure-policy and response-banner checks."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from webguard.checks.common import finding_result
from webguard.checks.config import DEFAULT_RULE_CONFIG, RuleConfig
from webguard.domain.enums import FindingStatus, HttpScheme, Severity
from webguard.scanner.checks import (
    AuxiliaryRequest,
    CheckEvaluationError,
    CheckMetadata,
    CheckResult,
)
from webguard.scanner.context import ResponseObservation, ScanContext

_RFC_9116 = "https://www.rfc-editor.org/rfc/rfc9116.html"
_OWASP_INFORMATION_EXPOSURE = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_"
    "Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework"
)
_VERSION_DETAIL = re.compile(r"(?:^|[/\s])v?\d+(?:\.[0-9a-z_-]+)+", re.IGNORECASE)
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)


def _landing(context: ScanContext) -> ResponseObservation:
    response = context.landing_page
    if response is None:
        raise CheckEvaluationError("The landing response was unavailable")
    return response


def _parse_rfc3339(value: str) -> datetime:
    candidate = value.strip()
    if _RFC3339.fullmatch(candidate) is None:
        raise ValueError("Expires is not an RFC 3339 timestamp")
    if candidate.endswith(("z", "Z")):
        candidate = f"{candidate[:-1]}+00:00"
    parsed = datetime.fromisoformat(candidate)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("RFC 3339 timestamp requires an offset")
    return parsed.astimezone(UTC)


class SecurityTxtCheck:
    metadata = CheckMetadata(
        rule_id="hygiene.security_txt",
        title="security.txt disclosure policy",
        category="Security Disclosure",
        order=400,
        references=(_RFC_9116,),
        auxiliary_requests=(
            AuxiliaryRequest(key="security_txt", path="/.well-known/security.txt"),
        ),
    )

    def __init__(self, config: RuleConfig = DEFAULT_RULE_CONFIG) -> None:
        self._config = config

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        probe = context.auxiliary_probe("security_txt")
        if probe is None or probe.failure is not None:
            raise CheckEvaluationError("The protected security.txt observation was unavailable")
        response = probe.final
        if response is None:
            raise CheckEvaluationError("The security.txt observation had no response")
        source = response.target.display_url
        if response.target.scheme is not HttpScheme.HTTPS or probe.observed_https_downgrade:
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description=(
                    "The security.txt request ended on plaintext HTTP. This weakens the integrity "
                    "of disclosure instructions but is not an application vulnerability."
                ),
                evidence="security.txt was not served entirely over HTTPS.",
                source_url=source,
                recommendation="Serve /.well-known/security.txt directly over HTTPS.",
            )
        if response.status_code != 200:
            return finding_result(
                self.metadata,
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                description=(
                    "A successful security.txt response was not found. The file is an optional "
                    "responsible-disclosure maturity signal, not a required vulnerability control."
                ),
                evidence=f"security.txt HTTP status: {response.status_code}.",
                source_url=source,
                recommendation=(
                    "Consider publishing an RFC 9116 security.txt file with Contact and Expires."
                ),
            )
        if response.body.size > self._config.security_txt_max_bytes:
            raise CheckEvaluationError("The security.txt response exceeded the rule parsing limit")
        content_type = (response.body.content_type or "").lower()
        if not content_type.startswith("text/plain"):
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description=(
                    "The security.txt resource was successful but was not served as text/plain, "
                    "as RFC 9116 specifies."
                ),
                evidence="security.txt Content-Type was absent or was not text/plain.",
                source_url=source,
                recommendation="Serve the UTF-8 file with a text/plain Content-Type.",
            )
        try:
            text = response.body.content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description=(
                    "The security.txt response was not valid UTF-8 text as RFC 9116 expects."
                ),
                evidence=f"security.txt response bytes: {response.body.size}; UTF-8: invalid.",
                source_url=source,
                recommendation="Publish security.txt as UTF-8 text following RFC 9116.",
            )

        fields: dict[str, list[str]] = {}
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            name, separator, value = stripped.partition(":")
            if separator:
                fields.setdefault(name.strip().lower(), []).append(value.strip())
        contacts = tuple(value for value in fields.get("contact", ()) if value)
        expires_values = tuple(value for value in fields.get("expires", ()) if value)
        if not contacts or len(expires_values) != 1:
            missing = []
            if not contacts:
                missing.append("Contact")
            if not expires_values:
                missing.append("Expires")
            elif len(expires_values) > 1:
                missing.append("one unambiguous Expires")
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description=(
                    "The security.txt response lacked the minimum unambiguous Contact and Expires "
                    "fields needed by this RFC 9116-oriented check."
                ),
                evidence=(
                    f"Contact fields: {len(contacts)}; Expires fields: {len(expires_values)}; "
                    f"needed: {', '.join(missing)}."
                ),
                source_url=source,
                recommendation="Publish at least one Contact and exactly one future Expires field.",
            )
        try:
            expires = _parse_rfc3339(expires_values[0])
        except ValueError:
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description=(
                    "The security.txt Expires value was not a parseable RFC 3339 timestamp."
                ),
                evidence=f"Contact fields: {len(contacts)}; Expires: malformed.",
                source_url=source,
                recommendation="Use a timezone-aware RFC 3339 timestamp for Expires.",
            )
        if expires <= context.observations_finished_at.astimezone(UTC):
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.LOW,
                description="The published security.txt disclosure information had expired.",
                evidence=(
                    f"Contact fields: {len(contacts)}; Expires: {expires.isoformat()}; "
                    "state: expired."
                ),
                source_url=source,
                recommendation=(
                    "Review the disclosure instructions and publish a future Expires date."
                ),
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.PASS,
            description=(
                "The HTTPS security.txt response contained Contact and a future, parseable Expires "
                "field. Referenced contacts were treated as text and were not fetched."
            ),
            evidence=(
                f"Contact fields: {len(contacts)}; Expires: {expires.isoformat()}; state: current."
            ),
            source_url=source,
            recommendation=(
                "Keep disclosure contacts monitored and refresh Expires before it lapses."
            ),
        )


class ServerDisclosureCheck:
    metadata = CheckMetadata(
        rule_id="hygiene.server_disclosure",
        title="Server header disclosure",
        category="Information Disclosure",
        order=410,
        references=(_OWASP_INFORMATION_EXPOSURE,),
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        response = _landing(context)
        values = response.header_values("server")
        if not values:
            return finding_result(
                self.metadata,
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                description=(
                    "No Server field was observed. Absence of a banner does not prove that the "
                    "underlying technology is hidden or secure."
                ),
                evidence="Server header was not present on the final response.",
                source_url=response.target.display_url,
                recommendation="No action is suggested from this observation alone.",
            )
        rendered = ", ".join(values)
        detailed = any(_VERSION_DETAIL.search(value) is not None for value in values)
        return finding_result(
            self.metadata,
            status=FindingStatus.WARNING if detailed else FindingStatus.INFO,
            severity=Severity.LOW if detailed else Severity.INFO,
            description=(
                "The Server field exposed explicit version-like detail that may aid inventorying, "
                "but it is not itself an exploitable vulnerability."
                if detailed
                else (
                    "A generic Server field was observed. Its presence is an informational banner, "
                    "not evidence of an exploitable vulnerability."
                )
            ),
            evidence=f"Server: {rendered}",
            source_url=response.target.display_url,
            recommendation=(
                "Remove unnecessary version detail where operationally practical; maintain and "
                "patch the actual server independently of banner text."
                if detailed
                else "Keep the underlying service patched; hiding a generic banner is optional."
            ),
        )


class XPoweredByDisclosureCheck:
    metadata = CheckMetadata(
        rule_id="hygiene.x_powered_by",
        title="X-Powered-By disclosure",
        category="Information Disclosure",
        order=420,
        references=(_OWASP_INFORMATION_EXPOSURE,),
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        response = _landing(context)
        values = response.header_values("x-powered-by")
        if not values:
            return finding_result(
                self.metadata,
                status=FindingStatus.INFO,
                severity=Severity.INFO,
                description=(
                    "No X-Powered-By field was observed. This does not prove that application "
                    "technology cannot be identified by other means."
                ),
                evidence="X-Powered-By header was not present on the final response.",
                source_url=response.target.display_url,
                recommendation="No action is suggested from this observation alone.",
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.INFO,
            severity=Severity.INFO,
            description=(
                "The response explicitly named implementation technology in X-Powered-By. This is "
                "informational and is not matched to vulnerabilities or treated as an exploit."
            ),
            evidence=f"X-Powered-By: {', '.join(values)}",
            source_url=response.target.display_url,
            recommendation="Remove the field if it is unnecessary, and patch the actual software.",
        )
