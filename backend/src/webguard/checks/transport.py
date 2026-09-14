"""Passive transport-security checks over centrally collected observations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from webguard.checks.common import finding_result
from webguard.checks.config import DEFAULT_RULE_CONFIG, RuleConfig
from webguard.domain.enums import FindingStatus, HttpScheme, Severity
from webguard.scanner.checks import CheckEvaluationError, CheckMetadata, CheckResult
from webguard.scanner.context import ProbeObservation, ResponseObservation, ScanContext

_TLS_REFERENCE = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    "https://www.rfc-editor.org/rfc/rfc5280",
)
_HTTPS_REFERENCE = ("https://developer.mozilla.org/en-US/docs/Glossary/HTTPS",)
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_HTTPS_UNAVAILABLE_FAILURES = frozenset(
    {
        "network.connection_refused",
        "network.connection_timeout",
        "network.connection_terminated",
        "network.dns_resolution_failed",
        "tls.certificate_expired",
        "tls.certificate_untrusted",
        "tls.handshake_failed",
        "tls.hostname_mismatch",
    }
)


def _probe_source(probe: ProbeObservation) -> str:
    final = probe.final
    return final.target.display_url if final is not None else probe.requested_target.display_url


def _verified_https_response(probe: ProbeObservation) -> ResponseObservation | None:
    return next(
        (
            response
            for response in reversed(probe.responses)
            if response.target.scheme is HttpScheme.HTTPS
        ),
        None,
    )


class HTTPSAvailabilityCheck:
    metadata = CheckMetadata(
        rule_id="transport.https_available",
        title="HTTPS availability",
        category="Transport Security",
        order=10,
        references=_HTTPS_REFERENCE,
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        probe = context.https_probe
        source = _probe_source(probe)
        verified_response = _verified_https_response(probe)
        if probe.succeeded and verified_response is not None:
            return finding_result(
                self.metadata,
                status=FindingStatus.PASS,
                description="A protected request completed successfully over verified HTTPS.",
                evidence=(
                    f"Verified HTTPS response received with status {verified_response.status_code}."
                ),
                source_url=source,
                recommendation="Continue serving the site over verified HTTPS.",
            )
        failure = probe.failure
        if failure is None or failure.code not in _HTTPS_UNAVAILABLE_FAILURES:
            raise CheckEvaluationError("HTTPS availability could not be determined")
        return finding_result(
            self.metadata,
            status=FindingStatus.FAIL,
            severity=Severity.MEDIUM,
            description=(
                "WebGuard could not obtain a verified HTTPS response during this scan. This may "
                "reflect transport configuration or temporary availability, not exploitation."
            ),
            evidence="No verified HTTPS response was available to the scanner.",
            source_url=source,
            recommendation=(
                "Provide a reachable HTTPS endpoint with a certificate trusted for this hostname, "
                "then repeat the scan."
            ),
        )


class HTTPRedirectCheck:
    metadata = CheckMetadata(
        rule_id="transport.http_redirect",
        title="HTTP to HTTPS redirect",
        category="Transport Security",
        order=20,
        references=_HTTPS_REFERENCE,
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        probe = context.http_probe
        if not probe.succeeded:
            raise CheckEvaluationError("HTTP redirect probe did not complete")
        response = probe.responses[0]
        locations = response.header_values("location")
        source = response.target.display_url
        if (
            response.status_code in _REDIRECT_STATUSES
            and len(locations) == 1
            and locations[0].lower().startswith("https://")
        ):
            return finding_result(
                self.metadata,
                status=FindingStatus.PASS,
                description="The HTTP endpoint directs clients toward HTTPS.",
                evidence=f"HTTP {response.status_code} Location: {locations[0]}",
                source_url=source,
                recommendation="Keep the HTTP-to-HTTPS redirect direct and consistently available.",
            )
        if response.status_code in _REDIRECT_STATUSES and len(locations) == 1:
            evidence = f"HTTP {response.status_code} Location: {locations[0]}"
        else:
            evidence = f"HTTP response remained available with status {response.status_code}."
        return finding_result(
            self.metadata,
            status=FindingStatus.FAIL,
            severity=Severity.MEDIUM,
            description=(
                "The tested HTTP endpoint did not direct clients to HTTPS. This weakens automatic "
                "transport upgrade but does not by itself prove interception."
            ),
            evidence=evidence,
            source_url=source,
            recommendation="Redirect HTTP requests directly to the equivalent HTTPS location.",
        )


class TLSValidityCheck:
    metadata = CheckMetadata(
        rule_id="transport.tls_validity",
        title="TLS certificate trust",
        category="Transport Security",
        order=30,
        references=_TLS_REFERENCE,
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        probe = context.https_probe
        if _verified_https_response(probe) is not None:
            return finding_result(
                self.metadata,
                status=FindingStatus.PASS,
                description="The verified TLS connection established a trusted certificate chain.",
                evidence="Certificate trust validation completed successfully.",
                source_url=_probe_source(probe),
                recommendation="Continue using a certificate chain trusted by major clients.",
            )
        if probe.failure is None or probe.failure.code != "tls.certificate_untrusted":
            raise CheckEvaluationError("TLS certificate trust could not be evaluated")
        return finding_result(
            self.metadata,
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
            description=(
                "The TLS certificate chain was not trusted by the scanner's system trust store. "
                "Clients may reject the connection."
            ),
            evidence="TLS certificate chain validation did not establish trust.",
            source_url=_probe_source(probe),
            recommendation="Install a complete certificate chain issued by a trusted authority.",
        )


class TLSHostnameCheck:
    metadata = CheckMetadata(
        rule_id="transport.tls_hostname",
        title="TLS certificate hostname",
        category="Transport Security",
        order=40,
        references=_TLS_REFERENCE,
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        probe = context.https_probe
        if _verified_https_response(probe) is not None:
            return finding_result(
                self.metadata,
                status=FindingStatus.PASS,
                description="The certificate identity matched the requested hostname.",
                evidence="TLS hostname validation completed successfully.",
                source_url=_probe_source(probe),
                recommendation="Keep certificate names aligned with every served HTTPS hostname.",
            )
        if probe.failure is None or probe.failure.code != "tls.hostname_mismatch":
            raise CheckEvaluationError("TLS hostname validation could not be evaluated")
        return finding_result(
            self.metadata,
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
            description="The presented TLS certificate did not match the requested hostname.",
            evidence="TLS certificate hostname validation failed.",
            source_url=_probe_source(probe),
            recommendation="Issue and install a certificate that covers the requested hostname.",
        )


@dataclass(frozen=True, slots=True)
class TLSExpiryCheck:
    config: RuleConfig = DEFAULT_RULE_CONFIG
    metadata = CheckMetadata(
        rule_id="transport.tls_expiry",
        title="TLS certificate expiration",
        category="Transport Security",
        order=50,
        references=_TLS_REFERENCE,
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        probe = context.https_probe
        if probe.failure is not None and probe.failure.code == "tls.certificate_expired":
            return finding_result(
                self.metadata,
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                description="TLS validation reported that the certificate had expired.",
                evidence="The certificate was expired at the time of the scan.",
                source_url=_probe_source(probe),
                recommendation="Renew and deploy the certificate, including its required chain.",
            )
        if not probe.succeeded:
            raise CheckEvaluationError("TLS certificate expiration could not be evaluated")
        https_response = _verified_https_response(probe)
        assert https_response is not None
        not_after = https_response.network.certificate_not_after
        if not_after is None:
            raise CheckEvaluationError("Certificate expiration metadata was unavailable")
        remaining = not_after - context.observations_finished_at
        evidence = f"Certificate expires at {not_after.isoformat()}."
        if remaining <= timedelta(0):
            return finding_result(
                self.metadata,
                status=FindingStatus.FAIL,
                severity=Severity.HIGH,
                description="The observed certificate expiration time has passed.",
                evidence=evidence,
                source_url=_probe_source(probe),
                recommendation="Renew and deploy the certificate immediately.",
            )
        if remaining <= timedelta(days=self.config.tls_expiry_warning_days):
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.MEDIUM,
                description=(
                    "The TLS certificate is approaching expiration within the configured "
                    f"{self.config.tls_expiry_warning_days}-day warning window."
                ),
                evidence=evidence,
                source_url=_probe_source(probe),
                recommendation="Schedule certificate renewal before the expiration date.",
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.PASS,
            description="The TLS certificate is outside the configured expiration warning window.",
            evidence=evidence,
            source_url=_probe_source(probe),
            recommendation="Continue monitoring certificate renewal dates.",
        )


class HTTPSDowngradeCheck:
    metadata = CheckMetadata(
        rule_id="transport.https_downgrade",
        title="HTTPS redirect downgrade",
        category="Transport Security",
        order=60,
        references=_TLS_REFERENCE,
    )

    def is_applicable(self, context: ScanContext) -> bool:
        return True

    def evaluate(self, context: ScanContext) -> CheckResult:
        if not any(
            response.target.scheme is HttpScheme.HTTPS
            for response in (*context.landing.responses, *context.https_probe.responses)
        ):
            raise CheckEvaluationError("HTTPS redirect observations were unavailable")
        if context.observed_https_downgrade:
            return finding_result(
                self.metadata,
                status=FindingStatus.WARNING,
                severity=Severity.MEDIUM,
                description=(
                    "A validated redirect moved from HTTPS to HTTP. This reduces transport "
                    "protection but is not proof that traffic was compromised."
                ),
                evidence="The redirect chain contained an HTTPS-to-HTTP transition.",
                source_url=context.target.display_url,
                recommendation="Keep redirects and final destinations on HTTPS.",
            )
        return finding_result(
            self.metadata,
            status=FindingStatus.PASS,
            description="No HTTPS-to-HTTP transition was observed in the validated redirect chain.",
            evidence="The observed HTTPS redirect path did not downgrade to HTTP.",
            source_url=context.target.display_url,
            recommendation="Continue keeping HTTPS navigation on encrypted destinations.",
        )
