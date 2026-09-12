"""Deterministic scan lifecycle and check failure isolation."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import ValidationError

from webguard import __version__
from webguard.domain.enums import FindingStatus, HttpScheme, ScanErrorKind, ScanState
from webguard.domain.models import (
    Finding,
    NormalizedTarget,
    ScanError,
    ScanMetadata,
    ScanRequest,
    ScanResult,
)
from webguard.scanner.checks import AuxiliaryRequest, CheckEvaluationError, CheckResult
from webguard.scanner.context import (
    AuxiliaryObservation,
    ProbeFailure,
    ProbeObservation,
    build_probe_observation,
    build_scan_context,
)
from webguard.scanner.network import SafeFetchClient, ScanNetworkService
from webguard.scanner.registry import CheckRegistry
from webguard.security.budget import RequestBudget
from webguard.security.client import SafeFetchResult, SafeHttpClient
from webguard.security.config import NetworkLimits
from webguard.security.errors import (
    EndpointUnavailable,
    SecurityBoundaryError,
    TLSCertificateExpired,
    TLSCertificateUntrusted,
    TLSHostnameMismatch,
    URLPolicyError,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class _Attempt:
    observation: ProbeObservation
    raw_result: SafeFetchResult | None


class ScanEngine:
    """Collect safe observations, execute checks in order, and build a public result."""

    def __init__(
        self,
        *,
        registry: CheckRegistry | None = None,
        client: SafeFetchClient | None = None,
        limits: NetworkLimits | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if registry is None:
            from webguard.checks import default_check_registry

            registry = default_check_registry()
        self._registry = registry
        self._limits = limits or NetworkLimits()
        self._client = client or SafeHttpClient(limits=self._limits)
        self._clock = clock

    async def scan(self, request: ScanRequest) -> ScanResult:
        started_at = self._clock()
        target: NormalizedTarget | None = None
        budget = RequestBudget(self._limits.max_requests)
        network = ScanNetworkService(self._client, budget)

        try:
            validated_request = ScanRequest.model_validate(request)
            target = network.normalize(validated_request.url)
        except ValidationError:
            return self._failed_result(
                started_at=started_at,
                target=None,
                kind=ScanErrorKind.TARGET,
                code="target.invalid_request",
                message="The scan request was invalid.",
            )
        except URLPolicyError:
            return self._failed_result(
                started_at=started_at,
                target=target,
                kind=ScanErrorKind.TARGET,
                code="target.rejected",
                message="The target was rejected by the URL safety policy.",
            )
        except SecurityBoundaryError:
            return self._failed_result(
                started_at=started_at,
                target=target,
                kind=ScanErrorKind.NETWORK,
                code="network.normalization_failed",
                message="The target could not be normalized safely.",
            )
        except Exception:
            return self._failed_result(
                started_at=started_at,
                target=target,
                kind=ScanErrorKind.NETWORK,
                code="network.unexpected_error",
                message="Target normalization failed unexpectedly.",
            )

        landing = await self._attempt(target, network.fetch(validated_request.url))
        https_url = self._scheme_url(target, HttpScheme.HTTPS)
        http_url = self._scheme_url(target, HttpScheme.HTTP)
        https_target = network.normalize(https_url)
        http_target = network.normalize(http_url)

        if target.scheme is HttpScheme.HTTPS:
            https_probe = landing
        else:
            https_result = self._https_result_from_landing(landing.raw_result)
            https_probe = (
                _Attempt(
                    observation=build_probe_observation(
                        requested_target=https_target,
                        fetch_result=https_result,
                    ),
                    raw_result=https_result,
                )
                if https_result is not None
                else await self._attempt(https_target, network.fetch(https_url))
            )

        if target.scheme is HttpScheme.HTTP and landing.raw_result is not None:
            http_result = SafeFetchResult(responses=(landing.raw_result.responses[0],))
            http_probe = _Attempt(
                observation=build_probe_observation(
                    requested_target=http_target,
                    fetch_result=http_result,
                ),
                raw_result=http_result,
            )
        else:
            http_probe = await self._attempt(http_target, network.fetch_once(http_url))

        auxiliary: list[AuxiliaryObservation] = []
        for observation_request in self._registry.auxiliary_requests():
            observation_url = self._auxiliary_url(target, observation_request)
            observation_target = network.normalize(observation_url)
            operation = (
                network.fetch(observation_url)
                if observation_request.follow_redirects
                else network.fetch_once(observation_url)
            )
            attempt = await self._attempt(observation_target, operation)
            auxiliary.append(
                AuxiliaryObservation(
                    key=observation_request.key,
                    probe=attempt.observation,
                )
            )

        observations_finished_at = self._clock()
        context = build_scan_context(
            target=target,
            landing=landing.observation,
            https_probe=https_probe.observation,
            http_probe=http_probe.observation,
            budget=budget,
            started_at=started_at,
            observations_finished_at=observations_finished_at,
            auxiliary=tuple(auxiliary),
        )
        findings: list[Finding] = []
        errors: list[ScanError] = []
        if landing.observation.failure is not None:
            errors.append(self._landing_error(landing.observation.failure))

        for check in self._registry:
            rule_id = check.metadata.rule_id
            try:
                if not check.is_applicable(context):
                    continue
                result = check.evaluate(context)
                self._validate_check_result(rule_id, result)
                findings.extend(result.findings)
            except CheckEvaluationError:
                errors.append(
                    self._check_error(
                        rule_id,
                        "check.evaluation_failed",
                        "The check could not evaluate the available observations.",
                    )
                )
            except Exception:
                errors.append(
                    self._check_error(
                        rule_id,
                        "check.unexpected_error",
                        "The check failed unexpectedly.",
                    )
                )

        finished_at = self._clock()
        state = (
            ScanState.FAILED
            if not landing.observation.succeeded
            else ScanState.PARTIAL
            if errors
            else ScanState.COMPLETED
        )
        return ScanResult(
            target=target,
            hops=landing.raw_result.hops if landing.raw_result is not None else (),
            findings=tuple(findings),
            errors=tuple(errors),
            score=None,
            metadata=self._metadata(
                started_at=started_at,
                finished_at=finished_at,
                redirect_count=max(0, len(context.redirect_chain) - 1),
                state=state,
            ),
        )

    async def _attempt(
        self,
        requested_target: NormalizedTarget,
        operation: Awaitable[SafeFetchResult],
    ) -> _Attempt:
        try:
            result = await operation
        except Exception as exc:
            return _Attempt(
                observation=build_probe_observation(
                    requested_target=requested_target,
                    failure=self._probe_failure(exc),
                ),
                raw_result=None,
            )
        return _Attempt(
            observation=build_probe_observation(
                requested_target=requested_target,
                fetch_result=result,
            ),
            raw_result=result,
        )

    @staticmethod
    def _probe_failure(error: Exception) -> ProbeFailure:
        if isinstance(error, TLSCertificateExpired):
            return ProbeFailure(
                code="tls.certificate_expired",
                message="The TLS certificate was reported as expired.",
            )
        if isinstance(error, TLSHostnameMismatch):
            return ProbeFailure(
                code="tls.hostname_mismatch",
                message="The TLS certificate did not match the requested hostname.",
            )
        if isinstance(error, TLSCertificateUntrusted):
            return ProbeFailure(
                code="tls.certificate_untrusted",
                message="The TLS certificate chain could not be trusted.",
            )
        if isinstance(error, URLPolicyError):
            return ProbeFailure(
                code="target.rejected",
                message="The observation target was rejected by URL policy.",
            )
        if isinstance(error, EndpointUnavailable):
            return ProbeFailure(
                code="network.endpoint_unavailable",
                message="The validated endpoint could not establish a connection.",
            )
        if isinstance(error, SecurityBoundaryError):
            return ProbeFailure(
                code="network.fetch_failed",
                message="The observation could not be fetched safely.",
            )
        return ProbeFailure(
            code="network.unexpected_error",
            message="The protected network operation failed unexpectedly.",
        )

    @staticmethod
    def _scheme_url(target: NormalizedTarget, scheme: HttpScheme) -> str:
        host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
        return f"{scheme.value}://{host}{target.path}"

    @staticmethod
    def _auxiliary_url(target: NormalizedTarget, request: AuxiliaryRequest) -> str:
        host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
        return f"{request.scheme.value}://{host}{request.path}"

    @staticmethod
    def _https_result_from_landing(
        result: SafeFetchResult | None,
    ) -> SafeFetchResult | None:
        if result is None:
            return None
        for index, response in enumerate(result.responses):
            if response.target.scheme is HttpScheme.HTTPS:
                return SafeFetchResult(responses=result.responses[index:])
        return None

    @staticmethod
    def _landing_error(failure: ProbeFailure) -> ScanError:
        kind = ScanErrorKind.TARGET if failure.code.startswith("target.") else ScanErrorKind.NETWORK
        return ScanError(kind=kind, code=failure.code, message=failure.message)

    @staticmethod
    def _validate_check_result(rule_id: str, result: CheckResult) -> None:
        if not isinstance(result, CheckResult):
            raise TypeError("Check returned an invalid result type")
        if any(finding.id != rule_id for finding in result.findings):
            raise ValueError("Check returned a finding for another rule")
        if any(finding.status is FindingStatus.ERROR for finding in result.findings):
            raise ValueError("Operational errors must not be returned as findings")

    @staticmethod
    def _check_error(rule_id: str, code: str, message: str) -> ScanError:
        return ScanError(
            kind=ScanErrorKind.CHECK,
            code=code,
            message=message,
            rule_id=rule_id,
        )

    def _failed_result(
        self,
        *,
        started_at: datetime,
        target: NormalizedTarget | None,
        kind: ScanErrorKind,
        code: str,
        message: str,
    ) -> ScanResult:
        finished_at = self._clock()
        return ScanResult(
            target=target,
            errors=(ScanError(kind=kind, code=code, message=message),),
            score=None,
            metadata=self._metadata(
                started_at=started_at,
                finished_at=finished_at,
                redirect_count=0,
                state=ScanState.FAILED,
            ),
        )

    def _metadata(
        self,
        *,
        started_at: datetime,
        finished_at: datetime,
        redirect_count: int,
        state: ScanState,
    ) -> ScanMetadata:
        duration_ms = max(0, round((finished_at - started_at).total_seconds() * 1000))
        return ScanMetadata(
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=duration_ms,
            webguard_version=__version__,
            ruleset_version=self._registry.ruleset_version,
            redirect_count=redirect_count,
            state=state,
        )
