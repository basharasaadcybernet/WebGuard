"""Deterministic scan lifecycle and check failure isolation."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import ValidationError

from webguard import __version__
from webguard.domain.enums import FindingStatus, ScanErrorKind, ScanState
from webguard.domain.models import (
    Finding,
    NormalizedTarget,
    ScanError,
    ScanMetadata,
    ScanRequest,
    ScanResult,
)
from webguard.scanner.checks import CheckEvaluationError, CheckResult
from webguard.scanner.context import build_scan_context
from webguard.scanner.network import SafeFetchClient, ScanNetworkService
from webguard.scanner.registry import CheckRegistry
from webguard.security.budget import RequestBudget
from webguard.security.client import SafeHttpClient
from webguard.security.config import NetworkLimits
from webguard.security.errors import SecurityBoundaryError, URLPolicyError


def _utc_now() -> datetime:
    return datetime.now(UTC)


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
        self._registry = registry if registry is not None else CheckRegistry()
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
            fetch_result = await network.fetch(validated_request.url)
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
                code="network.fetch_failed",
                message="The target could not be fetched safely.",
            )
        except Exception:
            return self._failed_result(
                started_at=started_at,
                target=target,
                kind=ScanErrorKind.NETWORK,
                code="network.unexpected_error",
                message="The protected network operation failed unexpectedly.",
            )

        observations_finished_at = self._clock()
        context = build_scan_context(
            target=target,
            fetch_result=fetch_result,
            budget=budget,
            started_at=started_at,
            observations_finished_at=observations_finished_at,
        )
        findings: list[Finding] = []
        errors: list[ScanError] = []

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
        state = ScanState.PARTIAL if errors else ScanState.COMPLETED
        return ScanResult(
            target=target,
            hops=fetch_result.hops,
            findings=tuple(findings),
            errors=tuple(errors),
            score=None,
            metadata=self._metadata(
                started_at=started_at,
                finished_at=finished_at,
                redirect_count=max(0, len(fetch_result.responses) - 1),
                state=state,
            ),
        )

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
