from __future__ import annotations

import ipaddress
from dataclasses import FrozenInstanceError, dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from webguard.domain.enums import FindingStatus, ScanErrorKind, ScanState, Severity
from webguard.domain.models import Finding, NormalizedTarget, ScanRequest
from webguard.scanner.checks import (
    AuxiliaryRequest,
    CheckEvaluationError,
    CheckMetadata,
    CheckResult,
    SecurityCheck,
)
from webguard.scanner.context import ScanContext
from webguard.scanner.engine import ScanEngine
from webguard.scanner.network import ScanNetworkService
from webguard.scanner.registry import CheckRegistry, DuplicateRuleIdError
from webguard.security.budget import RequestBudget
from webguard.security.client import SafeFetchResult, SafeResponse
from webguard.security.config import NetworkLimits
from webguard.security.errors import (
    BlockedAddressError,
    ConnectionRefused,
    ConnectionTerminated,
    DNSResolutionError,
    RedirectPolicyError,
    RequestTimedOut,
    TLSCertificateExpired,
    TLSCertificateUntrusted,
    TLSHandshakeFailed,
    TLSHostnameMismatch,
    TransportError,
    URLPolicyError,
)
from webguard.security.transport import TransportResponse
from webguard.security.url_policy import URLPolicy


class StepClock:
    def __init__(self) -> None:
        self._now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        current = self._now
        self._now += timedelta(milliseconds=1)
        return current


class FakeSafeClient:
    def __init__(
        self,
        *,
        result: SafeFetchResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result or safe_result()
        self.error = error
        self.budgets: list[RequestBudget] = []

    def normalize(self, raw_url: str) -> NormalizedTarget:
        if isinstance(self.error, URLPolicyError):
            raise self.error
        return URLPolicy().normalize(raw_url)

    async def fetch(self, raw_url: str, *, budget: RequestBudget | None = None) -> SafeFetchResult:
        assert budget is not None
        self.budgets.append(budget)
        await budget.consume()
        if self.error is not None:
            raise self.error
        return self.result

    async def fetch_once(
        self, raw_url: str, *, budget: RequestBudget | None = None
    ) -> SafeFetchResult:
        return await self.fetch(raw_url, budget=budget)


@dataclass
class FakeCheck:
    metadata: CheckMetadata
    finding_status: FindingStatus | None = FindingStatus.INFO
    applicable: bool = True
    error: Exception | None = None
    calls: list[str] | None = None
    contexts: list[ScanContext] | None = None

    def is_applicable(self, context: ScanContext) -> bool:
        if self.calls is not None:
            self.calls.append(f"applicable:{self.metadata.rule_id}")
        return self.applicable

    def evaluate(self, context: ScanContext) -> CheckResult:
        if self.calls is not None:
            self.calls.append(f"evaluate:{self.metadata.rule_id}")
        if self.contexts is not None:
            self.contexts.append(context)
        if self.error is not None:
            raise self.error
        if self.finding_status is None:
            return CheckResult()
        severity = (
            Severity.LOW
            if self.finding_status in {FindingStatus.WARNING, FindingStatus.FAIL}
            else Severity.INFO
        )
        return CheckResult(
            findings=(
                Finding(
                    id=self.metadata.rule_id,
                    title=self.metadata.title,
                    category=self.metadata.category,
                    status=self.finding_status,
                    severity=severity,
                    description="Synthetic orchestration test finding.",
                ),
            )
        )


def safe_result(*, secret_headers: bool = False) -> SafeFetchResult:
    target = URLPolicy().normalize("https://example.com/page?token=secret")
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "text/html"),)
    if secret_headers:
        headers += (
            ("Authorization", "Bearer hidden"),
            ("Set-Cookie", "session=hidden; Secure; HttpOnly; SameSite=Lax"),
            ("Location", "/next?key=hidden"),
        )
    return SafeFetchResult(
        responses=(
            SafeResponse(
                target=target,
                destination_ip=ipaddress.ip_address("93.184.216.34"),
                response=TransportResponse(
                    status_code=200,
                    headers=headers,
                    body=b"<html>bounded internal secret</html>",
                    elapsed_ms=5,
                    http_version="HTTP/1.1",
                ),
            ),
        )
    )


def check(rule_id: str, order: int, **kwargs: object) -> FakeCheck:
    return FakeCheck(
        metadata=CheckMetadata(
            rule_id=rule_id,
            title=rule_id,
            category="Synthetic",
            order=order,
        ),
        **kwargs,
    )


def engine(*checks: FakeCheck, client: FakeSafeClient | None = None) -> ScanEngine:
    return ScanEngine(
        registry=CheckRegistry(checks),
        client=client or FakeSafeClient(),
        limits=NetworkLimits(max_requests=4),
        clock=StepClock(),
        scorer=None,
    )


@pytest.mark.asyncio
async def test_scan_context_is_immutable_and_contains_safe_observations() -> None:
    contexts: list[ScanContext] = []
    client = FakeSafeClient(result=safe_result(secret_headers=True))
    result = await engine(check("synthetic.context", 1, contexts=contexts), client=client).scan(
        ScanRequest(url="https://example.com/page?token=secret")
    )

    context = contexts[0]
    assert context.request_budget.used == 2
    assert context.request_budget.maximum == 4
    assert context.landing_page.body.size > 0
    assert context.landing_page.body.text.startswith("<html>")
    assert context.landing_page.header_values("authorization") == ("[redacted]",)
    assert context.landing_page.header_values("set-cookie") == (
        "session=[redacted]; Secure; HttpOnly; SameSite=Lax",
    )
    assert context.landing_page.header_values("location") == (
        "https://example.com/next?[redacted]",
    )
    with pytest.raises(FrozenInstanceError):
        context.observed_https_downgrade = True  # type: ignore[misc]
    serialized = result.model_dump_json()
    assert "hidden" not in serialized
    assert "token=secret" not in serialized
    assert "bounded internal secret" not in serialized


def test_check_protocol_and_metadata_validation() -> None:
    synthetic = check("synthetic.protocol", 1)
    assert isinstance(synthetic, SecurityCheck)
    with pytest.raises(ValueError, match="stable dotted"):
        CheckMetadata(rule_id="Not Stable", title="Title", category="Category")


def test_auxiliary_request_declarations_are_validated_and_deduplicated() -> None:
    request = AuxiliaryRequest(key="security_txt", path="/.well-known/security.txt")
    first = check("synthetic.first", 1)
    second = check("synthetic.second", 2)
    first.metadata = CheckMetadata(  # type: ignore[misc]
        rule_id=first.metadata.rule_id,
        title=first.metadata.title,
        category=first.metadata.category,
        order=first.metadata.order,
        auxiliary_requests=(request,),
    )
    second.metadata = CheckMetadata(  # type: ignore[misc]
        rule_id=second.metadata.rule_id,
        title=second.metadata.title,
        category=second.metadata.category,
        order=second.metadata.order,
        auxiliary_requests=(request,),
    )
    assert CheckRegistry((second, first)).auxiliary_requests() == (request,)

    with pytest.raises(ValueError, match="safe absolute path"):
        AuxiliaryRequest(key="unsafe", path="//attacker.example/path")
    with pytest.raises(ValueError, match="stable lowercase"):
        AuxiliaryRequest(key="Not-Stable", path="/safe")
    with pytest.raises(ValueError, match="keys must be unique"):
        CheckMetadata(
            rule_id="synthetic.duplicate",
            title="duplicate",
            category="Synthetic",
            auxiliary_requests=(request, request),
        )


def test_conflicting_auxiliary_declarations_are_rejected() -> None:
    first = check("synthetic.first", 1)
    second = check("synthetic.second", 2)
    first.metadata = CheckMetadata(  # type: ignore[misc]
        rule_id=first.metadata.rule_id,
        title=first.metadata.title,
        category=first.metadata.category,
        auxiliary_requests=(AuxiliaryRequest(key="resource", path="/one"),),
    )
    second.metadata = CheckMetadata(  # type: ignore[misc]
        rule_id=second.metadata.rule_id,
        title=second.metadata.title,
        category=second.metadata.category,
        auxiliary_requests=(AuxiliaryRequest(key="resource", path="/two"),),
    )
    with pytest.raises(ValueError, match="Conflicting auxiliary"):
        CheckRegistry((first, second))


def test_registry_is_deterministic_and_rejects_duplicate_ids() -> None:
    registry = CheckRegistry(
        [
            check("synthetic.zeta", 20),
            check("synthetic.beta", 10),
            check("synthetic.alpha", 10),
        ]
    )
    assert [item.metadata.rule_id for item in registry] == [
        "synthetic.alpha",
        "synthetic.beta",
        "synthetic.zeta",
    ]
    with pytest.raises(DuplicateRuleIdError, match=r"synthetic\.alpha"):
        registry.register(check("synthetic.alpha", 99))
    with pytest.raises(ValueError, match="ruleset_version"):
        CheckRegistry(ruleset_version=" ")


def test_safe_fetch_result_requires_an_observation() -> None:
    with pytest.raises(ValueError, match="at least one response"):
        SafeFetchResult(responses=())


@pytest.mark.asyncio
async def test_no_checks_is_a_completed_unscored_scan() -> None:
    result = await engine().scan(ScanRequest(url="https://example.com"))
    assert result.metadata.state is ScanState.COMPLETED
    assert result.findings == ()
    assert result.errors == ()
    assert result.score is None


@pytest.mark.asyncio
async def test_findings_and_execution_order_are_deterministic() -> None:
    calls: list[str] = []
    result = await engine(
        check("synthetic.last", 20, finding_status=FindingStatus.FAIL, calls=calls),
        check("synthetic.first", 10, calls=calls),
    ).scan(ScanRequest(url="https://example.com"))
    assert [finding.id for finding in result.findings] == [
        "synthetic.first",
        "synthetic.last",
    ]
    assert calls == [
        "applicable:synthetic.first",
        "evaluate:synthetic.first",
        "applicable:synthetic.last",
        "evaluate:synthetic.last",
    ]
    assert result.metadata.state is ScanState.COMPLETED


@pytest.mark.asyncio
async def test_not_applicable_check_does_not_evaluate() -> None:
    calls: list[str] = []
    result = await engine(check("synthetic.skip", 1, applicable=False, calls=calls)).scan(
        ScanRequest(url="https://example.com")
    )
    assert calls == ["applicable:synthetic.skip"]
    assert result.findings == ()
    assert result.metadata.state is ScanState.COMPLETED


@pytest.mark.asyncio
async def test_check_failures_are_isolated_and_make_scan_partial() -> None:
    result = await engine(
        check("synthetic.expected", 1, error=CheckEvaluationError("details")),
        check("synthetic.crash", 2, error=RuntimeError("secret traceback detail")),
        check("synthetic.success", 3),
    ).scan(ScanRequest(url="https://example.com"))
    assert [finding.id for finding in result.findings] == ["synthetic.success"]
    assert [error.code for error in result.errors] == [
        "check.evaluation_failed",
        "check.unexpected_error",
    ]
    assert all(error.kind is ScanErrorKind.CHECK for error in result.errors)
    assert "secret traceback detail" not in result.model_dump_json()
    assert result.metadata.state is ScanState.PARTIAL
    assert result.score is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "kind", "code"),
    [
        (URLPolicyError("unsafe target detail"), ScanErrorKind.TARGET, "target.rejected"),
        (TransportError("network secret detail"), ScanErrorKind.NETWORK, "network.fetch_failed"),
    ],
)
async def test_target_and_network_failures_return_failed_scan(
    error: Exception, kind: ScanErrorKind, code: str
) -> None:
    result = await engine(client=FakeSafeClient(error=error)).scan(
        ScanRequest(url="https://example.com")
    )
    assert result.metadata.state is ScanState.FAILED
    assert result.findings == ()
    assert result.errors[0].kind is kind
    assert result.errors[0].code == code
    assert "secret detail" not in result.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "code"),
    [
        (DNSResolutionError("secret"), "network.dns_resolution_failed"),
        (ConnectionRefused("secret"), "network.connection_refused"),
        (RequestTimedOut("secret"), "network.connection_timeout"),
        (TLSHandshakeFailed("secret"), "tls.handshake_failed"),
        (TLSCertificateUntrusted("secret"), "tls.certificate_untrusted"),
        (TLSCertificateExpired("secret"), "tls.certificate_expired"),
        (TLSHostnameMismatch("secret"), "tls.hostname_mismatch"),
        (ConnectionTerminated("secret"), "network.connection_terminated"),
        (RedirectPolicyError("secret"), "network.redirect_rejected"),
        (BlockedAddressError("secret"), "network.destination_blocked"),
        (TransportError("secret"), "network.fetch_failed"),
    ],
)
async def test_network_failures_use_safe_specific_classifications(
    error: Exception, code: str
) -> None:
    result = await engine(client=FakeSafeClient(error=error)).scan(
        ScanRequest(url="https://example.com")
    )

    assert result.metadata.state is ScanState.FAILED
    assert result.errors[0].code == code
    assert "secret" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_unexpected_network_failure_is_safely_recorded() -> None:
    result = await engine(client=FakeSafeClient(error=RuntimeError("adapter secret"))).scan(
        ScanRequest(url="https://example.com")
    )
    assert result.metadata.state is ScanState.FAILED
    assert result.errors[0].code == "network.unexpected_error"
    assert "adapter secret" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_scan_network_service_reuses_one_budget() -> None:
    client = FakeSafeClient()
    budget = RequestBudget(3)
    network = ScanNetworkService(client, budget)
    await network.fetch("https://example.com")
    await network.fetch("https://example.com/second")
    await network.fetch_once("https://example.com/third")
    assert client.budgets == [budget, budget, budget]
    assert budget.used == 3
    assert budget.remaining == 0


@pytest.mark.asyncio
async def test_invalid_runtime_request_is_a_safe_target_failure() -> None:
    result = await engine().scan(cast(ScanRequest, {"url": "https://example.com\nsecret"}))
    assert result.metadata.state is ScanState.FAILED
    assert result.target is None
    assert result.errors[0].code == "target.invalid_request"
