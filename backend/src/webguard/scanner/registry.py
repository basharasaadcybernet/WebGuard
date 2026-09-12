"""Explicit deterministic registry for future security checks."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from webguard.scanner.checks import SecurityCheck


class DuplicateRuleIdError(ValueError):
    """Raised when two checks claim the same stable rule identifier."""


class CheckRegistry:
    """Explicitly registered checks iterated by order and then rule ID."""

    def __init__(
        self,
        checks: Iterable[SecurityCheck] = (),
        *,
        ruleset_version: str = "0.1.0",
    ) -> None:
        if not ruleset_version.strip():
            raise ValueError("ruleset_version cannot be empty")
        self._checks: dict[str, SecurityCheck] = {}
        self.ruleset_version = ruleset_version
        for check in checks:
            self.register(check)

    def register(self, check: SecurityCheck) -> None:
        rule_id = check.metadata.rule_id
        if rule_id in self._checks:
            raise DuplicateRuleIdError(f"Duplicate check rule ID: {rule_id}")
        self._checks[rule_id] = check

    def ordered(self) -> tuple[SecurityCheck, ...]:
        return tuple(
            sorted(
                self._checks.values(),
                key=lambda check: (check.metadata.order, check.metadata.rule_id),
            )
        )

    def __iter__(self) -> Iterator[SecurityCheck]:
        return iter(self.ordered())

    def __len__(self) -> int:
        return len(self._checks)
