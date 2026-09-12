"""Approved per-scan access to the protected HTTP boundary."""

from __future__ import annotations

from typing import Protocol

from webguard.domain.models import NormalizedTarget
from webguard.security.budget import RequestBudget
from webguard.security.client import SafeFetchResult


class SafeFetchClient(Protocol):
    """Narrow scanner-facing portion of SafeHttpClient, injectable for tests."""

    def normalize(self, raw_url: str) -> NormalizedTarget: ...

    async def fetch(
        self, raw_url: str, *, budget: RequestBudget | None = None
    ) -> SafeFetchResult: ...


class ScanNetworkService:
    """Own one request budget and route every scan fetch through the safe client."""

    def __init__(self, client: SafeFetchClient, budget: RequestBudget) -> None:
        self._client = client
        self.budget = budget

    def normalize(self, raw_url: str) -> NormalizedTarget:
        return self._client.normalize(raw_url)

    async def fetch(self, raw_url: str) -> SafeFetchResult:
        return await self._client.fetch(raw_url, budget=self.budget)
