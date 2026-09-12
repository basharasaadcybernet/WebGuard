"""Per-scan outbound request accounting."""

import asyncio

from webguard.security.errors import RequestBudgetExceeded


class RequestBudget:
    """Concurrency-safe counter that fails before an extra request starts."""

    def __init__(self, maximum: int) -> None:
        if maximum < 1:
            raise ValueError("Request budget must allow at least one request")
        self._maximum = maximum
        self._used = 0
        self._lock = asyncio.Lock()

    @property
    def used(self) -> int:
        return self._used

    @property
    def maximum(self) -> int:
        """Return the immutable per-scan request ceiling."""
        return self._maximum

    @property
    def remaining(self) -> int:
        """Return how many requests can still start."""
        return self._maximum - self._used

    async def consume(self) -> None:
        async with self._lock:
            if self._used >= self._maximum:
                raise RequestBudgetExceeded("Outbound request budget exhausted")
            self._used += 1
