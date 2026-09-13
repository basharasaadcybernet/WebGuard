"""Bounded, process-local admission and rate controls for scan execution."""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
from collections import OrderedDict, deque
from collections.abc import Callable


class ScanCapacity:
    """An immediate-admission concurrency limiter with no in-memory work queue."""

    def __init__(self, limit: int) -> None:
        if limit < 1:
            raise ValueError("Concurrency limit must be positive")
        self._limit = limit
        self._active = 0
        self._lock = asyncio.Lock()

    @property
    def active(self) -> int:
        return self._active

    async def try_acquire(self) -> bool:
        async with self._lock:
            if self._active >= self._limit:
                return False
            self._active += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            if self._active == 0:
                raise RuntimeError("Scan capacity released without an active scan")
            self._active -= 1


class ClientRateLimiter:
    """Fixed-window limiter with hashed keys and a hard cap on tracked clients."""

    def __init__(
        self,
        *,
        requests: int,
        window_seconds: float,
        max_clients: int,
        clock: Callable[[], float] = time.monotonic,
        key: bytes | None = None,
    ) -> None:
        if requests < 1 or window_seconds <= 0 or max_clients < 1:
            raise ValueError("Rate-limit settings must be positive")
        self._requests = requests
        self._window_seconds = window_seconds
        self._max_clients = max_clients
        self._clock = clock
        self._key = key or os.urandom(32)
        self._clients: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = asyncio.Lock()

    @property
    def tracked_clients(self) -> int:
        return len(self._clients)

    async def allow(self, client_host: str) -> bool:
        client_key = hashlib.blake2s(
            client_host.encode("utf-8", errors="replace"),
            key=self._key,
            digest_size=16,
        ).hexdigest()
        now = self._clock()
        cutoff = now - self._window_seconds
        async with self._lock:
            timestamps = self._clients.pop(client_key, deque())
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()
            if len(timestamps) >= self._requests:
                self._clients[client_key] = timestamps
                return False
            timestamps.append(now)
            self._clients[client_key] = timestamps
            while len(self._clients) > self._max_clients:
                self._clients.popitem(last=False)
            return True
