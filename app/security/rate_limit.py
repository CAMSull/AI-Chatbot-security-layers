"""
Layer 3 - Rate Limiting & Abuse Prevention
============================================
Addresses OWASP LLM10 (Unbounded Consumption) / model-DoS and general API
abuse (credential stuffing against Layer 1, scripted flooding, runaway
client bugs).

A fixed-window counter, keyed per authenticated user, tracks how many
requests have been made within the configured window and rejects requests
over the limit with 429 Too Many Requests and a Retry-After header.

This implementation is in-memory and process-local, which is appropriate
for a single-instance demo/assessment deployment. In production behind
multiple replicas you would back this with a shared store (Redis
INCR/EXPIRE, or Azure API Management's built-in rate-limit policies sitting
in front of this service) so limits are enforced cluster-wide - noted in
the README as a scaling consideration.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after_seconds: int


class InMemoryRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        # key -> (window_start_epoch, count)
        self._buckets: Dict[str, Tuple[float, int]] = {}

    def check(self, key: str) -> RateLimitResult:
        now = time.time()
        with self._lock:
            window_start, count = self._buckets.get(key, (now, 0))

            if now - window_start >= self.window_seconds:
                window_start, count = now, 0

            if count >= self.max_requests:
                retry_after = int(self.window_seconds - (now - window_start)) + 1
                self._buckets[key] = (window_start, count)
                return RateLimitResult(allowed=False, remaining=0, retry_after_seconds=max(retry_after, 1))

            count += 1
            self._buckets[key] = (window_start, count)
            return RateLimitResult(
                allowed=True,
                remaining=self.max_requests - count,
                retry_after_seconds=0,
            )

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
