"""Fixed-window rate limiter backed by Redis with an in-memory fallback."""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict

from app.core.config import get_settings

log = logging.getLogger("cloudaegis.ratelimit")


class RateLimiter:
    def __init__(self, redis_url: str | None) -> None:
        self._redis = None
        if redis_url:
            try:
                import redis

                self._redis = redis.Redis.from_url(redis_url, socket_connect_timeout=1, socket_timeout=1)
                self._redis.ping()
            except Exception:  # Redis unavailable: degrade to per-process limiting
                log.warning("rate_limiter_redis_unavailable_using_memory")
                self._redis = None
        self._memory: dict[str, tuple[int, float]] = defaultdict(lambda: (0, 0.0))
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        """Record a hit. Returns ``(allowed, retry_after_seconds)``."""
        bucket = int(time.time() // window_seconds)
        full_key = f"ca:rl:{key}:{bucket}"
        if self._redis is not None:
            try:
                pipe = self._redis.pipeline()
                pipe.incr(full_key)
                pipe.expire(full_key, window_seconds + 1)
                count = int(pipe.execute()[0])
                return count <= limit, window_seconds - int(time.time() % window_seconds)
            except Exception:
                log.warning("rate_limiter_redis_error")
        with self._lock:
            count, started = self._memory[full_key]
            if not started:
                started = time.time()
            count += 1
            self._memory[full_key] = (count, started)
            if len(self._memory) > 10000:  # prune old windows
                for k in list(self._memory)[:5000]:
                    if not k.endswith(f":{bucket}"):
                        self._memory.pop(k, None)
        return count <= limit, window_seconds - int(time.time() % window_seconds)

    def reset(self) -> None:
        with self._lock:
            self._memory.clear()
        if self._redis is not None:
            try:
                for key in self._redis.scan_iter("ca:rl:*"):
                    self._redis.delete(key)
            except Exception:
                pass


_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter(get_settings().redis_url)
    return _limiter
