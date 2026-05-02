"""Pluggable nonce store for capability-token single-use enforcement.

In a single-replica deployment the in-memory `MemoryNonceStore` is sufficient.
For multi-replica HA deployments where a token might race against itself
across replicas, swap in a backend that shares state (Redis, DynamoDB, etc).

The interface is intentionally minimal: `mark_used(nonce, ttl_seconds) -> bool`
returns True if this is the first time the nonce was seen and successfully
recorded. False means the nonce is already consumed (reject the call).

Implementations must be atomic: a successful `mark_used` must guarantee that
no concurrent caller across any process / replica also gets True for the same
nonce. Redis backends use `SET NX EX`; DynamoDB uses `PutItem` with a
`attribute_not_exists` condition.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Protocol


class NonceStore(Protocol):
    """Atomic single-use nonce ledger."""

    def mark_used(self, nonce: str, ttl_seconds: int) -> bool:
        """Atomically mark `nonce` as used.

        Returns True if this is the first call for the nonce and it has been
        recorded for `ttl_seconds`. Returns False if the nonce was already used.
        """
        ...

    def is_used(self, nonce: str) -> bool:
        """Lightweight read; for diagnostics. May race; only `mark_used` is the source of truth."""
        ...


@dataclass
class _MemoryRecord:
    expires_at: float


@dataclass
class MemoryNonceStore:
    """In-memory thread-safe nonce store with TTL eviction.

    Default for single-replica deployments. Sweep is amortized: every Nth
    `mark_used` triggers a scan of expired entries.
    """

    sweep_every: int = 256
    _data: dict[str, _MemoryRecord] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _writes_since_sweep: int = 0

    def mark_used(self, nonce: str, ttl_seconds: int) -> bool:
        now = time.time()
        with self._lock:
            self._maybe_sweep_locked(now)
            existing = self._data.get(nonce)
            if existing is not None and existing.expires_at > now:
                return False
            self._data[nonce] = _MemoryRecord(expires_at=now + ttl_seconds)
            self._writes_since_sweep += 1
            return True

    def is_used(self, nonce: str) -> bool:
        with self._lock:
            rec = self._data.get(nonce)
            if rec is None:
                return False
            return rec.expires_at > time.time()

    def _maybe_sweep_locked(self, now: float) -> None:
        if self._writes_since_sweep < self.sweep_every:
            return
        expired = [n for n, r in self._data.items() if r.expires_at <= now]
        for n in expired:
            self._data.pop(n, None)
        self._writes_since_sweep = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


class RedisNonceStore:
    """Redis-backed nonce store using `SET NX EX` for atomic mark-used.

    Requires `redis>=4.0`. Install with `pip install 'aegis-guard[redis]'`.

    The key namespace defaults to `aegis:cap:nonce:` to avoid collisions with
    other Redis keys in the deployment.
    """

    def __init__(
        self,
        redis_client=None,
        url: str | None = None,
        namespace: str = "aegis:cap:nonce:",
    ) -> None:
        if redis_client is None:
            try:
                import redis
            except ImportError as exc:
                raise ImportError(
                    "RedisNonceStore requires `redis`. Install with: "
                    "pip install 'aegis-guard[redis]'"
                ) from exc
            redis_client = redis.Redis.from_url(url or "redis://localhost:6379/0")
        self._client = redis_client
        self._namespace = namespace

    def _key(self, nonce: str) -> str:
        return self._namespace + nonce

    def mark_used(self, nonce: str, ttl_seconds: int) -> bool:
        # SET NX EX: atomically set if not exists, with TTL.
        # Returns True only on first successful set.
        result = self._client.set(self._key(nonce), b"1", nx=True, ex=max(1, ttl_seconds))
        return bool(result)

    def is_used(self, nonce: str) -> bool:
        return bool(self._client.exists(self._key(nonce)))


def make_nonce_store_from_config(config: dict) -> NonceStore:
    """Construct a nonce store from a config dict.

    Config keys:
        kind: "memory" | "redis"
        url: redis URL (for redis kind)
        namespace: redis key namespace (optional)
    """
    kind = (config or {}).get("kind", "memory")
    if kind == "memory":
        return MemoryNonceStore()
    if kind == "redis":
        return RedisNonceStore(
            url=config.get("url"),
            namespace=config.get("namespace", "aegis:cap:nonce:"),
        )
    raise ValueError(f"unknown nonce_store kind: {kind}")
