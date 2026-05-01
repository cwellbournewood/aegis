"""Session state and per-session key derivation.

Sessions are the unit of correlation across all five layers. Each session has:
    - A derived HMAC key (HKDF from a master key)
    - An origin Intent Anchor vector (set when first user request arrives)
    - A garden of Canary tokens
    - A pool of mintable Capability tokens
"""

from __future__ import annotations

import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _derive_master_key() -> bytes:
    """Source the master key from env, or generate a new one for this process.

    Production deployments should set AEGIS_MASTER_KEY (hex-encoded 32 bytes)
    or AEGIS_MASTER_KEY_FILE. If neither is set, a fresh ephemeral key is used
    so dev runs don't fail, but session keys won't survive a restart.
    """
    env_key = os.environ.get("AEGIS_MASTER_KEY")
    if env_key:
        try:
            key = bytes.fromhex(env_key)
        except ValueError as exc:
            raise RuntimeError("AEGIS_MASTER_KEY must be hex-encoded") from exc
        if len(key) < 32:
            raise RuntimeError("AEGIS_MASTER_KEY must be at least 32 bytes")
        return key
    key_file = os.environ.get("AEGIS_MASTER_KEY_FILE")
    if key_file and os.path.exists(key_file):
        with open(key_file, "rb") as fh:
            data = fh.read().strip()
            if len(data) >= 64 and all(c in b"0123456789abcdefABCDEF" for c in data):
                return bytes.fromhex(data.decode())
            return data
    return secrets.token_bytes(32)


_MASTER_KEY_LOCK = threading.Lock()
_MASTER_KEY: bytes | None = None


def master_key() -> bytes:
    global _MASTER_KEY
    with _MASTER_KEY_LOCK:
        if _MASTER_KEY is None:
            _MASTER_KEY = _derive_master_key()
        return _MASTER_KEY


def reset_master_key_for_tests(key: bytes | None = None) -> None:
    global _MASTER_KEY
    with _MASTER_KEY_LOCK:
        _MASTER_KEY = key


def derive_session_key(session_id: str, salt: bytes = b"aegis/v1/session") -> bytes:
    """Derive a per-session HMAC key from the master key via HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=session_id.encode("utf-8"),
    )
    return hkdf.derive(master_key())


@dataclass
class Session:
    """Per-conversation state shared across all five layers."""

    session_id: str
    upstream: str = "anthropic"
    user_intent: str | None = None
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)
    anchor: Any | None = None
    canaries: Any | None = None
    capabilities: dict[str, Any] = field(default_factory=dict)
    expires_at: float | None = None

    @property
    def hmac_key(self) -> bytes:
        return derive_session_key(self.session_id)

    def touch(self) -> None:
        self.last_active = time.time()

    def expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at


class SessionStore:
    """In-memory session store. Production deployments can swap in Redis."""

    def __init__(self, default_ttl_seconds: int = 60 * 60 * 12) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._default_ttl = default_ttl_seconds

    def create(
        self,
        upstream: str = "anthropic",
        user_intent: str | None = None,
        ttl_seconds: int | None = None,
    ) -> Session:
        session_id = "ses_" + secrets.token_urlsafe(18)
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        session = Session(
            session_id=session_id,
            upstream=upstream,
            user_intent=user_intent,
            expires_at=time.time() + ttl if ttl > 0 else None,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            return None
        if session.expired():
            self.delete(session_id)
            return None
        session.touch()
        return session

    def get_or_create(self, session_id: str | None, **kwargs: Any) -> Session:
        if session_id:
            existing = self.get(session_id)
            if existing is not None:
                return existing
        return self.create(**kwargs)

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def gc(self) -> int:
        now = time.time()
        removed = 0
        with self._lock:
            stale = [sid for sid, s in self._sessions.items() if s.expires_at and s.expires_at < now]
            for sid in stale:
                self._sessions.pop(sid, None)
                removed += 1
        return removed

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)
