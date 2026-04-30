"""Cryptographic Content Provenance Tags (CCPT).

Wraps every chunk of context that flows through the proxy in an HMAC-signed
envelope binding origin, trust level, and session. The envelope is *internal*
to the proxy pipeline — it is stripped before the upstream model ever sees the
prompt, so it doesn't pollute the context window or confuse the model.

The envelope exists to:
    - Make origin claims unforgeable across the pipeline
    - Bind context to a specific session (no cross-session leakage)
    - Provide a stable integrity check for downstream gates
"""

from __future__ import annotations

import base64
import enum
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

CCPT_VERSION = 1


class Origin(str, enum.Enum):
    SYSTEM = "system"
    USER = "user"
    RETRIEVED = "retrieved"
    TOOL = "tool"
    AGENT = "agent"


class Level(str, enum.Enum):
    """Trust levels, ordered: L3 most trusted → L0 least trusted."""

    L3 = "L3"
    L2 = "L2"
    L1 = "L1"
    L0 = "L0"

    @property
    def rank(self) -> int:
        return {"L0": 0, "L1": 1, "L2": 2, "L3": 3}[self.value]

    @classmethod
    def coerce(cls, value: str | Level) -> Level:
        if isinstance(value, cls):
            return value
        return cls(str(value))


_DEFAULT_ORIGIN_LEVELS: dict[Origin, Level] = {
    Origin.SYSTEM: Level.L3,
    Origin.USER: Level.L2,
    Origin.RETRIEVED: Level.L1,
    Origin.TOOL: Level.L0,
    Origin.AGENT: Level.L1,
}


def default_level_for(origin: Origin) -> Level:
    return _DEFAULT_ORIGIN_LEVELS[origin]


@dataclass
class CCPTEnvelope:
    origin: Origin
    level: Level
    session_id: str
    nonce: str
    payload: str
    sig: str = ""
    ccpt_v: int = CCPT_VERSION
    timestamp: float = field(default_factory=time.time)
    chunk_id: str = field(default_factory=lambda: secrets.token_hex(8))
    parents: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ccpt_v": self.ccpt_v,
            "origin": self.origin.value,
            "level": self.level.value,
            "session_id": self.session_id,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "chunk_id": self.chunk_id,
            "parents": list(self.parents),
            "payload": self.payload,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CCPTEnvelope:
        return cls(
            ccpt_v=int(d.get("ccpt_v", CCPT_VERSION)),
            origin=Origin(d["origin"]),
            level=Level(d["level"]),
            session_id=d["session_id"],
            nonce=d["nonce"],
            timestamp=float(d.get("timestamp", time.time())),
            chunk_id=d.get("chunk_id", secrets.token_hex(8)),
            parents=tuple(d.get("parents", []) or []),
            payload=d["payload"],
            sig=d.get("sig", ""),
        )


def _canonical_signing_input(env: CCPTEnvelope) -> bytes:
    """Stable byte sequence over which we compute the HMAC.

    Any field that affects authorization or routing must be covered. We
    deliberately keep this canonical form simple — JSON with sorted keys
    over a fixed set of fields. Adding a new field requires bumping ccpt_v.
    """
    body = {
        "v": env.ccpt_v,
        "origin": env.origin.value,
        "level": env.level.value,
        "sid": env.session_id,
        "nonce": env.nonce,
        "ts": int(env.timestamp),
        "cid": env.chunk_id,
        "parents": list(env.parents),
        "payload": env.payload,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def tag(
    content: str,
    origin: Origin,
    session_key: bytes,
    session_id: str,
    level: Level | None = None,
    parents: tuple[str, ...] = (),
) -> CCPTEnvelope:
    """Wrap content in a CCPT envelope and sign it with the session key."""
    if level is None:
        level = default_level_for(origin)
    env = CCPTEnvelope(
        origin=origin,
        level=level,
        session_id=session_id,
        nonce=secrets.token_hex(16),
        payload=content,
        parents=parents,
    )
    sig = hmac.new(session_key, _canonical_signing_input(env), sha256).hexdigest()
    env.sig = sig
    return env


def verify(env: CCPTEnvelope, session_key: bytes, expected_session_id: str | None = None) -> bool:
    """Constant-time verify the envelope's HMAC and (optionally) session binding."""
    if env.ccpt_v != CCPT_VERSION:
        return False
    if expected_session_id is not None and env.session_id != expected_session_id:
        return False
    expected_sig = hmac.new(session_key, _canonical_signing_input(env), sha256).hexdigest()
    return hmac.compare_digest(expected_sig, env.sig)


def strip(env: CCPTEnvelope) -> str:
    """Return only the raw payload — the form the upstream model receives."""
    return env.payload


def derive_child(
    parent: CCPTEnvelope,
    new_payload: str,
    origin: Origin,
    session_key: bytes,
    level: Level | None = None,
) -> CCPTEnvelope:
    """Create a child envelope that propagates parent provenance.

    Used for taint propagation: when content derived from an L0 source is
    rephrased or summarized, the child inherits the parent's chunk_id in
    its `parents` tuple. The child's level defaults to the parent's level —
    callers can override only with explicit caution.
    """
    inherited_level = level if level is not None else parent.level
    return tag(
        new_payload,
        origin=origin,
        session_key=session_key,
        session_id=parent.session_id,
        level=inherited_level,
        parents=(*parent.parents, parent.chunk_id),
    )


def serialize(env: CCPTEnvelope) -> str:
    """Compact base64-JSON encoding for transport between components."""
    raw = json.dumps(env.to_dict(), separators=(",", ":")).encode("utf-8")
    return "ccpt1." + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def deserialize(blob: str) -> CCPTEnvelope:
    if not blob.startswith("ccpt1."):
        raise ValueError("not a ccpt1 envelope")
    b64 = blob[len("ccpt1.") :]
    pad = "=" * (-len(b64) % 4)
    raw = base64.urlsafe_b64decode(b64 + pad)
    return CCPTEnvelope.from_dict(json.loads(raw))


def lowest_level(envs: list[CCPTEnvelope]) -> Level:
    """Return the lowest (least-trusted) level among a set of envelopes.

    Used by the Lattice Gate to compute the effective trust floor for
    composed inputs (a system+user prompt mixed with retrieved L0 content
    has effective level L0 for purposes of action authorization).
    """
    if not envs:
        return Level.L3
    return min(envs, key=lambda e: e.level.rank).level
