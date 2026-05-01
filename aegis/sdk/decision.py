"""Typed decision objects exposed by the AEGIS SDK.

Every response from a proxied LLM call has an `aegis` field in its body that
encodes the orchestrator's decision. This module provides typed wrappers so
developers see structured, debuggable objects instead of nested dicts.

The contract:

    >>> result = client.messages.create(...)
    >>> aegis_decision = AegisDecision.from_response(result)
    >>> aegis_decision.decision         # 'ALLOW' | 'WARN' | 'BLOCK'
    >>> aegis_decision.votes['lattice'] # AegisVote(verdict, reason, confidence)
    >>> aegis_decision.warnings         # list[AegisWarning] for any WARN votes
    >>> aegis_decision.blocked_by       # tuple of layer names that voted BLOCK

When the proxy returns HTTP 451 (BLOCK), use `AegisDecisionBlocked.from_http_error`
to lift the response into a typed exception with `suggested_fix`.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AegisVote:
    """A single layer's vote on a request."""

    layer: str
    verdict: str  # 'ALLOW' | 'WARN' | 'BLOCK'
    reason: str
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.layer}: {self.verdict} ({self.reason})"


@dataclass(frozen=True)
class AegisWarning:
    """A WARN-level signal, the request passed but a gate flagged it.

    Useful for `permissive` / `balanced` modes where you want to see what
    *would have been* blocked in stricter modes.
    """

    layer: str
    message: str
    request_id: str

    def __str__(self) -> str:
        return f"[AegisWarning] {self.layer}: {self.message} (req={self.request_id})"


@dataclass(frozen=True)
class AegisDecision:
    """The orchestrator's decision attached to a successful upstream response."""

    decision: str  # 'ALLOW' | 'WARN'
    request_id: str
    session_id: str
    score: float
    mode: str
    reason: str
    votes: dict[str, AegisVote]
    blocked_by: tuple[str, ...] = ()
    warnings: tuple[AegisWarning, ...] = ()

    @classmethod
    def from_response(cls, response: Any) -> AegisDecision | None:
        """Lift the `aegis` field out of an upstream response.

        Accepts the response in several shapes:
            - a dict (the parsed JSON)
            - an SDK response object exposing `.model_dump()` or `.dict()`
            - a raw response object with an `aegis` attribute
        """
        body = _coerce_to_dict(response)
        if body is None:
            return None
        aegis_block = body.get("aegis")
        if not isinstance(aegis_block, dict):
            return None
        return cls._from_dict(aegis_block)

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> AegisDecision:
        votes_raw = d.get("votes", {}) or {}
        votes: dict[str, AegisVote] = {}
        warnings: list[AegisWarning] = []
        request_id = d.get("request_id", "")
        for layer, raw in votes_raw.items():
            if not isinstance(raw, dict):
                continue
            vote = AegisVote(
                layer=layer,
                verdict=raw.get("verdict", "ALLOW"),
                reason=raw.get("reason", ""),
                confidence=float(raw.get("confidence", 1.0)),
                metadata=raw.get("metadata", {}) or {},
            )
            votes[layer] = vote
            if vote.verdict == "WARN":
                warnings.append(
                    AegisWarning(
                        layer=layer,
                        message=raw.get("reason", ""),
                        request_id=request_id,
                    )
                )

        blocked_by = tuple(layer for layer, v in votes.items() if v.verdict == "BLOCK")

        return cls(
            decision=str(d.get("decision", "ALLOW")),
            request_id=request_id,
            session_id=str(d.get("session_id", "")),
            score=float(d.get("score", 0.0)),
            mode=str(d.get("mode", "balanced")),
            reason=str(d.get("reason", "")),
            votes=votes,
            blocked_by=blocked_by,
            warnings=tuple(warnings),
        )

    def __iter__(self) -> Iterator[AegisVote]:
        return iter(self.votes.values())

    def pretty(self) -> str:
        """Human-readable summary, suitable for logging / debugging."""
        lines = [
            f"AegisDecision({self.decision}, request_id={self.request_id}, mode={self.mode})",
            f"  reason: {self.reason}",
            f"  score:  {self.score:.3f}",
            "  votes:",
        ]
        for layer, vote in self.votes.items():
            mark = {"ALLOW": "✓", "WARN": "!", "BLOCK": "✗"}.get(vote.verdict, "?")
            lines.append(f"    {mark} {layer:<14} {vote.verdict:<6} {vote.reason}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Block exception with suggested fix
# ---------------------------------------------------------------------------


_FIX_HINTS: dict[str, str] = {
    "lattice": (
        "If this action is legitimate, the causal-origin level is too low. "
        "Either upgrade the source (move retrieved content from L0 → L1 by "
        "adjusting the adapter), or accept the block. L0 should not authorize "
        "tool calls."
    ),
    "capability": (
        "Mint a capability token for this exact (tool, parameters) before the call:\n"
        "    session.capabilities.mint(\"<tool>\", constraints={...})\n"
        "Tight constraints (`eq`, `regex`, `prefix`) are stronger than `any`."
    ),
    "intent_drift": (
        "The proposed action is semantically far from the user's stated intent. "
        "If this is a legitimate sub-task, either declare the new intent on the "
        "session (via add_anchor / a new top-level user message) or lower "
        "anchor.threshold_balanced in the policy."
    ),
    "intent_drift_text": (
        "The model's response text drifted from the user's stated intent. "
        "Usually a soft signal (WARN); if you see this firing on legitimate "
        "responses, lower anchor.threshold_balanced."
    ),
    "canary": (
        "A canary token leaked in the response. This is high-confidence "
        "evidence of injection, review the audit log for the source content "
        "and quarantine it. False positives here are very rare; investigate "
        "before tuning."
    ),
    "ccpt_verify": (
        "An envelope failed signature verification. This is a configuration or "
        "tampering bug, investigate the audit log entry; it should never fire "
        "during normal operation."
    ),
}


def _suggested_fix_for(blocked_by: tuple[str, ...]) -> str:
    if not blocked_by:
        return ""
    parts = []
    for layer in blocked_by:
        hint = _FIX_HINTS.get(layer)
        if hint:
            parts.append(f"  [{layer}]\n  " + hint.replace("\n", "\n  "))
    if not parts:
        return ""
    return "Suggested fix:\n" + "\n".join(parts)


@dataclass
class AegisDecisionBlocked(Exception):  # noqa: N818  (public API: kept verb-form name)
    """Raised when the AEGIS proxy blocks an LLM request.

    Contains every layer that voted BLOCK with its reason, plus a concrete
    `suggested_fix` string the developer can act on.
    """

    decision: AegisDecision
    suggested_fix: str = ""

    def __post_init__(self) -> None:
        if not self.suggested_fix:
            self.suggested_fix = _suggested_fix_for(self.decision.blocked_by)
        Exception.__init__(self, self._message())

    def _message(self) -> str:
        return f"AEGIS blocked: {self.decision.reason} (request_id={self.decision.request_id})"

    def __str__(self) -> str:
        return self.pretty()

    @property
    def request_id(self) -> str:
        return self.decision.request_id

    @property
    def blocked_by(self) -> tuple[str, ...]:
        return self.decision.blocked_by

    def pretty(self) -> str:
        block_votes = [
            self.decision.votes[layer]
            for layer in self.decision.blocked_by
            if layer in self.decision.votes
        ]
        lines = [
            f"AegisDecisionBlocked: {self.decision.reason}",
            f"  request_id:  {self.decision.request_id}",
            f"  session_id:  {self.decision.session_id}",
            f"  blocked_by:  {list(self.decision.blocked_by)}",
            "  reasons:",
        ]
        for v in block_votes:
            lines.append(f"    {v.layer}: {v.reason}")
        if self.suggested_fix:
            lines.append("")
            lines.append(self.suggested_fix)
        return "\n".join(lines)

    @classmethod
    def from_http_error(cls, payload: dict[str, Any]) -> AegisDecisionBlocked:
        """Lift an HTTP 451 response body into an AegisDecisionBlocked.

        The proxy emits payloads of shape:
            {
              "error": {"type": "aegis_blocked", "message": "...",
                        "decision": "BLOCK", "request_id": "...", "session_id": "..."},
              "aegis": { ...full decision...}
            }
        """
        aegis_block = payload.get("aegis", {}) if isinstance(payload, dict) else {}
        decision = AegisDecision._from_dict(aegis_block) if aegis_block else AegisDecision(
            decision="BLOCK",
            request_id=str(payload.get("error", {}).get("request_id", "")),
            session_id=str(payload.get("error", {}).get("session_id", "")),
            score=0.0,
            mode="unknown",
            reason=str(payload.get("error", {}).get("message", "blocked")),
            votes={},
            blocked_by=(),
            warnings=(),
        )
        return cls(decision=decision)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_to_dict(response: Any) -> dict[str, Any] | None:
    if response is None:
        return None
    if isinstance(response, dict):
        return response
    # Pydantic v2 model
    if hasattr(response, "model_dump"):
        try:
            d = response.model_dump()
            if isinstance(d, dict):
                return d
        except Exception:
            pass
    # Pydantic v1 model / Anthropic SDK Message has `.dict()`
    if hasattr(response, "dict"):
        try:
            d = response.dict()
            if isinstance(d, dict):
                return d
        except Exception:
            pass
    # Direct attribute access
    if hasattr(response, "aegis"):
        wrapper = {"aegis": response.aegis}
        return wrapper
    return None


def attach_decision(response: Any) -> AegisDecision | None:
    """Lift the AEGIS decision off a response in-place if possible.

    Returns the typed `AegisDecision`, and also attaches it as `response.aegis`
    when the response object accepts attribute assignment.
    """
    decision = AegisDecision.from_response(response)
    if decision is None:
        return None
    with contextlib.suppress(AttributeError, TypeError):
        response.aegis = decision
    return decision
