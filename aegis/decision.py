"""Decision Engine.

Combines votes from each layer into a single ALLOW / WARN / BLOCK decision
according to a configurable policy mode (strict / balanced / permissive).
Emits structured records for the hash-chained log.
"""

from __future__ import annotations

import enum
import secrets
import time
from dataclasses import dataclass, field
from typing import Any


class Verdict(str, enum.Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class PolicyMode(str, enum.Enum):
    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"


@dataclass
class Vote:
    layer: str
    verdict: Verdict
    reason: str
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DecisionRecord:
    decision: Verdict
    reason: str
    votes: list[Vote]
    score: float
    session_id: str
    request_id: str
    timestamp: float
    mode: PolicyMode

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "votes": {v.layer: {"verdict": v.verdict.value, "reason": v.reason, "confidence": v.confidence, "metadata": v.metadata} for v in self.votes},
            "score": self.score,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "mode": self.mode.value,
        }


_VERDICT_WEIGHT: dict[Verdict, float] = {
    Verdict.ALLOW: 0.0,
    Verdict.WARN: 0.5,
    Verdict.BLOCK: 1.0,
}


class DecisionEngine:
    """Combines per-layer votes into a final verdict.

    Strict:     any single BLOCK blocks; any TWO WARNs block.
    Balanced:   any single BLOCK blocks; WARNs logged but pass.
    Permissive: nothing blocks; everything is logged.
    """

    def __init__(self, mode: PolicyMode = PolicyMode.BALANCED) -> None:
        self.mode = mode

    def combine(
        self,
        votes: list[Vote],
        session_id: str,
        request_id: str | None = None,
    ) -> DecisionRecord:
        if request_id is None:
            request_id = "req_" + secrets.token_urlsafe(12)

        block_votes = [v for v in votes if v.verdict == Verdict.BLOCK]
        warn_votes = [v for v in votes if v.verdict == Verdict.WARN]

        score = self._score(votes)

        if self.mode == PolicyMode.PERMISSIVE:
            decision = Verdict.ALLOW
            reason = "permissive mode (logged only)"
            if block_votes:
                reason = f"would BLOCK in stricter modes: {block_votes[0].reason}"
            elif warn_votes:
                reason = f"would WARN: {warn_votes[0].reason}"
        elif self.mode == PolicyMode.STRICT:
            if block_votes:
                decision = Verdict.BLOCK
                reason = block_votes[0].reason
            elif len(warn_votes) >= 2:
                decision = Verdict.BLOCK
                reason = f"two or more WARNs in strict mode: {warn_votes[0].reason}; {warn_votes[1].reason}"
            elif warn_votes:
                decision = Verdict.WARN
                reason = warn_votes[0].reason
            else:
                decision = Verdict.ALLOW
                reason = "all gates ALLOW"
        else:  # balanced
            if block_votes:
                decision = Verdict.BLOCK
                reason = block_votes[0].reason
            elif warn_votes:
                decision = Verdict.WARN
                reason = warn_votes[0].reason
            else:
                decision = Verdict.ALLOW
                reason = "all gates ALLOW"

        return DecisionRecord(
            decision=decision,
            reason=reason,
            votes=votes,
            score=score,
            session_id=session_id,
            request_id=request_id,
            timestamp=time.time(),
            mode=self.mode,
        )

    def _score(self, votes: list[Vote]) -> float:
        if not votes:
            return 0.0
        total = 0.0
        weight_total = 0.0
        for v in votes:
            w = max(0.0, min(1.0, v.confidence))
            total += _VERDICT_WEIGHT[v.verdict] * w
            weight_total += w
        if weight_total == 0:
            return 0.0
        return round(total / weight_total, 4)
