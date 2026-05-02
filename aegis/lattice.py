"""Trust Lattice Enforcement.

Bell-LaPadula-style information flow rules over CCPT-tagged content. The
lattice gate consults a declarative policy to decide whether content at a
given trust level is authorized to:

    - Reach a tool call ("write up")
    - Reference / instruct against content at a higher level ("read up")

The core invariant: any tool call must trace its causal origin to L2 or L3
content. L0/L1 content can inform answers but cannot authorize actions.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from aegis.ccpt import CCPTEnvelope, Level


class LatticeDecision(str, enum.Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass
class FlowRule:
    """A single declarative rule.

    Matches when:
        - the *minimum* causal-origin level of the proposed action's inputs
          is at-or-below `from_level`, AND
        - the action `to` matches the rule's `to` (e.g. "tool_call").
    """

    from_level: Level
    to: str
    decision: LatticeDecision
    require: tuple[str, ...] = field(default_factory=tuple)
    reason: str = ""

    def matches(self, effective_level: Level, action_kind: str) -> bool:
        if action_kind != self.to:
            return False
        return effective_level.rank <= self.from_level.rank


def default_rules() -> list[FlowRule]:
    """Default lattice policy.

    L0 → tool_call    : BLOCK   (untrusted content can never authorize actions)
    L1 → tool_call    : WARN    (RAG content gets a warn signal, capability tokens still required)
    L2 → tool_call    : ALLOW   (authenticated user can authorize, with capability token)
    L3 → tool_call    : ALLOW   (system can authorize)
    L0 → response_ref : WARN    (model citing L0 content gets a soft signal)
    """
    return [
        FlowRule(Level.L0, "tool_call", LatticeDecision.BLOCK, reason="L0 cannot authorize tool calls"),
        FlowRule(Level.L1, "tool_call", LatticeDecision.WARN, reason="L1 origin requires elevated review"),
        FlowRule(Level.L2, "tool_call", LatticeDecision.ALLOW, require=("capability_token",), reason="L2 ok with capability token"),
        FlowRule(Level.L3, "tool_call", LatticeDecision.ALLOW, reason="L3 system origin"),
        FlowRule(Level.L0, "response_ref", LatticeDecision.WARN, reason="response references L0 content"),
    ]


@dataclass
class LatticeVerdict:
    decision: LatticeDecision
    matched_rule: FlowRule | None
    effective_level: Level
    requires: tuple[str, ...]
    reason: str


class LatticeGate:
    """Evaluates flow rules against CCPT-tagged inputs.

    The gate does not make capability decisions itself, it can mark a flow
    as needing a `capability_token`, which is then enforced by the Capability
    Gate. This separation of concerns is deliberate: the lattice decides
    *whether the trust shape is right*, and capability tokens decide *whether
    the user actually authorized this specific call*.
    """

    def __init__(self, rules: list[FlowRule] | None = None) -> None:
        self.rules: list[FlowRule] = rules if rules is not None else default_rules()

    def evaluate(
        self,
        causal_inputs: list[CCPTEnvelope],
        action_kind: str = "tool_call",
    ) -> LatticeVerdict:
        # Action with no traceable causal origin is suspicious, treat as L0.
        effective = (
            Level.L0 if not causal_inputs else min(env.level for env in causal_inputs)
        )

        # Iterate from most-restrictive (lowest from_level) to least.
        ordered = sorted(self.rules, key=lambda r: r.from_level.rank)
        for rule in ordered:
            if rule.matches(effective, action_kind):
                return LatticeVerdict(
                    decision=rule.decision,
                    matched_rule=rule,
                    effective_level=effective,
                    requires=rule.require,
                    reason=rule.reason or f"{action_kind} from {effective.value}",
                )

        return LatticeVerdict(
            decision=LatticeDecision.ALLOW,
            matched_rule=None,
            effective_level=effective,
            requires=(),
            reason="no matching rule (default-allow)",
        )
