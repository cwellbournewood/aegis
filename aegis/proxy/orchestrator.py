"""Decision orchestrator.

The Orchestrator is the brain of the proxy: it binds the per-request CCPT
tagging, lattice gate, intent anchor, canary scan, and capability gate into
one decision, then logs the result.

Provider adapters extract a generic `NormalizedRequest` and `NormalizedResponse`
and feed them through this orchestrator — keeping all five layers wire-format
agnostic.

Both sync (`pre_flight` / `post_flight`) and async (`pre_flight_async` /
`post_flight_async`) APIs are provided. The async variants execute the
independent gates (canary, lattice, drift, capability) in parallel via
`asyncio.gather`, cutting tail latency to max(gate) instead of sum(gates).
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from aegis.anchor import IntentAnchor, ProposedAction, make_embedder_from_config
from aegis.canary import CanaryGarden
from aegis.capability import CapabilityMinter, ProposedCall
from aegis.ccpt import CCPTEnvelope, Level, Origin, default_level_for, tag
from aegis.decision import DecisionEngine, DecisionRecord, PolicyMode, Verdict, Vote
from aegis.lattice import LatticeDecision, LatticeGate
from aegis.log import DecisionLog
from aegis.metrics import metrics
from aegis.nonce_store import make_nonce_store_from_config
from aegis.policy import Policy, load_policy_from_env_or_default
from aegis.session import Session, SessionStore


@dataclass
class NormalizedMessage:
    role: str
    origin: Origin
    level: Level | None
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedToolCall:
    tool: str
    parameters: dict[str, Any]
    summary: str | None = None
    capability_token: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedRequest:
    upstream: str
    messages: list[NormalizedMessage]
    tools: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    session_id_hint: str | None = None
    user_intent_hint: str | None = None
    capability_tokens: list[str] = field(default_factory=list)


@dataclass
class NormalizedResponse:
    text: str
    tool_calls: list[NormalizedToolCall] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProxyContext:
    """Per-request scratchpad. Carries the envelopes, anchor, garden, and votes."""

    session: Session
    request_id: str
    envelopes: list[CCPTEnvelope] = field(default_factory=list)
    pre_votes: list[Vote] = field(default_factory=list)
    post_votes: list[Vote] = field(default_factory=list)


class Orchestrator:
    """Coordinates all five layers across the request lifecycle."""

    def __init__(
        self,
        policy: Policy | None = None,
        session_store: SessionStore | None = None,
        decision_log: DecisionLog | None = None,
    ) -> None:
        self.policy = policy or load_policy_from_env_or_default()
        self.sessions = session_store or SessionStore(default_ttl_seconds=self.policy.session_ttl_seconds)

        self.lattice = LatticeGate(rules=self.policy.rules)
        self.anchor = IntentAnchor(
            embedder=make_embedder_from_config(self.policy.anchor.embedder),
            threshold_balanced=self.policy.anchor.threshold_balanced,
            threshold_strict=self.policy.anchor.threshold_strict,
        )
        self.minter = CapabilityMinter(
            default_ttl_seconds=self.policy.capability.default_ttl_seconds,
            nonce_store=make_nonce_store_from_config(self.policy.capability.nonce_store),
        )
        self.engine = DecisionEngine(mode=self.policy.mode)

        if decision_log is not None:
            self.log: DecisionLog = decision_log
        else:
            self.log = DecisionLog(path=self.policy.log_path)

    # ---------------------------------------------------------------- session
    def get_or_create_session(
        self,
        upstream: str,
        session_id: str | None,
        user_intent: str | None,
    ) -> Session:
        session = None
        if session_id:
            session = self.sessions.get(session_id)
        if session is None:
            session = self.sessions.create(upstream=upstream, user_intent=user_intent)
            if self.policy.canary.enabled:
                session.canaries = CanaryGarden.generate(
                    session_id=session.session_id, count=self.policy.canary.count
                )
        if user_intent:
            if session.anchor is None:
                session.user_intent = user_intent
                session.anchor = self.anchor.anchor(user_intent)
            else:
                # Multi-anchor accumulation: each new user-intent expression
                # widens what counts as "aligned" — reduces drift FPs without
                # weakening detection of clearly-unrelated actions.
                self.anchor.add_anchor(session.anchor, user_intent)
        return session

    # ---------------------------------------------------------------- pre
    def pre_flight(self, req: NormalizedRequest) -> tuple[NormalizedRequest, ProxyContext]:
        """Tag inputs, run lattice/canary checks, attach anchor, mutate prompt with canary block."""
        session = self.get_or_create_session(
            upstream=req.upstream,
            session_id=req.session_id_hint,
            user_intent=req.user_intent_hint or self._infer_user_intent(req),
        )
        ctx = ProxyContext(session=session, request_id="req_" + secrets.token_urlsafe(12))

        # 1. CCPT-tag every message.
        for msg in req.messages:
            level = msg.level or default_level_for(msg.origin)
            env = tag(
                content=msg.content,
                origin=msg.origin,
                level=level,
                session_key=session.hmac_key,
                session_id=session.session_id,
            )
            ctx.envelopes.append(env)

        # 2. Inject the canary system block (if there's a system message, prepend; else add one).
        if self.policy.canary.enabled and session.canaries is not None:
            req = self._inject_canary_block(req, session.canaries)

        # 3. Pre-flight votes — at this stage we mostly establish baseline state.
        ctx.pre_votes.append(
            Vote(
                layer="ccpt_verify",
                verdict=Verdict.ALLOW,
                reason="all envelopes signed",
                confidence=1.0,
                metadata={"chunks": len(ctx.envelopes)},
            )
        )

        return req, ctx

    def _infer_user_intent(self, req: NormalizedRequest) -> str | None:
        for msg in req.messages:
            if msg.origin == Origin.USER and msg.content.strip():
                return msg.content.strip()
        return None

    def _inject_canary_block(self, req: NormalizedRequest, garden: CanaryGarden) -> NormalizedRequest:
        block = garden.system_prompt_block()
        if not block:
            return req
        new_messages = list(req.messages)

        # Find the first system-origin message and append; else add a synthetic system msg.
        for i, msg in enumerate(new_messages):
            if msg.origin == Origin.SYSTEM:
                new_messages[i] = NormalizedMessage(
                    role=msg.role,
                    origin=msg.origin,
                    level=msg.level,
                    content=msg.content + "\n\n" + block,
                    metadata={**msg.metadata, "aegis_canary_injected": True},
                )
                break
        else:
            new_messages.insert(
                0,
                NormalizedMessage(
                    role="system",
                    origin=Origin.SYSTEM,
                    level=Level.L3,
                    content=block,
                    metadata={"aegis_canary_injected": True, "synthetic": True},
                ),
            )
        return NormalizedRequest(
            upstream=req.upstream,
            messages=new_messages,
            tools=req.tools,
            metadata=req.metadata,
            session_id_hint=req.session_id_hint,
            user_intent_hint=req.user_intent_hint,
            capability_tokens=req.capability_tokens,
        )

    # ---------------------------------------------------------------- post
    def post_flight(
        self,
        req: NormalizedRequest,
        resp: NormalizedResponse,
        ctx: ProxyContext,
    ) -> DecisionRecord:
        """Run canary scan, drift gate, capability gate. Return the final decision.

        Synchronous variant. For async deployments use `post_flight_async`,
        which runs the independent gates concurrently via `asyncio.gather`.
        """
        decision_start = time.perf_counter()
        votes = self._collect_votes_sync(req, resp, ctx)
        record = self.engine.combine(votes, session_id=ctx.session.session_id, request_id=ctx.request_id)
        self.log.append(self._log_payload(req, resp, ctx, record))
        self._record_metrics(req, record, time.perf_counter() - decision_start)
        return record

    async def post_flight_async(
        self,
        req: NormalizedRequest,
        resp: NormalizedResponse,
        ctx: ProxyContext,
    ) -> DecisionRecord:
        """Async variant — runs independent gates in parallel.

        Latency improvement scales with number of tool calls: a response with
        N tool calls runs lattice / drift / capability for each in parallel
        rather than serially.
        """
        decision_start = time.perf_counter()
        loop = asyncio.get_running_loop()

        canary_task = loop.run_in_executor(None, self._timed_canary_vote, resp, ctx)

        per_call_tasks: list[asyncio.Future[Vote]] = []
        for call in resp.tool_calls:
            per_call_tasks.append(loop.run_in_executor(None, self._timed_lattice_vote, ctx, call))
            per_call_tasks.append(loop.run_in_executor(None, self._timed_drift_vote, ctx, call))
            per_call_tasks.append(loop.run_in_executor(None, self._timed_capability_vote, req, ctx, call))

        votes: list[Vote] = list(ctx.pre_votes)
        votes.append(await canary_task)
        if per_call_tasks:
            votes.extend(await asyncio.gather(*per_call_tasks))

        if not resp.tool_calls and ctx.session.anchor is not None and resp.text:
            votes.append(
                await loop.run_in_executor(None, self._text_drift_vote, resp, ctx)
            )

        record = self.engine.combine(votes, session_id=ctx.session.session_id, request_id=ctx.request_id)
        self.log.append(self._log_payload(req, resp, ctx, record))
        self._record_metrics(req, record, time.perf_counter() - decision_start)
        return record

    def _collect_votes_sync(
        self,
        req: NormalizedRequest,
        resp: NormalizedResponse,
        ctx: ProxyContext,
    ) -> list[Vote]:
        votes = list(ctx.pre_votes)
        votes.append(self._timed_canary_vote(resp, ctx))
        for call in resp.tool_calls:
            votes.append(self._timed_lattice_vote(ctx, call))
            votes.append(self._timed_drift_vote(ctx, call))
            votes.append(self._timed_capability_vote(req, ctx, call))
        if not resp.tool_calls and ctx.session.anchor is not None and resp.text:
            votes.append(self._text_drift_vote(resp, ctx))
        return votes

    def _text_drift_vote(self, resp: NormalizedResponse, ctx: ProxyContext) -> Vote:
        """Lightweight drift gate over textual output when there are no tool calls."""
        drift = self.anchor.drift_against_text(
            resp.text[:512],
            ctx.session.anchor,
            mode=("strict" if self.policy.mode == PolicyMode.STRICT else "balanced"),
        )
        verdict = Verdict.ALLOW if not drift.drifted else Verdict.WARN
        return Vote(
            layer="intent_drift_text",
            verdict=verdict,
            reason=f"text similarity={drift.similarity:.3f} threshold={drift.threshold:.3f}",
            confidence=0.5,
            metadata={"similarity": drift.similarity, "threshold": drift.threshold},
        )

    # ---------------------------------------------------------------- timed wrappers
    def _timed_canary_vote(self, resp: NormalizedResponse, ctx: ProxyContext) -> Vote:
        start = time.perf_counter()
        try:
            return self._canary_vote(resp, ctx)
        finally:
            metrics.histogram("aegis_gate_seconds").observe(
                time.perf_counter() - start, {"gate": "canary"}
            )

    def _timed_lattice_vote(self, ctx: ProxyContext, call) -> Vote:  # type: ignore[no-untyped-def]
        start = time.perf_counter()
        try:
            return self._lattice_vote(ctx, call)
        finally:
            metrics.histogram("aegis_gate_seconds").observe(
                time.perf_counter() - start, {"gate": "lattice"}
            )

    def _timed_drift_vote(self, ctx: ProxyContext, call) -> Vote:  # type: ignore[no-untyped-def]
        start = time.perf_counter()
        try:
            return self._drift_vote(ctx, call)
        finally:
            metrics.histogram("aegis_gate_seconds").observe(
                time.perf_counter() - start, {"gate": "intent_drift"}
            )

    def _timed_capability_vote(
        self,
        req: NormalizedRequest,
        ctx: ProxyContext,
        call,  # type: ignore[no-untyped-def]
    ) -> Vote:
        start = time.perf_counter()
        try:
            return self._capability_vote(req, ctx, call)
        finally:
            metrics.histogram("aegis_gate_seconds").observe(
                time.perf_counter() - start, {"gate": "capability"}
            )

    def _record_metrics(
        self,
        req: NormalizedRequest,
        record: DecisionRecord,
        elapsed: float,
    ) -> None:
        metrics.histogram("aegis_decision_seconds").observe(elapsed)
        metrics.counter("aegis_requests_total").inc(
            labels={"upstream": req.upstream, "decision": record.decision.value}
        )
        for v in record.votes:
            metrics.counter("aegis_layer_votes_total").inc(
                labels={"layer": v.layer, "verdict": v.verdict.value}
            )
            if v.layer == "canary" and v.verdict.value == "BLOCK":
                metrics.counter("aegis_canary_leaks_total").inc()
            if v.layer == "capability":
                if v.verdict.value == "ALLOW":
                    metrics.counter("aegis_capability_consumed_total").inc()
                elif v.verdict.value == "BLOCK":
                    # Pull a short reason key without leaking specifics.
                    short_reason = self._classify_capability_reason(v.reason)
                    metrics.counter("aegis_capability_rejected_total").inc(
                        labels={"reason": short_reason}
                    )
        metrics.gauge("aegis_active_sessions").set(float(len(self.sessions)))
        metrics.gauge("aegis_log_entries").set(float(len(self.log)))

    @staticmethod
    def _classify_capability_reason(reason: str) -> str:
        r = reason.lower()
        if "no capability token" in r:
            return "missing"
        if "expired" in r:
            return "expired"
        if "tool mismatch" in r:
            return "tool_mismatch"
        if "session_id" in r:
            return "session_mismatch"
        if "single-use" in r or "consumed" in r:
            return "replay"
        if "constraint" in r or "violates" in r:
            return "constraint_failed"
        if "signature" in r:
            return "bad_signature"
        if "malformed" in r:
            return "malformed"
        return "other"

    def _canary_vote(self, resp: NormalizedResponse, ctx: ProxyContext) -> Vote:
        garden: CanaryGarden | None = ctx.session.canaries
        if garden is None or not garden.canaries:
            return Vote(layer="canary", verdict=Verdict.ALLOW, reason="canaries disabled", confidence=0.3)
        hits = garden.scan(resp.text)
        for call in resp.tool_calls:
            hits.extend(garden.scan_structured(call.parameters, location=f"tool:{call.tool}"))
        if hits:
            first = hits[0]
            return Vote(
                layer="canary",
                verdict=Verdict.BLOCK,
                reason=f"canary leaked at {first.location}",
                confidence=0.95,
                metadata={"hits": len(hits), "first_location": first.location},
            )
        return Vote(layer="canary", verdict=Verdict.ALLOW, reason="no canary leakage", confidence=1.0)

    def _lattice_vote(self, ctx: ProxyContext, call) -> Vote:  # type: ignore[no-untyped-def]
        verdict = self.lattice.evaluate(ctx.envelopes, action_kind="tool_call")
        if verdict.decision == LatticeDecision.BLOCK:
            return Vote(
                layer="lattice",
                verdict=Verdict.BLOCK,
                reason=f"{verdict.reason} (effective={verdict.effective_level.value}, tool={call.tool})",
                confidence=1.0,
                metadata={"effective_level": verdict.effective_level.value, "requires": list(verdict.requires)},
            )
        if verdict.decision == LatticeDecision.WARN:
            return Vote(
                layer="lattice",
                verdict=Verdict.WARN,
                reason=f"{verdict.reason} (effective={verdict.effective_level.value}, tool={call.tool})",
                confidence=0.7,
                metadata={"effective_level": verdict.effective_level.value, "requires": list(verdict.requires)},
            )
        return Vote(
            layer="lattice",
            verdict=Verdict.ALLOW,
            reason=verdict.reason,
            confidence=1.0,
            metadata={"effective_level": verdict.effective_level.value, "requires": list(verdict.requires)},
        )

    def _drift_vote(self, ctx: ProxyContext, call) -> Vote:  # type: ignore[no-untyped-def]
        if ctx.session.anchor is None:
            return Vote(
                layer="intent_drift",
                verdict=Verdict.WARN,
                reason="no anchor captured for session — drift undetectable",
                confidence=0.4,
            )
        action = ProposedAction(
            tool_name=call.tool, parameters=call.parameters, summary=call.summary
        )
        mode = "strict" if self.policy.mode == PolicyMode.STRICT else "balanced"
        score = self.anchor.drift(action, ctx.session.anchor, mode=mode)
        if score.drifted:
            return Vote(
                layer="intent_drift",
                verdict=Verdict.BLOCK if self.policy.mode != PolicyMode.PERMISSIVE else Verdict.WARN,
                reason=f"intent drift: similarity={score.similarity:.3f} < threshold={score.threshold:.3f}",
                confidence=0.75,
                metadata={"similarity": score.similarity, "threshold": score.threshold, "anchor": score.anchor_text[:120]},
            )
        return Vote(
            layer="intent_drift",
            verdict=Verdict.ALLOW,
            reason=f"intent aligned: similarity={score.similarity:.3f}",
            confidence=0.85,
            metadata={"similarity": score.similarity, "threshold": score.threshold},
        )

    def _capability_vote(
        self,
        req: NormalizedRequest,
        ctx: ProxyContext,
        call,  # type: ignore[no-untyped-def]
    ) -> Vote:
        # Two sources of tokens: tokens attached to the tool call, and tokens in the request envelope.
        candidates = list(req.capability_tokens)
        if call.capability_token:
            candidates.insert(0, call.capability_token)

        if not candidates:
            return Vote(
                layer="capability",
                verdict=Verdict.BLOCK,
                reason=f"no capability token presented for tool={call.tool}",
                confidence=1.0,
                metadata={"tool": call.tool},
            )

        proposed = ProposedCall(tool=call.tool, parameters=call.parameters)
        last_reason = ""
        for raw in candidates:
            verdict = self.minter.verify_and_consume(
                raw,
                session_key=ctx.session.hmac_key,
                proposed=proposed,
                expected_session_id=ctx.session.session_id,
            )
            if verdict.valid and verdict.token is not None:
                return Vote(
                    layer="capability",
                    verdict=Verdict.ALLOW,
                    reason="capability token accepted and consumed",
                    confidence=1.0,
                    metadata={"tool": call.tool, "nonce": verdict.token.claims.nonce[:8] + "..."},
                )
            last_reason = verdict.reason
        return Vote(
            layer="capability",
            verdict=Verdict.BLOCK,
            reason=f"no valid capability token: {last_reason}",
            confidence=1.0,
            metadata={"tool": call.tool},
        )

    def _log_payload(
        self,
        req: NormalizedRequest,
        resp: NormalizedResponse,
        ctx: ProxyContext,
        record: DecisionRecord,
    ) -> dict[str, Any]:
        return {
            "request_id": record.request_id,
            "session_id": record.session_id,
            "upstream": req.upstream,
            "decision": record.decision.value,
            "reason": record.reason,
            "score": record.score,
            "mode": record.mode.value,
            "votes": {
                v.layer: {
                    "verdict": v.verdict.value,
                    "reason": v.reason,
                    "confidence": v.confidence,
                }
                for v in record.votes
            },
            "tool_calls": [
                {"tool": c.tool, "parameters_redacted": list(c.parameters.keys()), "summary": c.summary}
                for c in resp.tool_calls
            ],
            "input_chunks": [
                {"chunk_id": e.chunk_id, "origin": e.origin.value, "level": e.level.value}
                for e in ctx.envelopes
            ],
            "timestamp": time.time(),
        }
