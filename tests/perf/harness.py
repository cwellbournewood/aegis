"""Latency / throughput measurement harness.

Used by both `aegis bench-perf` and CI-asserted regression tests. We avoid
external benchmark deps (pytest-benchmark, asv), keeping this self-contained
makes the numbers easy to reason about and the tests easy to read.
"""

from __future__ import annotations

import gc
import statistics
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from aegis.ccpt import Level, Origin
from aegis.metrics import metrics
from aegis.policy import Policy
from aegis.proxy.orchestrator import (
    NormalizedMessage,
    NormalizedRequest,
    NormalizedResponse,
    NormalizedToolCall,
    Orchestrator,
)


@dataclass
class LatencyResult:
    n: int
    p50_ms: float
    p90_ms: float
    p99_ms: float
    mean_ms: float
    min_ms: float
    max_ms: float

    def __str__(self) -> str:
        return (
            f"n={self.n:>5}  p50={self.p50_ms:7.3f}ms  p90={self.p90_ms:7.3f}ms  "
            f"p99={self.p99_ms:7.3f}ms  mean={self.mean_ms:7.3f}ms  "
            f"min={self.min_ms:7.3f}ms  max={self.max_ms:7.3f}ms"
        )


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * pct
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def measure_sync(
    fn: Callable[[], object],
    *,
    iterations: int = 200,
    warmup: int = 20,
) -> LatencyResult:
    """Run `fn` `iterations` times after `warmup`, return percentile stats."""
    for _ in range(warmup):
        fn()
    gc.disable()
    try:
        timings: list[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            fn()
            timings.append((time.perf_counter() - t0) * 1000.0)
    finally:
        gc.enable()
    return LatencyResult(
        n=len(timings),
        p50_ms=_percentile(timings, 0.50),
        p90_ms=_percentile(timings, 0.90),
        p99_ms=_percentile(timings, 0.99),
        mean_ms=statistics.mean(timings),
        min_ms=min(timings),
        max_ms=max(timings),
    )


async def measure_async(
    fn: Callable[[], Awaitable[object]],
    *,
    iterations: int = 200,
    warmup: int = 20,
) -> LatencyResult:
    for _ in range(warmup):
        await fn()
    gc.disable()
    try:
        timings: list[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            await fn()
            timings.append((time.perf_counter() - t0) * 1000.0)
    finally:
        gc.enable()
    return LatencyResult(
        n=len(timings),
        p50_ms=_percentile(timings, 0.50),
        p90_ms=_percentile(timings, 0.90),
        p99_ms=_percentile(timings, 0.99),
        mean_ms=statistics.mean(timings),
        min_ms=min(timings),
        max_ms=max(timings),
    )


# ---------------------------------------------------------------------------
# Workload builders
# ---------------------------------------------------------------------------


def build_simple_text_workload() -> tuple[Orchestrator, Callable[[], None]]:
    """One user message, one text response, no tool calls. Baseline workload."""
    p = Policy.default()
    p.log_path = None
    orch = Orchestrator(policy=p)
    metrics.reset_for_tests()

    req = NormalizedRequest(
        upstream="anthropic",
        messages=[
            NormalizedMessage(role="user", origin=Origin.USER, level=Level.L2, content="hello, please summarize my latest invoice email"),
        ],
    )

    def run() -> None:
        augmented, ctx = orch.pre_flight(req)
        resp = NormalizedResponse(text="Sure, I'll summarize your latest invoice email.", tool_calls=[])
        orch.post_flight(augmented, resp, ctx)

    return orch, run


def build_tool_call_workload(num_tool_calls: int = 1) -> tuple[Orchestrator, Callable[[], None]]:
    """User message + N tool calls, exercises lattice/drift/capability per call."""
    p = Policy.default()
    p.log_path = None
    orch = Orchestrator(policy=p)
    metrics.reset_for_tests()

    sess = orch.get_or_create_session(upstream="anthropic", session_id=None, user_intent="email alice")
    tok = orch.minter.mint(
        tool="send_email",
        session_id=sess.session_id,
        session_key=sess.hmac_key,
        single_use=False,  # reuse for benchmarking
    )

    req = NormalizedRequest(
        upstream="anthropic",
        messages=[
            NormalizedMessage(role="user", origin=Origin.USER, level=Level.L2, content="email alice the meeting notes"),
        ],
        session_id_hint=sess.session_id,
        capability_tokens=[tok.raw],
    )

    def run() -> None:
        augmented, ctx = orch.pre_flight(req)
        resp = NormalizedResponse(
            text="Sending the email now.",
            tool_calls=[
                NormalizedToolCall(
                    tool="send_email",
                    parameters={"to": "alice@x.com", "body": "meeting notes attached"},
                    summary="email alice the meeting notes",
                )
                for _ in range(num_tool_calls)
            ],
        )
        orch.post_flight(augmented, resp, ctx)

    return orch, run


def build_async_tool_call_workload(num_tool_calls: int = 4):
    """Async variant of the tool-call workload, exercises the parallel orchestrator."""
    p = Policy.default()
    p.log_path = None
    orch = Orchestrator(policy=p)
    metrics.reset_for_tests()

    sess = orch.get_or_create_session(upstream="anthropic", session_id=None, user_intent="email alice")
    tok = orch.minter.mint(
        tool="send_email", session_id=sess.session_id, session_key=sess.hmac_key, single_use=False
    )

    req = NormalizedRequest(
        upstream="anthropic",
        messages=[
            NormalizedMessage(role="user", origin=Origin.USER, level=Level.L2, content="email alice the meeting notes"),
        ],
        session_id_hint=sess.session_id,
        capability_tokens=[tok.raw],
    )

    async def run() -> None:
        augmented, ctx = orch.pre_flight(req)
        resp = NormalizedResponse(
            text="Sending the email now.",
            tool_calls=[
                NormalizedToolCall(
                    tool="send_email",
                    parameters={"to": "alice@x.com", "body": "meeting notes attached"},
                    summary="email alice the meeting notes",
                )
                for _ in range(num_tool_calls)
            ],
        )
        await orch.post_flight_async(augmented, resp, ctx)

    return orch, run


def build_large_context_workload(num_messages: int = 50) -> tuple[Orchestrator, Callable[[], None]]:
    """50-message conversation history, exercises CCPT tagging cost."""
    p = Policy.default()
    p.log_path = None
    orch = Orchestrator(policy=p)
    metrics.reset_for_tests()

    msgs = [NormalizedMessage(role="system", origin=Origin.SYSTEM, level=Level.L3, content="You assist.")]
    for i in range(num_messages):
        if i % 2 == 0:
            msgs.append(
                NormalizedMessage(role="user", origin=Origin.USER, level=Level.L2, content=f"turn {i} user message about topic")
            )
        else:
            msgs.append(
                NormalizedMessage(role="assistant", origin=Origin.AGENT, level=Level.L1, content=f"turn {i} assistant reply")
            )

    req = NormalizedRequest(upstream="anthropic", messages=msgs)

    def run() -> None:
        augmented, ctx = orch.pre_flight(req)
        resp = NormalizedResponse(text="acknowledged.", tool_calls=[])
        orch.post_flight(augmented, resp, ctx)

    return orch, run


# ---------------------------------------------------------------------------
# Throughput
# ---------------------------------------------------------------------------


def measure_throughput(fn: Callable[[], None], duration_seconds: float = 1.0) -> float:
    """Run fn in a tight loop for `duration_seconds`, return ops/sec."""
    # Warmup
    for _ in range(50):
        fn()
    gc.disable()
    try:
        deadline = time.perf_counter() + duration_seconds
        count = 0
        while time.perf_counter() < deadline:
            fn()
            count += 1
        elapsed = time.perf_counter() - (deadline - duration_seconds)
    finally:
        gc.enable()
    return count / elapsed
