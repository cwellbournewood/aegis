"""Performance regression tests with CI-asserted targets.

The RFP specifies:
    - Added p50 latency < 100ms (hard cap < 150ms)
    - Added p99 latency < 250ms (hard cap < 400ms)
    - Throughput > 100 req/s on 4 vCPU

We measure against the *idle proxy* — the absolute time taken by the
orchestrator pipeline excluding any upstream LLM call. The targets here are
*generous* (3-10x slacker than RFP) because:

  1. CI runners have wildly variable performance — GitHub Actions free tier is
     a noisy two-vCPU shared host.
  2. We want to catch *regressions* (10x slowdowns), not litigate the absolute.

If you want to compare against the RFP targets exactly, run the dedicated
bench-perf CLI on a quiet machine — it reports unfiltered numbers.
"""

from __future__ import annotations

import os

import pytest

from tests.perf.harness import (
    build_async_tool_call_workload,
    build_large_context_workload,
    build_simple_text_workload,
    build_tool_call_workload,
    measure_async,
    measure_sync,
    measure_throughput,
)

# Slack factor for CI vs. local. Override with AEGIS_PERF_SLACK=1.0 to enforce
# the original RFP targets exactly.
SLACK = float(os.environ.get("AEGIS_PERF_SLACK", "3.0"))


def _budget_ms(rfp_target_ms: float) -> float:
    return rfp_target_ms * SLACK


@pytest.mark.slow
def test_simple_text_workload_within_budget():
    _orch, run = build_simple_text_workload()
    res = measure_sync(run, iterations=300, warmup=30)
    print(f"\nSimple text workload: {res}")
    assert res.p50_ms < _budget_ms(50), f"p50={res.p50_ms:.2f}ms > budget"
    assert res.p99_ms < _budget_ms(150), f"p99={res.p99_ms:.2f}ms > budget"


@pytest.mark.slow
def test_one_tool_call_workload_within_budget():
    _orch, run = build_tool_call_workload(num_tool_calls=1)
    res = measure_sync(run, iterations=300, warmup=30)
    print(f"\nOne tool call workload (sync): {res}")
    assert res.p50_ms < _budget_ms(100), f"p50={res.p50_ms:.2f}ms > budget"
    assert res.p99_ms < _budget_ms(250), f"p99={res.p99_ms:.2f}ms > budget"


@pytest.mark.slow
def test_four_tool_calls_workload_within_budget():
    _orch, run = build_tool_call_workload(num_tool_calls=4)
    res = measure_sync(run, iterations=200, warmup=20)
    print(f"\nFour tool calls workload (sync): {res}")
    # Four tool calls means 12 gate evaluations (3 per call). p99 budget is
    # roughly proportional.
    assert res.p99_ms < _budget_ms(400)


@pytest.mark.slow
@pytest.mark.asyncio
async def test_four_tool_calls_async_within_budget():
    """The async path runs the 12 gates in parallel — should be similar to sync
    on Python (GIL-bound) but never *worse* than sync."""
    _orch, run = build_async_tool_call_workload(num_tool_calls=4)
    res = await measure_async(run, iterations=100, warmup=10)
    print(f"\nFour tool calls workload (async): {res}")
    assert res.p99_ms < _budget_ms(500)


@pytest.mark.slow
def test_large_context_workload_within_budget():
    _orch, run = build_large_context_workload(num_messages=50)
    res = measure_sync(run, iterations=100, warmup=10)
    print(f"\nLarge context (50 msgs) workload: {res}")
    # Tagging 50 messages adds linear cost — generous budget.
    assert res.p99_ms < _budget_ms(500)


@pytest.mark.slow
def test_throughput_above_minimum():
    _orch, run = build_simple_text_workload()
    rps = measure_throughput(run, duration_seconds=1.0)
    print(f"\nThroughput (simple workload): {rps:.0f} req/s")
    # Generous floor: 100 req/s. RFP target is 100 req/s on 4 vCPU.
    assert rps > 100, f"throughput {rps:.0f} req/s below floor"
