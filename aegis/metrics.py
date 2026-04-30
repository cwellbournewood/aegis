"""Prometheus-format metrics for AEGIS.

Self-contained Prometheus exposition — no external prometheus_client dependency.
Counters, histograms, and gauges live in a process-local registry and are
serialized on demand by the `/metrics` endpoint.

Why hand-rolled: keeping the dependency surface minimal so AEGIS continues to
install in <30 seconds and runs in any environment, even those that block the
prometheus_client wheel. The exposition format is stable and small enough to
re-implement in a couple hundred lines.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# Default histogram buckets in seconds — covers typical AEGIS overhead range.
_DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.25, 0.5, 1.0, 2.5, 5.0, float("inf"))


def _format_label_pairs(labels: dict[str, str]) -> str:
    """Render labels in Prometheus exposition syntax: `key="value",...`."""
    if not labels:
        return ""
    items = []
    for k in sorted(labels):
        v = labels[k].replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
        items.append(f'{k}="{v}"')
    return "{" + ",".join(items) + "}"


@dataclass
class _Counter:
    name: str
    help: str
    values: dict[tuple[tuple[str, str], ...], float] = field(default_factory=lambda: defaultdict(float))
    lock: threading.Lock = field(default_factory=threading.Lock)

    def inc(self, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
        key = tuple(sorted((labels or {}).items()))
        with self.lock:
            self.values[key] += amount

    def render(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.help}"
        yield f"# TYPE {self.name} counter"
        with self.lock:
            for key, val in self.values.items():
                lbls = dict(key)
                yield f"{self.name}{_format_label_pairs(lbls)} {val}"


@dataclass
class _Gauge:
    name: str
    help: str
    values: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def set(self, value: float, labels: dict[str, str] | None = None) -> None:
        key = tuple(sorted((labels or {}).items()))
        with self.lock:
            self.values[key] = float(value)

    def inc(self, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
        key = tuple(sorted((labels or {}).items()))
        with self.lock:
            self.values[key] = self.values.get(key, 0.0) + amount

    def dec(self, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
        self.inc(-amount, labels)

    def render(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.help}"
        yield f"# TYPE {self.name} gauge"
        with self.lock:
            for key, val in self.values.items():
                lbls = dict(key)
                yield f"{self.name}{_format_label_pairs(lbls)} {val}"


@dataclass
class _HistogramBucket:
    counts: list[int] = field(default_factory=list)
    sum: float = 0.0


@dataclass
class _Histogram:
    name: str
    help: str
    buckets: tuple[float, ...] = _DEFAULT_BUCKETS
    series: dict[tuple[tuple[str, str], ...], _HistogramBucket] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def observe(self, value: float, labels: dict[str, str] | None = None) -> None:
        key = tuple(sorted((labels or {}).items()))
        with self.lock:
            bucket = self.series.get(key)
            if bucket is None:
                bucket = _HistogramBucket(counts=[0] * len(self.buckets))
                self.series[key] = bucket
            for i, edge in enumerate(self.buckets):
                if value <= edge:
                    bucket.counts[i] += 1
            bucket.sum += value

    def render(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.help}"
        yield f"# TYPE {self.name} histogram"
        with self.lock:
            for key, bucket in self.series.items():
                lbls = dict(key)
                cumulative = 0
                for edge, count in zip(self.buckets, bucket.counts, strict=False):
                    cumulative = count
                    le = "+Inf" if edge == float("inf") else f"{edge}"
                    bucket_lbls = {**lbls, "le": le}
                    yield f"{self.name}_bucket{_format_label_pairs(bucket_lbls)} {cumulative}"
                total = bucket.counts[-1] if bucket.counts else 0
                yield f"{self.name}_count{_format_label_pairs(lbls)} {total}"
                yield f"{self.name}_sum{_format_label_pairs(lbls)} {bucket.sum}"


class _Registry:
    """Process-local metrics registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, _Counter] = {}
        self._gauges: dict[str, _Gauge] = {}
        self._histograms: dict[str, _Histogram] = {}

        # Standard AEGIS metric set.
        self.register_counter(
            "aegis_requests_total",
            "Total LLM requests processed by AEGIS, labeled by upstream and decision.",
        )
        self.register_counter(
            "aegis_layer_votes_total",
            "Per-layer ALLOW/WARN/BLOCK vote counts.",
        )
        self.register_counter(
            "aegis_canary_leaks_total",
            "Total canary leak detections (high-confidence injection signal).",
        )
        self.register_counter(
            "aegis_capability_consumed_total",
            "Total capability tokens consumed (single-use successful calls).",
        )
        self.register_counter(
            "aegis_capability_rejected_total",
            "Total capability token verifications that failed, labeled by reason.",
        )
        self.register_gauge(
            "aegis_active_sessions",
            "Currently-tracked sessions in the in-memory store.",
        )
        self.register_gauge(
            "aegis_log_entries",
            "Total entries in the decision log since process start.",
        )
        self.register_histogram(
            "aegis_decision_seconds",
            "End-to-end orchestrator decision latency in seconds.",
        )
        self.register_histogram(
            "aegis_gate_seconds",
            "Per-gate evaluation latency in seconds, labeled by gate.",
        )

    def register_counter(self, name: str, help_: str) -> _Counter:
        with self._lock:
            c = self._counters.get(name)
            if c is None:
                c = _Counter(name=name, help=help_)
                self._counters[name] = c
            return c

    def register_gauge(self, name: str, help_: str) -> _Gauge:
        with self._lock:
            g = self._gauges.get(name)
            if g is None:
                g = _Gauge(name=name, help=help_)
                self._gauges[name] = g
            return g

    def register_histogram(self, name: str, help_: str) -> _Histogram:
        with self._lock:
            h = self._histograms.get(name)
            if h is None:
                h = _Histogram(name=name, help=help_)
                self._histograms[name] = h
            return h

    def counter(self, name: str) -> _Counter:
        return self._counters[name]

    def gauge(self, name: str) -> _Gauge:
        return self._gauges[name]

    def histogram(self, name: str) -> _Histogram:
        return self._histograms[name]

    def render(self) -> str:
        lines: list[str] = []
        with self._lock:
            for c in self._counters.values():
                lines.extend(c.render())
            for g in self._gauges.values():
                lines.extend(g.render())
            for h in self._histograms.values():
                lines.extend(h.render())
        return "\n".join(lines) + "\n"

    def reset_for_tests(self) -> None:
        with self._lock:
            for c in self._counters.values():
                c.values.clear()
            for g in self._gauges.values():
                g.values.clear()
            for h in self._histograms.values():
                h.series.clear()


metrics = _Registry()


class Stopwatch:
    """Context manager / decorator for timing a block and observing into a histogram."""

    def __init__(self, hist_name: str, labels: dict[str, str] | None = None) -> None:
        self._hist = metrics.histogram(hist_name)
        self._labels = labels
        self._start: float = 0.0

    def __enter__(self) -> Stopwatch:
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc: Any) -> None:  # type: ignore[override]
        self._hist.observe(time.perf_counter() - self._start, self._labels)
