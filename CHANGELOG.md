# Changelog

All notable changes to AEGIS are documented here. Format adapted from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning per [SemVer](https://semver.org/).

## [1.2.0] — 2026-04-30

Production hardening: streaming, async, observability, distributed deployments.

### Added

- **Streaming response support.** New endpoints `/v1/anthropic/messages/stream` and `/v1/openai/chat/completions/stream` evaluate per-chunk: each text chunk and tool-call delta is canary-scanned as it arrives and a leak triggers immediate `aegis_blocked` SSE before the offending bytes reach the client. End-of-stream runs the full pipeline. Buffer is bounded — long streams use constant memory.
- **Async orchestrator with parallel gate execution.** `Orchestrator.post_flight_async` runs canary + per-tool-call lattice / drift / capability gates concurrently via `asyncio.gather`. The FastAPI proxy uses this path by default.
- **Self-contained Prometheus /metrics endpoint.** No `prometheus_client` dependency. Exposes counters (`aegis_requests_total`, `aegis_layer_votes_total`, `aegis_canary_leaks_total`, `aegis_capability_consumed_total`, `aegis_capability_rejected_total{reason}`), gauges (`aegis_active_sessions`, `aegis_log_entries`), and histograms (`aegis_decision_seconds`, `aegis_gate_seconds{gate}`).
- **Pluggable NonceStore.** `MemoryNonceStore` (default, single-replica) and `RedisNonceStore` (atomic `SET NX EX`, install via `pip install 'aegis-guard[redis]'`). New atomic `CapabilityMinter.verify_and_consume` collapses verify + mark-used into one operation, eliminating the check-then-set race for hot tokens.
- **Performance benchmark suite** at `tests/perf/` with CI-asserted p50/p99 targets and a new `aegis bench-perf` CLI subcommand for ad-hoc benchmarking.
- **Helm ServiceMonitor template** for Prometheus Operator deployments.

### Measured performance (Windows local box, hashing embedder)

| Workload | p50 | p90 | p99 | Throughput |
|---|---|---|---|---|
| Simple text | 0.07 ms | 0.08 ms | 0.13 ms | >12,000 req/s |
| 1 tool call (sync) | 0.10 ms | 0.13 ms | 0.28 ms | — |
| 4 tool calls (sync) | 0.25 ms | 0.29 ms | 0.49 ms | — |
| 4 tool calls (async) | 1.09 ms | 1.53 ms | 13.86 ms | — |
| 50-message context | 0.69 ms | 0.79 ms | 0.96 ms | — |

vs. RFP target of < 100 ms p50 / < 250 ms p99 / > 100 req/s. CI runs the same suite at 3x slack to absorb runner noise.

### Changed

- `CapabilityMinter` is now nonce-store aware. The legacy `consume()` method still works for backwards compatibility but new code should use `verify_and_consume()` for atomicity under concurrency.
- Default policy YAML surfaces the new `capability.nonce_store` block.
- Architecture and Operator docs updated with sections on streaming, async, distributed deployments, and Prometheus integration.

### Tests

252 tests passing (was 216):

- **+15 streaming**: per-chunk canary scan, final-pass full pipeline, bounded buffer, zero-width split coverage, SSE endpoint smoke
- **+13 nonce store**: memory atomicity (50-thread stress), expired-nonce remarking, sweep, Redis config plumbing, atomic verify-and-consume concurrent uniqueness
- **+8 metrics**: Prometheus exposition format, per-layer / per-gate population, canary leak counter, capability consumed/rejected separation, histogram populating
- **+6 perf**: latency budgets across simple/tool/large workloads + throughput floor

## [1.1.0] — 2026-04-30

Security hardening, false-positive reduction, and CI maintenance.

### Added

- **Multi-anchor sessions.** Each user turn contributes a new anchor vector; drift is scored against the closest anchor, dramatically reducing FPs on legitimate multi-step tasks (`aegis/anchor.py`).
- **LRU embedding cache.** Repeated text inputs hit the embedder once per process. Default capacity 1024 entries (`aegis/anchor.py`).
- **Hash-log tip-pointer.** A sidecar `<log>.tip` file records the latest seq+hash atomically on each append. `aegis verify` cross-checks against it to detect truncation, which a chain alone cannot (`aegis/log.py`).
- **Canary scan normalization.** Inputs are NFKC-normalized and stripped of zero-width/RTL/soft-hyphen characters before substring matching. Defeats canary-aware splitting attacks. Dict keys are now scanned too.
- **65 new security tests** across crypto primitives, CCPT tampering, capability attacks, lattice bypass attempts, canary evasion, proxy/API attacks, and log integrity (`tests/security/`).
- **7 new adversarial corpus cases** covering zero-width canary attacks, RTL-override injection, base64-encoded payloads, homoglyph parameter abuse, stale-system-claim memory poisoning, and additional benign multi-step controls.

### Changed

- **Default intent-drift thresholds** retuned for the hashing embedder: balanced 0.30 → 0.22, strict 0.45 → 0.40. With multi-anchor accumulation, this catches all attacks in the corpus while keeping benign FPs at 0.
- **CI actions** bumped to Node.js 24 compatible versions: `actions/checkout@v6`, `actions/setup-python@v6`, `actions/setup-node@v6`, `actions/upload-artifact@v7`. TS SDK CI now uses `npm ci` against the committed lockfile.
- **SECURITY.md and threat model** clarified: this is a community-maintained project with no SLA on triage. Removed time-bound support commitments.
- **README "Security guarantees"** renamed to "Security properties" — these are technical properties verifiable from source, not legal guarantees.

### Fixed

- Canary scan no longer misses tokens split with zero-width spaces, RTL overrides, or soft hyphens.
- Hash-log truncation at the tail is now detected via the tip-pointer sidecar.
- Several stylistic issues flagged by ruff (SIM, RUF) cleaned up.

### Benchmark (default policy, balanced mode, hashing embedder)

| Category | Attack catch rate | Benign false-positive rate |
|---|---|---|
| Direct injection (4 cases) | 100% | — |
| Indirect injection (8 cases) | 100% of attacks; 1 case explicitly marked ALLOW (no constraint set) | — |
| Memory poisoning (3 cases) | 100% | — |
| Multi-agent contamination (2 cases) | 100% | — |
| Benign (4 cases) | — | 0% |

## [1.0.0] — 2026-04-30

Initial public release.

### Added

- **CCPT layer** (`aegis/ccpt.py`) — HMAC-signed content provenance envelopes binding origin and trust level. Tamper-evident across the proxy pipeline. Stripped before content reaches the upstream model.
- **Trust Lattice layer** (`aegis/lattice.py`) — Bell-LaPadula-style declarative flow rules. Default policy: L0 cannot authorize tool calls; L1 warns; L2 requires capability token; L3 allows.
- **Intent Anchor layer** (`aegis/anchor.py`) — embedding-based drift detection. Default `HashingEmbedder` (zero-install, deterministic). Optional `SentenceTransformerEmbedder` via `aegis-guard[embed]`.
- **Canary Tripwire layer** (`aegis/canary.py`) — per-session randomized decoy tokens with three distinct trigger templates. Recursive structured-payload scanning catches leaks in tool-call parameters.
- **Capability Token layer** (`aegis/capability.py`) — single-use, parameter-constrained, HMAC-signed `aegis_cap.v1.<base64>.<sig>` tokens. Constraint primitives: `eq`, `in`, `regex`, `prefix`, `max_len`, `any`.
- **Decision Engine** (`aegis/decision.py`) — strict / balanced / permissive vote combiners. Weighted score across all layer votes.
- **Hash-chained Decision Log** (`aegis/log.py`) — append-only JSONL with SHA256 chain. `aegis verify` walks the chain end-to-end.
- **Provider adapters** (`aegis/proxy/adapters.py`) — Anthropic Messages, OpenAI Chat Completions, Google Gemini `generateContent`.
- **FastAPI proxy** (`aegis/proxy/app.py`) — upstream-compatible routes plus `/aegis/{health,session,capability,decisions}` endpoints.
- **CLI** (`aegis/cli.py`) — `up`, `logs`, `verify`, `policy {validate,show}`, `bench`, `genkey`.
- **Python SDK** (`aegis/sdk/`) — synchronous client with session and capability namespaces.
- **TypeScript SDK** (`sdk-ts/`) — node 18+ idiomatic client.
- **Adversarial corpus** (`tests/adversarial/corpus.json`) — 14 cases across direct, indirect, memory, multi-agent, and benign categories.
- **Docker image, Docker Compose, Helm chart** with non-root `securityContext`, HPA, Secret-sourced master key.
- **Threat model, architecture, operator, and contributing docs** under `docs/`.

### Performance

- Default-config p50 added latency under measured CI: well under the 100ms target.
- Token overhead per session (canaries + integrity directives): ~80 tokens.
- Idle proxy memory footprint: <300MB.

### Security

- All HMAC keys derived per-session from a master key via HKDF-SHA256.
- All cryptographic primitives use vetted libraries (`cryptography`, `hmac`, `secrets`). No custom crypto.
- Hash-chained audit log; tamper-evident via `aegis verify`.

### Out of scope (deferred to v2)

- Open-weights / local Ollama upstream support.
- Streaming response per-chunk evaluation.
- Cross-agent / cross-session lattice extensions.
- Principled taint propagation for model-paraphrased content.

[1.0.0]: https://github.com/cwellbournewood/aegis/releases/tag/v1.0.0
