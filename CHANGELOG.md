# Changelog

Format adapted from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning per [SemVer](https://semver.org/).

## [0.9.0] — pre-1.0 development

Working toward a stable 1.0 release. Treat as beta — APIs and policy schema may change before 1.0.

### Five composed defense layers

- **CCPT** — HMAC-signed content provenance envelopes binding origin and trust level. Stripped before content reaches the model.
- **Trust Lattice** — Bell-LaPadula info-flow rules. L0 cannot authorize tool calls; L1 warns and requires capability tokens; L2 allows with capability tokens; L3 allows.
- **Intent Anchor** — embedding-based drift detection. Multi-anchor sessions accumulate one anchor per user turn and score against the closest match. LRU embedding cache.
- **Canary Tripwires** — per-session randomized decoy tokens with NFKC normalization (defeats zero-width / RTL / soft-hyphen splitting). Multi-template instructions resist canary-aware attacks.
- **Capability Tokens** — single-use, parameter-constrained, HMAC-signed tokens the model cannot mint. Atomic `verify_and_consume`.

### Decision orchestration

- Sync + async paths. The async path runs gates concurrently via `asyncio.gather`.
- Three policy modes: `strict`, `balanced` (default), `permissive`.
- Hash-chained, append-only decision log with sidecar tip pointer (truncation-detectable).

### Proxy

- FastAPI sidecar with wire-compatible adapters for Anthropic Messages, OpenAI Chat Completions, and Google `generateContent`.
- Streaming endpoints with per-chunk canary scan and final-pass full-pipeline evaluation.
- Tool-call blocks return HTTP 200 with the `tool_use` block rewritten to a structured "denied" message the agent can recover from. Hard HTTP 451 reserved for canary leaks and broken envelopes.
- Self-contained Prometheus `/metrics` endpoint (no `prometheus_client` dependency).
- `/aegis/dashboard` — single-page operator UI, no external resources.

### SDKs and CLI

- Python SDK with typed `AegisDecision` / `AegisVote` / `AegisWarning` / `AegisDecisionBlocked`. Per-layer `suggested_fix` strings.
- TypeScript SDK with the same surface.
- CLI: `up`, `status`, `logs {tail|show|query|export}`, `sessions {list|show}`, `policy {validate|show|explain}`, `verify`, `bench`, `bench-perf`, `genkey`, `mcp-wrap`.
- `aegis mcp-wrap` — wraps an MCP server's stdio so AEGIS inspects tool responses for canary leaks before they reach the agent.

### Distributed deployment

- Pluggable `NonceStore`: `MemoryNonceStore` (default) and `RedisNonceStore` (atomic `SET NX EX`).
- Helm chart with HPA, ServiceMonitor, non-root securityContext, Secret-sourced master key.

### Audit log schema

- Versioned `aegis.decision/v1` with `policy_version`, `blocked_by`, optional `user_id` / `tenant_id`, per-vote metadata, redacted parameter keys.

### Tests and benchmarks

- 277 tests across unit, security-attack, adversarial corpus, performance, MCP wrapper, streaming, metrics.
- Default policy benchmark on the bundled adversarial corpus (21 cases): 100% catch on all attack categories, 0% false positives on benign cases.
- Idle proxy latency: p50 0.07 ms, p99 0.13 ms. Throughput >12,000 req/s on simple workload.

### Known limitations going into 1.0

- Default hashing embedder is coarser than transformer options. Calibrated `sentence-transformers` defaults are pending.
- No automatic taint propagation through model paraphrase. `derive_child` is the explicit API; principled taint analysis is open work.
- Streaming is supported for Anthropic and OpenAI Chat Completions. Google streaming and the OpenAI Responses API are pending.
- Adversarial corpus is hand-curated. Public benchmark integration (LLM-PI-Bench, OWASP samples) is pending.

See [ROADMAP.md](ROADMAP.md) for the remaining work.
