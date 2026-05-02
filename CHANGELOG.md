# Changelog

Format adapted from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning per [SemVer](https://semver.org/).

## [1.0.0] — 2026-05-02

The personal-project release. AEGIS treats prompt injection as an information-flow problem instead of a content-classification one and ships five layers that cooperate to enforce it.

### Five composed defense layers

- **CCPT** (Cryptographic Content Provenance Tags). HMAC-signed envelopes bind every context chunk to its origin and trust level. Stripped before reaching the model.
- **Trust Lattice**. Bell-LaPadula info-flow rules. L0/L1 content cannot authorize tool calls; L2 requires a capability token; L3 system content can.
- **Intent Anchor**. Embedding-based drift detection. Multi-anchor sessions accumulate one anchor per user turn and score against the closest match. LRU embedding cache.
- **Canary Tripwires**. Per-session randomized decoy tokens with NFKC + invisible-character normalization (defeats zero-width / RTL / soft-hyphen splitting). Multiple templates per session.
- **Capability Tokens**. Single-use, parameter-constrained, HMAC-signed tokens the model cannot mint. Atomic `verify_and_consume`.

### Decision orchestration

- Sync + async paths; the async path runs gates concurrently via `asyncio.gather`.
- Three policy modes: `strict`, `balanced` (default), `permissive`.
- Hash-chained, append-only decision log with sidecar tip pointer; `aegis verify` checks integrity end-to-end.

### Proxy

- FastAPI sidecar with wire-compatible adapters for Anthropic Messages, OpenAI Chat Completions, and Google `generateContent`.
- Streaming endpoints with per-chunk canary scan and final-pass full-pipeline evaluation.
- Tool-call blocks return HTTP 200 with the `tool_use` block rewritten to a structured `aegis_denied` message; hard HTTP 451 reserved for canary leaks and broken envelopes.
- Self-contained Prometheus `/metrics` endpoint (no `prometheus_client` dependency).
- `/aegis/dashboard` — single-page Bronze & Obsidian operator console, no external resources.

### SDKs and CLI

- Python SDK with typed `AegisDecision` / `AegisVote` / `AegisWarning` / `AegisDecisionBlocked` and per-layer `suggested_fix` strings.
- TypeScript SDK with matching surface.
- CLI: `up`, `down`, `status`, `logs {tail|show|query|export}`, `sessions {list|show}`, `policy {validate|show|explain}`, `verify`, `bench`, `bench-perf`, `genkey`, `mcp-wrap`.

### MCP integration

- `aegis mcp-wrap` is now end-to-end useful. With `--proxy-url`, the wrapper polls `/aegis/canaries/active` and scans both directions of MCP traffic against the same tokens the proxy planted in the LLM's prompts. `tools/call` request params are scanned as well as response content; a leak short-circuits the request with a JSON-RPC error.
- `--policy permissive` logs leaks but lets traffic through unmodified; `strict` and `balanced` BLOCK.
- Cross-platform binary resolution via `shutil.which` so `npx`/`npm` shims work on Windows.

### Distributed deployment

- Pluggable `NonceStore`: `MemoryNonceStore` (default) and `RedisNonceStore` (atomic `SET NX EX` across replicas).
- Helm chart with HPA, ServiceMonitor, non-root securityContext, Secret-sourced master key. Linted + kubeconformed in CI.

### Supply chain

- Multi-arch (amd64 + arm64) image published to `ghcr.io/cwellbournewood/aegis:1.0.0` and `:latest`.
- Cosign keyless signature via Sigstore Fulcio (`cosign verify ...`).
- SLSA v1 build-provenance attestation against the image (`gh attestation verify`).
- SPDX SBOMs for source tree and image, attached to the GitHub Release and as cosign attestations on the image.

### Audit log schema

- Versioned `aegis.decision/v1` with `policy_version`, `blocked_by`, optional `user_id` / `tenant_id`, per-vote metadata, redacted parameter keys.

### Tests and benchmarks

- 282 tests across unit, security-attack, adversarial corpus, performance, MCP wrapper, streaming, metrics.
- Default policy benchmark on the bundled adversarial corpus (21 cases): 100% catch on direct / memory / multi-agent, 87.5% on indirect (one explicit-allow case), 0% false positives on benign.
- Idle proxy latency: p50 0.07 ms, p99 0.13 ms. Throughput >12,000 req/s on a simple workload.

### Known limits

- Default embedder is hashing; calibrated `sentence-transformers` defaults are not the default.
- No automatic taint propagation through model paraphrase; `derive_child` is the explicit API.
- Streaming covers Anthropic Messages and OpenAI Chat Completions. Google streaming and the OpenAI Responses API are not supported.
- Adversarial corpus is hand-curated.
