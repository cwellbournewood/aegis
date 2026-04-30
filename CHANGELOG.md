# Changelog

All notable changes to AEGIS are documented here. Format adapted from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning per [SemVer](https://semver.org/).

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

[1.0.0]: https://github.com/aegis-guard/aegis/releases/tag/v1.0.0
