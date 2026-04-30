# Changelog

All notable changes to AEGIS are documented here. Format adapted from [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning per [SemVer](https://semver.org/).

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
