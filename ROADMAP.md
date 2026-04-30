# Roadmap

Open an issue or RFC to push items up or down.

## Current state (0.9.0, pre-1.0)

- Five composed defense layers: CCPT, Trust Lattice, Intent Anchor, Canary Tripwires, Capability Tokens.
- Decision Engine with strict / balanced / permissive modes.
- Sync + async orchestrator with parallel gate execution.
- FastAPI proxy with adapters for Anthropic, OpenAI, Google. Streaming endpoints with per-chunk canary scan.
- Prometheus `/metrics` and operator dashboard at `/aegis/dashboard`.
- Pluggable nonce store with Memory + Redis backends.
- Hash-chained, append-only decision log with sidecar tip pointer.
- MCP server wrapper (`aegis mcp-wrap`) for Claude Code / Cursor / Cline.
- 277 tests; bundled adversarial corpus runs in CI.

Idle p50: 0.07 ms. Idle throughput: >12,000 req/s.

---

## Required for 1.0

These need to land before AEGIS calls itself stable:

### Public adversarial corpora

The bundled corpus is hand-curated (21 cases). 1.0 requires public-benchmark integration:

- LLM-PI-Bench
- OWASP LLM01 sample sets
- Lakera Gandalf-derived public corpora

Deliverable: `aegis bench --corpus llmpibench` runs an external corpus. CI runs against a reproducible snapshot. Published baseline numbers per release.

### Calibrated `sentence-transformers` defaults

Today the default thresholds are calibrated for the hashing embedder. For higher-quality drift detection users install the `embed` extra, but thresholds aren't retuned.

Deliverable: policy `anchor.embedder.kind: sentence-transformers` works with retuned defaults verified by the corpus. Operator guide includes a side-by-side comparison.

### Streaming parity

Currently supports Anthropic SSE and OpenAI Chat Completions SSE. Need parsers for the OpenAI Responses API and Google's streaming format.

Deliverable: `parse_openai_responses_sse` and `parse_google_sse` in `aegis/proxy/streaming.py`. Endpoint coverage parity.

### Per-tool-class drift profiles

Today the intent-drift threshold is global. In practice "search" tools have wider acceptable drift than "send_email" tools.

Deliverable: policy syntax `tool_drift_profiles: { send_email: { threshold: 0.40 }, web_search: { threshold: 0.10 } }`.

### Stability of the public schema

The audit log is `aegis.decision/v1`. Capability token format is `aegis_cap.v1`. CCPT envelope is `ccpt1`. Lock these for 1.0; future schema changes bump the version.

---

## Post-1.0

### Multimodal injection coverage

Image-embedded prompts (steganographic instructions in icons, screenshots that contain hidden text), audio prompts in voice flows, structured-output injection (JSON schemas with malicious string fields).

Deliverable: image-prompt detector that runs OCR + canary scan on inbound image content. Vision-model adapter that tags image content as L0 by default.

### Taint propagation through model paraphrase

When the model summarizes L0 content into its own response and that response is fed back as context, naive provenance tracking loses the L0 taint. v0.x supports explicit `derive_child`. Automatic taint propagation needs heuristic signals (n-gram overlap, embedding similarity to prior L0 content).

Deliverable: `aegis.taint` module + orchestrator hook. New `taint_score` vote in the decision engine.

### Distributed session store

Sessions are currently per-replica (only nonces are distributed). For session affinity without sticky routing, allow Redis-backed sessions.

Deliverable: `SessionStore` protocol + Redis implementation.

### Expanded provider coverage

Azure OpenAI, AWS Bedrock, local Ollama / vLLM.

### OpenTelemetry tracing

Each layer evaluation emits a span. Compatible with Datadog, Honeycomb, Jaeger.

### Schema enforcement complement to capability tokens

Capability tokens enforce intent binding. JSON Schema enforcement enforces shape binding. Together they prevent both unauthorized tools and well-named-but-malformed parameters.

Deliverable: new `ConstraintKind.SCHEMA` that takes a JSON Schema and validates tool parameters.

### Native-language port for serverless / embedded

Python startup time precludes serverless cold-paths. A native-language reimplementation of the hot path (CCPT verify, lattice, capability verify) with a Python orchestrator on top would address this. Significant rewrite; gated on demand.

### Adversarial-robustness improvements to the embedding layer

Adversarial perturbation of embeddings defeats the intent anchor. Active research area. Possible approaches: multi-embedder voting, contrastive fine-tuning of an injection-aware embedder on adversarial examples, token-overlap fallback when cosine similarity is suspiciously high.

### Cross-agent provenance

When agent A calls agent B, B's outputs become A's tool results. Federated CCPT envelopes signed with a federation key shared by collaborating proxies.

### Formal verification of the lattice gate

Bell-LaPadula non-interference is well-understood. Restating it formally for AEGIS's specific lattice rules (in TLA+ or Coq) would make AEGIS one of the few LLM security tools with a machine-checkable correctness argument.

---

## Continuous improvement

Run on every release:

- **Bench corpus expansion.** 2–5 new attack cases per release based on real CVEs and reported injection techniques.
- **Performance regression guard.** CI asserts p50/p99 budgets at 3x slack.
- **Dependency hygiene.** Pinned in `pyproject.toml`; upgraded with intention.
- **Threat model refresh.** Document new known limitations as they're discovered.
