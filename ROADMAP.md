# AEGIS Roadmap

How AEGIS continues to optimize and improve. This document is a living plan — open an issue or RFC to push items up or down.

## Current state (v1.2.0)

- Five composed defense layers (CCPT, Trust Lattice, Intent Anchor, Canary Tripwires, Capability Tokens) with a vote-combining Decision Engine.
- Sync + async orchestrator with parallel gate execution.
- FastAPI proxy with Anthropic / OpenAI / Google adapters.
- Streaming endpoints with per-chunk canary scan + final-pass full pipeline.
- Prometheus `/metrics` (self-contained — no `prometheus_client` dep).
- Pluggable nonce store with Memory + Redis backends; atomic `verify_and_consume`.
- Hash-chained, append-only decision log with sidecar tip pointer (truncation-detectable).
- MCP server wrapper (`aegis mcp-wrap`) for Claude Code / Cursor / Cline integrations.
- 261 tests across unit, security-attack, adversarial corpus, performance, MCP wrapper.
- Helm chart with HPA + ServiceMonitor templates.

Measured idle p50: 0.07 ms; idle throughput: >12,000 req/s. ~750x under the RFP's 100 ms target.

---

## How we prioritize

Three lenses, applied in order:

1. **Real attack surface that AEGIS doesn't cover.** Anything that lets an adversary succeed where AEGIS users expected protection.
2. **Production blockers for the ideal user profiles** ([WHO_SHOULD_USE.md](docs/WHO_SHOULD_USE.md)). Streaming was the headliner here — closed in v1.2.0.
3. **Defense-in-depth depth.** Adding a sixth layer is rarely the right move; deepening an existing one usually is.

Items below are tagged with the lens they answer to.

---

## Near-term (next 1-2 minor releases)

### Adversarial robustness benchmarks against public corpora — *attack surface*

Currently the bundled corpus is hand-curated (21 cases, 100% catch / 0% FP). Real production confidence needs the public benchmarks too.

- [LLM-PI-Bench](https://github.com/protectai/llm-guard) — 1,000+ injection prompts across categories.
- [Lakera Gandalf](https://gandalf.lakera.ai) public dump — paraphrased + adaptive attacks.
- OWASP LLM01 sample sets.

**Concrete deliverable:** `aegis bench --corpus llmpibench` runs an external corpus. CI runs against a reproducible snapshot weekly. Publish baseline numbers + diff vs. prior version.

### Per-tool-class drift profiles — *false-positive reduction*

Today the intent-drift threshold is global. In practice, "search" tools have wider acceptable drift than "send_email" tools. A per-tool-class profile would let us tighten where it matters and loosen where it doesn't.

**Concrete deliverable:** policy syntax for `tool_drift_profiles: { send_email: { threshold: 0.40 }, web_search: { threshold: 0.10 } }`. Drift gate consults the profile per-call.

### Multimodal injection coverage — *attack surface*

2026 attack surface includes image-embedded prompts (steganographic instructions in icons, screenshots that contain hidden text), audio prompts in agent voice flows, and structured-output injection (JSON schemas with malicious string fields).

**Concrete deliverable:** image-prompt detector that runs OCR + canary scan on inbound image content. Vision-model adapter that tags image content as L0 by default.

### Hosted embedder integration with sentence-transformers benchmark — *quality*

The `embed` extra exists but the default thresholds are calibrated for the hashing embedder. Need calibrated defaults for `all-MiniLM-L6-v2` and a published comparison.

**Concrete deliverable:** policy `anchor.embedder.kind: sentence-transformers` works with retuned thresholds (verified by the bench corpus). Operator guide includes a side-by-side comparison.

### OpenTelemetry tracing — *observability*

Prometheus `/metrics` is shipping. Distributed tracing is the other half — operators want to see a single request trace from agent → AEGIS gates → upstream LLM → tool execution.

**Concrete deliverable:** opt-in `OTEL_EXPORTER_OTLP_ENDPOINT` integration. Each layer evaluation emits a span. Compatible with Datadog, Honeycomb, Jaeger.

---

## Medium-term (next 3-6 months)

### Taint propagation through model paraphrase — *attack surface*

When the model summarizes L0 content into its own response and that response is fed back as context, naive provenance tracking loses the L0 taint. v1 ships an explicit `derive_child` API; what we need is heuristic *automatic* taint propagation:

- N-gram overlap between model output and prior L0 content → high taint score.
- Embedding similarity between model output and prior L0 content → second-order signal.
- Operator-tunable threshold for promoting "tainted" output back to L0 in the next turn.

**Concrete deliverable:** `aegis.taint` module + orchestrator hook. New `taint_score` vote in the decision engine.

### Distributed session store backend — *deployment*

Sessions are currently per-replica (only nonces are distributed). For session affinity without sticky routing, allow Redis-backed sessions.

**Concrete deliverable:** `SessionStore` protocol + Redis implementation with the same atomicity properties as `RedisNonceStore`.

### Expanded provider coverage — *deployment*

v1.2 supports Anthropic / OpenAI / Google. Real production fleets also use Azure OpenAI, AWS Bedrock, local Ollama / vLLM.

**Concrete deliverable:** `AzureOpenAIAdapter`, `BedrockAdapter`, `OllamaAdapter` in `aegis/proxy/adapters.py`. CI smoke tests for each.

### Native streaming for OpenAI Responses API + Google `generateContent` — *deployment*

The streaming evaluator currently has parsers for Anthropic SSE and OpenAI Chat Completions SSE. Need native parsers for the newer Responses API and Google's streaming format.

**Concrete deliverable:** `parse_openai_responses_sse`, `parse_google_sse` in `aegis/proxy/streaming.py`. Endpoint coverage parity.

### Schema enforcement complement to capability tokens — *defense depth*

Capability tokens enforce *intent* binding. JSON Schema enforcement enforces *shape* binding. Together they prevent both unauthorized tools AND well-named-but-malformed parameters.

**Concrete deliverable:** new `ConstraintKind.SCHEMA` that takes a JSON Schema and validates tool parameters against it.

---

## Longer-term / research

### C++/Rust core for serverless and embedded — *deployment*

Python startup time (~1-2s) precludes serverless cold-paths. A native-language reimplementation of the hot path (CCPT verify, lattice, capability verify) with a Python orchestrator on top would address this.

This is a significant rewrite and will only happen if there's clear demand.

### Adversarial-robustness improvements to the embedding layer — *attack surface*

Adversarial perturbation of embeddings (adding character noise to make a malicious request embed-similar to a benign one) defeats the intent anchor. Active research area; potential approaches:

- Multi-embedder voting (sentence-transformers + word2vec + character n-gram).
- Contrastive fine-tuning of an injection-aware embedder on adversarial examples.
- Token-overlap fallback when cosine similarity is suspiciously high.

### Cross-agent provenance for multi-agent systems — *attack surface*

When agent A calls agent B, B's outputs become A's tool results. AEGIS needs to track provenance across agent boundaries — not just within one session.

**Concept:** federated CCPT envelopes. Cross-agent envelopes signed with a federation key shared by collaborating proxies.

### Formal verification of the lattice gate — *defense depth*

The Bell-LaPadula non-interference proof is well-understood. Restating it formally for AEGIS's specific lattice rules (in TLA+ or Coq) would make AEGIS one of the few LLM security tools with a machine-checkable correctness argument.

---

## Continuous improvement (every release)

These run on every minor release, not as separate roadmap items:

- **Bench corpus expansion.** Add 2–5 new attack cases per release based on real CVEs and reported injection techniques.
- **Performance regression guard.** CI asserts p50/p99 budgets at 3x slack. Any merge that pushes us over fails CI.
- **Dependency hygiene.** Pinned in `pyproject.toml`; upgraded with intention, not blanket dependabot accepts.
- **Threat model refresh.** Document any new known limitations as they're discovered.
- **Adversarial test sweep.** Run the corpus across all three providers' wire formats every release.

---

## Want to contribute?

See [CONTRIBUTING.md](docs/CONTRIBUTING.md). The evaluation criteria from the original RFP still apply:

| Criterion | Weight |
|---|---|
| Demonstrably reduces attack success on the adversarial corpus | 30% |
| Stays within performance budget | 20% |
| Code quality, test coverage, documentation | 20% |
| Composes cleanly with existing layers | 15% |
| Operator ergonomics | 15% |

Bonus: contributions that **expand the adversarial corpus** with novel attacks are highly valued. AEGIS only gets harder to defeat as more adversarial cases land in the corpus.
