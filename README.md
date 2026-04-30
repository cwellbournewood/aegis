# AEGIS

**Authenticated Execution Gateway for Injection Security**

Open-source, model-agnostic prompt-injection defense gateway for agentic LLM applications. Apache-2.0.

> **Built for** agents that take consequential tool actions (send email, modify databases, deploy code, post to APIs) and ingest untrusted content (RAG, web fetch, MCP servers).
>
> **Not built for** pure chatbots, agents that only see content you wrote yourself, or pre-product prototypes. See [WHO_SHOULD_USE.md](docs/WHO_SHOULD_USE.md) for the 30-second decision rubric.

## Quick links

- **New here?** → [QUICKSTART.md](docs/QUICKSTART.md) — three deployment cases (Anthropic API, Claude Code, other agentic frameworks) with copy-paste code.
- **Want intuition?** → [MENTAL_MODEL.md](docs/MENTAL_MODEL.md) — every layer explained with analogies (DKIM, ER nurse, drift detector, honeytoken, key-not-permission-slip).
- **Right fit for me?** → [WHO_SHOULD_USE.md](docs/WHO_SHOULD_USE.md) — user profiles, infrastructure fit, and explicit "do not use" cases.
- **What's coming?** → [ROADMAP.md](ROADMAP.md) — prioritized improvement plan.

---

## Why

Prompt injection is the most consequential unsolved problem in production LLM systems. LLMs ingest a single token stream — the boundary between *system instructions*, *user input*, *retrieved documents*, and *tool output* exists only as a convention enforced by the application layer. Every defense built on natural-language filtering can be bypassed by sufficiently creative natural language.

AEGIS abandons content-filtering as the primary mechanism. Instead, it imposes **structure the LLM cannot impose on itself**, treating prompt injection as a *provenance, authorization, and intent-drift* problem — the same lens used to defeat SQL injection, CSRF, and privilege escalation.

## Five composed defense layers

| Layer | What it does |
|---|---|
| **CCPT** — Cryptographic Content Provenance Tags | Every context chunk wrapped in an HMAC-signed envelope binding origin and trust level |
| **Trust Lattice** | Bell-LaPadula info-flow rules — L0/L1 content cannot authorize tool calls |
| **Intent Anchor** | User's original intent embedded once; proposed actions are checked for semantic drift |
| **Canary Tripwires** | Decoy honeytoken instructions seeded into the system prompt; leakage = high-confidence attack signal |
| **Capability Tokens** | Tool calls require cryptographic, single-use, parameter-constrained tokens that the model cannot mint |

A **Decision Engine** combines per-layer ALLOW/WARN/BLOCK votes per a configurable policy (`strict` / `balanced` / `permissive`). Every decision is recorded in a hash-chained, append-only audit log.

## Deploys as a sidecar

```
┌───────────────┐     ┌────────────────────────┐     ┌─────────────────┐
│  Application  │────▶│   AEGIS SIDECAR PROXY  │────▶│  LLM API        │
│  (any lang)   │◀────│   (Python / FastAPI)   │◀────│  Claude/GPT/    │
└───────┬───────┘     └──────────┬─────────────┘     │  Gemini         │
        │                        │                   └─────────────────┘
        ▼                        ▼
  ┌──────────┐            ┌────────────┐
  │ AEGIS    │            │  Decision  │
  │ SDK      │            │  Log (W/A) │
  │ (Py/TS)  │            └────────────┘
  └──────────┘
```

Apps either point their existing OpenAI/Anthropic/Google client at the AEGIS proxy URL, or use the AEGIS SDK for richer features (capability minting, intent declaration).

---

## Quickstart (60 seconds)

> Full quickstart with three deployment cases (Anthropic API agent, Claude Code, other frameworks) is in [docs/QUICKSTART.md](docs/QUICKSTART.md).

### Run the proxy with Docker

```bash
docker run -d --name aegis -p 8080:8080 \
  -e AEGIS_MASTER_KEY="$(openssl rand -hex 32)" \
  ghcr.io/cwellbournewood/aegis:1.2.0
```

Or with `docker-compose`:

```bash
cd deploy
AEGIS_MASTER_KEY=$(openssl rand -hex 32) docker-compose up -d
```

### Use it from Python

```python
from aegis.sdk import AegisClient
import anthropic

aegis = AegisClient(base_url="http://localhost:8080")

session = aegis.session.create(
    user_intent="summarize my latest invoice email",
    upstream="anthropic",
)

# Mint capability tokens for the tools the user has actually authorized.
session.capabilities.mint(
    "read_email",
    constraints={"folder": {"kind": "eq", "value": "inbox"}, "limit": {"kind": "max_len", "value": 5}},
)

# Point the upstream client at the AEGIS proxy URL.
claude = anthropic.Anthropic(base_url=session.proxy_url, api_key="sk-ant-...")

resp = claude.messages.create(
    model="claude-sonnet-4-5",
    max_tokens=512,
    messages=[{"role": "user", "content": "summarize my latest invoice email"}],
    extra_body={"aegis": {"session_id": session.session_id, "capability_tokens": session.capability_tokens()}},
)
```

When AEGIS blocks a request, the response uses HTTP `451` and includes a structured `aegis.decision` record with the votes from each layer.

---

## Install

### Server (proxy)

```bash
pip install aegis-guard
aegis genkey > .aegis-master-key                 # 32-byte hex master key
export AEGIS_MASTER_KEY="$(cat .aegis-master-key)"
aegis up --port 8080
```

For hosted-quality embeddings (recommended):

```bash
pip install 'aegis-guard[embed]'
```

### TypeScript SDK

```bash
npm install @aegis/guard
```

```ts
import { AegisClient, c } from "@aegis/guard";

const aegis = new AegisClient({ baseUrl: "http://localhost:8080" });
const session = await aegis.createSession({ userIntent: "..." });
await session.mintCapability("send_email", { constraints: { to: c.eq("alice@x.com") } });
```

---

## CLI

```bash
aegis up                        # start the proxy
aegis up --policy ./policy.yaml # with a custom policy
aegis logs --tail 50 --follow   # tail the decision log
aegis verify ./aegis-decisions.log   # verify hash chain + tip pointer
aegis policy validate ./policy.yaml
aegis policy show
aegis bench                     # run the bundled adversarial corpus
aegis bench-perf                # run latency / throughput benchmarks
aegis genkey                    # 32-byte hex master key
aegis mcp-wrap -- <mcp-cmd>     # wrap an MCP server with AEGIS inspection
```

### Wrapping an MCP server (for Claude Code / Cursor / Cline users)

```bash
# Instead of:
claude mcp add github "npx @modelcontextprotocol/server-github"

# Wrap it:
claude mcp add github "aegis mcp-wrap --policy strict -- npx @modelcontextprotocol/server-github"
```

Now every tool response from that MCP server is canary-scanned, tagged L0, and the wrapper drops a tamper-evident JSON-RPC error into the agent's stream if injection is detected. See [QUICKSTART.md §Case 2](docs/QUICKSTART.md#case-2--claude-code-the-harder-case).

---

## Configuration

A YAML policy controls every layer:

```yaml
mode: balanced  # strict | balanced | permissive

flows:
  - { from: L0, to: tool_call, decision: BLOCK }
  - { from: L1, to: tool_call, decision: WARN }
  - { from: L2, to: tool_call, decision: ALLOW, require: [capability_token] }
  - { from: L3, to: tool_call, decision: ALLOW }

anchor:
  threshold_balanced: 0.30
  threshold_strict: 0.45
  embedder: { kind: hashing, dim: 384 }

canary:
  enabled: true
  count: 3

capability:
  default_ttl_seconds: 600
  require_for_levels: [L2, L3]

log_path: ./aegis-decisions.log
```

See [`aegis/policies/default.yaml`](aegis/policies/default.yaml) for the full annotated default.

### Environment

| Variable | Purpose |
|---|---|
| `AEGIS_MASTER_KEY` | Hex-encoded 32-byte master key (HKDF root for per-session keys). **Required for production.** |
| `AEGIS_MASTER_KEY_FILE` | Path to a file containing the master key (alternative to env var). |
| `AEGIS_POLICY_PATH` | Path to a policy YAML. |
| `AEGIS_ANTHROPIC_URL` | Override Anthropic upstream URL. |
| `AEGIS_OPENAI_URL` | Override OpenAI upstream URL. |
| `AEGIS_GOOGLE_URL` | Override Google upstream URL. |
| `AEGIS_DRY_RUN=1` | Don't forward upstream — return synthetic responses (testing/demo). |

---

## Supported providers (v1.0)

| Provider | Models | Wire format |
|---|---|---|
| Anthropic | Claude 3.5+, Claude 4 family | Messages API |
| OpenAI | GPT-4o, GPT-4.1, GPT-5 family | Chat Completions, Responses API |
| Google | Gemini 1.5+, Gemini 2.x | `generateContent` |

Open-weights / local Ollama is scoped for v2.

---

## Performance

| Metric | RFP target | Measured (idle, hashing embedder) |
|---|---|---|
| Added p50 latency | < 100 ms | **0.07 ms** (simple) / **0.10 ms** (1 tool call) / **0.25 ms** (4 tool calls) |
| Added p99 latency | < 250 ms | **0.13 ms** / **0.28 ms** / **0.49 ms** |
| Throughput (single instance) | > 100 req/s | **>12,000 req/s** |
| Token overhead (canaries + system block) | < 10% | ~80 tokens / session |

Numbers from `aegis bench-perf` on a Windows local box. CI-asserted regression tests (`tests/perf/`) run on every commit at 3x slack.

Embedding inference dominates added latency in the worst case. The default local hashing embedder is CPU-friendly and zero-install; for higher-quality drift detection install `aegis-guard[embed]` and switch the policy embedder to `sentence-transformers`.

### Streaming

Modern agentic apps need streaming. AEGIS supports it natively:

```bash
POST /v1/anthropic/messages/stream
POST /v1/openai/chat/completions/stream
```

Each chunk is canary-scanned as it arrives. A leak triggers an immediate `aegis_blocked` SSE event before the offending chunk is forwarded to the client. End-of-stream runs the full five-layer pipeline as a final pass. Buffer is bounded — a 1-hour stream uses constant memory.

### Observability

`GET /metrics` returns Prometheus exposition with:

- `aegis_requests_total{upstream,decision}` — total requests labeled by upstream and ALLOW/WARN/BLOCK
- `aegis_layer_votes_total{layer,verdict}` — per-layer vote counts
- `aegis_canary_leaks_total` — high-confidence injection signal counter
- `aegis_capability_consumed_total` / `aegis_capability_rejected_total{reason}` — token lifecycle
- `aegis_decision_seconds` / `aegis_gate_seconds{gate}` — latency histograms
- `aegis_active_sessions` / `aegis_log_entries` — gauges

---

## Security properties

These are technical properties of the code, verifiable from source and tests — not legal guarantees:

- **All HMAC keys** are derived per-session from a master key via HKDF-SHA256.
- **The decision log** is append-only and hash-chained. `aegis verify <log>` confirms integrity end-to-end.
- **No model API keys** are persisted by AEGIS — they pass through from your app to the upstream provider.
- **CCPT envelopes are stripped** before content reaches the upstream model.
- **Canary tokens** are cryptographically random, per-session, and use multiple instruction templates (resistant to single-template-aware attacks).
- **Capability tokens** are single-use and time-bounded by default.
- **All cryptographic primitives** use vetted libraries (`cryptography` for Python, `node:crypto` for TS). No custom crypto.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full threat model and disclosure policy.

---

## What AEGIS is *not*

- **Not a model.** No alignment, no RLHF.
- **Not a WAF.** Doesn't inspect HTTP outside the LLM API path.
- **Not a substitute for least-privilege tool design** — it's a complement.
- **Not zero-FN.** The goal is to dramatically raise attacker cost while keeping false positives manageable. AEGIS does not promise it stops 100% of attacks.

---

## Documentation

- [**Quickstart**](docs/QUICKSTART.md) — three deployment cases with copy-paste code
- [**Who should use it**](docs/WHO_SHOULD_USE.md) — fit criteria, decision rubric, "do not use" cases
- [**Mental model**](docs/MENTAL_MODEL.md) — every layer explained with analogies
- [**Interfaces**](docs/INTERFACES.md) — five surfaces (end user, SDK, CLI, dashboard, audit log) and what each is tuned for
- [Architecture](docs/ARCHITECTURE.md) — the decision pipeline and how the layers compose
- [Threat Model](docs/THREAT_MODEL.md) — what AEGIS defends against, what it doesn't
- [Operator Guide](docs/OPERATOR.md) — deploying, tuning, and observing
- [Contributing](docs/CONTRIBUTING.md) — code style, evaluation criteria, RFC process
- [Roadmap](ROADMAP.md) — prioritized improvement plan

---

## License

[Apache-2.0](LICENSE).

Forks, audits, and pull requests welcome. AEGIS does not claim that any single layer is novel in isolation. Its contribution is the **composition** — five mechanisms operating on different attack surfaces, orchestrated by a single auditable decision engine, deployable as one open artifact.
