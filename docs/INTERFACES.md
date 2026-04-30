# AEGIS Interface Surfaces

Five audiences, five surfaces, each tuned for its audience. This document maps the design philosophy to the specific code, endpoints, and contracts in the repo.

| Surface | Audience | Design principle |
|---|---|---|
| **1. End user** | Humans interacting with the agent | Invisible by default. Graceful when not. No technical detail leaked. |
| **2. Developer SDK** | Application authors | Maximally explicit. Typed objects. Every block has a `suggested_fix`. |
| **3. CLI** | Operators | Verb-oriented (`aegis logs show <id>`). Live + forensic. |
| **4. Dashboard** | Solo devs / small ops teams | Opinionated, single-binary, no CDN. |
| **5. Audit log** | SIEMs / forensics / compliance | Structured, schema-versioned, hash-chained. The source of truth. |

---

## Surface 1 — End user (graceful, invisible)

**Design principle:** AEGIS hides until the moment a hard block is genuinely required. Most blocks should be invisible to end users because the agent's response can route around them.

### What the user sees

For tool-call blocks (the common case): the agent's response is rewritten so the tool_use block becomes a structured "denied" message. The agent receives the denial and can recover — for example:

> *"I noticed an instruction in that email asking me to set up forwarding. That looked unusual, so I didn't act on it. Here's the summary you asked for instead."*

For hard blocks (canary leaks, broken envelopes): a calm non-technical message — HTTP 451 with `error.message` set to the reason but stripped of layer names, scores, or token IDs.

### What the user must NEVER see

- Stack traces
- Layer names or vote details
- Confidence scores
- Capability token IDs
- "AegisDecisionBlocked" or anything that looks like a security product

These are leaks that help adaptive attackers (the A3 adversaries in the threat model) map AEGIS's behavior.

### Where this lives in the code

- [`aegis/proxy/app.py`](../aegis/proxy/app.py) — `_is_tool_call_only_block` chooses soft vs. hard, `_rewrite_response_with_blocked_tool_results` does the rewrite per provider format.
- Tests: [`tests/test_soft_block.py`](../tests/test_soft_block.py).

### What you (the deployer) get to decide

- **`policy.mode`** — `permissive` mode never hard-blocks. `balanced` (default) soft-blocks tool calls and hard-blocks canary leaks. `strict` is the same but escalates double-WARNs to BLOCK.
- **Custom error UI in your agent.** AEGIS hands you a structured "denied" with a brief reason; how you wrap that for the end user is your call.

---

## Surface 2 — Developer SDK (typed, debuggable)

**Design principle:** maximally explicit, every decision inspectable, every block has actionable next steps.

### What developers see

```python
from aegis.sdk import AegisDecision, AegisDecisionBlocked, attach_decision

result = client.messages.create(...)

decision = AegisDecision.from_response(result)
print(decision.pretty())
# AegisDecision(ALLOW, request_id=req_..., mode=balanced)
#   reason: all gates ALLOW
#   score:  0.000
#   votes:
#     ✓ ccpt_verify    ALLOW  all envelopes signed
#     ✓ canary         ALLOW  no canary leakage
#     ✓ lattice        ALLOW  L2 ok with capability token
#     ✓ capability     ALLOW  capability token accepted and consumed
#     ✓ intent_drift   ALLOW  intent aligned: similarity=0.74

# Inspect specific layers:
decision.votes["lattice"].verdict  # 'ALLOW'
decision.warnings                  # tuple of AegisWarning for any WARN votes
decision.blocked_by                # tuple of layer names that voted BLOCK
```

For a blocked request:

```python
try:
    result = client.messages.create(...)
    decision = AegisDecision.from_response(result)
    # If the proxy did a soft-block, decision.decision == "BLOCK" but the
    # response is still 200 and the agent can recover. Check decision.blocked_by
    # to know which layers fired.
except aegis.sdk.AegisDecisionBlocked as e:
    print(e.pretty())
    # AegisDecisionBlocked: L0 cannot authorize tool calls (effective=L0, ...)
    #   request_id: req_...
    #   session_id: ses_...
    #   blocked_by: ['lattice', 'capability', 'intent_drift']
    #   reasons:
    #     lattice:      L0 cannot authorize tool calls (effective=L0, tool=set_email_forwarding)
    #     capability:   no capability token presented for tool=set_email_forwarding
    #     intent_drift: intent drift: similarity=0.18 < threshold=0.30
    #
    # Suggested fix:
    #   [lattice]
    #   If this action is legitimate, the causal-origin level is too low. ...
    #   [capability]
    #   Mint a capability token for this exact (tool, parameters) before the call:
    #       session.capabilities.mint("<tool>", constraints={...})
    #   ...
```

### Where this lives in the code

- [`aegis/sdk/decision.py`](../aegis/sdk/decision.py) — `AegisDecision`, `AegisVote`, `AegisWarning`, `AegisDecisionBlocked`, `attach_decision`, `_FIX_HINTS`.
- [`aegis/sdk/__init__.py`](../aegis/sdk/__init__.py) — re-exports.
- Tests: [`tests/test_sdk_decision.py`](../tests/test_sdk_decision.py).

---

## Surface 3 — CLI (operator's daily driver)

**Design principle:** verb-oriented (modeled on `kubectl` / `gh`). Live + forensic. Structured by default.

### Commands

```bash
# Status / health
aegis status                            # health, version, uptime, counts
aegis sessions list                     # active session count
aegis sessions show <session_id>        # one session's metadata

# Decision log inspection
aegis logs tail [-n 50] [-f]            # tail recent decisions
aegis logs show <request_id>            # full formatted detail view
aegis logs query --since 1h --decision BLOCK --tool bash
aegis logs export                       # JSONL/NDJSON for SIEM ingest

# Integrity / verification
aegis verify <log-path>                 # walk hash chain + tip pointer

# Policy
aegis policy validate <path>            # lint a policy file
aegis policy show                       # render the active policy
aegis policy explain --decision-id <req>  # why did this request decide as it did

# Adversarial + perf evaluation
aegis bench [--mode balanced]           # bundled adversarial corpus
aegis bench-perf                        # latency / throughput benchmarks

# Operations
aegis up [--port 8080] [--policy ./p.yaml]   # start the proxy
aegis genkey                            # 32-byte hex master key
aegis mcp-wrap -- <mcp-cmd>             # wrap an MCP server
```

### Where this lives in the code

- [`aegis/cli.py`](../aegis/cli.py) — all subcommands.
- The drill-down formatted view is `_render_decision_detail`.
- The structured query is `aegis logs query` — supports `--since 1h`, `--since 15m`, ISO timestamps.

---

## Surface 4 — Dashboard (optional, opinionated, single-page)

**Design principle:** solo developers and small teams shouldn't need Splunk. Single binary, single HTML page, no external dependencies. The dopamine loop that gets developers actually watching the tool.

### What it shows

- **Live decision stream** — reverse-chronological, color-coded by ALLOW/WARN/BLOCK, click-through to full payload JSON.
- **Counters** — total / allow / warn / block in the current 200-entry window.
- **Block-rate sparkline** — last 5 minutes, 30 buckets, SVG-rendered.
- **Per-layer ALLOW vs BLOCK bars** — see which layer is contributing the most blocks.
- **Top blocked tools** — actionable signal that you should tighten policy on tool X.
- **Health header** — version, uptime, mode, active sessions, log entries.

### What it deliberately doesn't show

- Real-time graphs that update every second and burn CPU
- Anything that requires reading a manual to interpret
- External font / icon CDNs (auditable on locked-down networks)

### How to access it

```bash
aegis up                           # start the proxy as usual
# Then in a browser:
open http://localhost:8080/aegis/dashboard
```

### Where this lives in the code

- [`aegis/proxy/dashboard.py`](../aegis/proxy/dashboard.py) — the single-page HTML (one string constant).
- [`aegis/proxy/app.py`](../aegis/proxy/app.py) — the `/aegis/dashboard` route.
- Tests: [`tests/test_dashboard.py`](../tests/test_dashboard.py) verify HTML response, no external resources, < 50 KB.

For larger / multi-tenant deployments, prefer Prometheus + Grafana via [`/metrics`](../aegis/metrics.py).

---

## Surface 5 — Structured logs (the source of truth)

**Design principle:** the most-used AEGIS interface in production is the JSONL audit log piped into existing security tooling. Everything else is a view onto this.

### Schema (`aegis.decision/v1`)

```json
{
  "schema": "aegis.decision/v1",
  "policy_version": "1.4.0",
  "request_id": "req_01H8Y3K9M2NQRX7P4VBFCZTAH",
  "session_id": "ses_4f2a2c8b",
  "user_id": null,
  "tenant_id": null,
  "upstream": "anthropic",
  "decision": "BLOCK",
  "blocked_by": ["lattice", "capability", "intent_drift"],
  "reason": "L0 cannot authorize tool calls (effective=L0, tool=set_email_forwarding)",
  "score": 0.78,
  "mode": "balanced",
  "votes": {
    "ccpt_verify":  { "verdict": "ALLOW", "reason": "all envelopes signed",       "confidence": 1.0, "metadata": {"chunks": 3} },
    "canary":       { "verdict": "ALLOW", "reason": "no canary leakage",          "confidence": 1.0, "metadata": {} },
    "lattice":      { "verdict": "BLOCK", "reason": "L0 cannot authorize ...",    "confidence": 1.0, "metadata": {"effective_level": "L0", "requires": []} },
    "intent_drift": { "verdict": "BLOCK", "reason": "intent drift: ...",          "confidence": 0.75, "metadata": {"similarity": 0.18, "threshold": 0.30} },
    "capability":   { "verdict": "BLOCK", "reason": "no capability token ...",    "confidence": 1.0, "metadata": {"tool": "set_email_forwarding"} }
  },
  "tool_calls": [
    { "tool": "set_email_forwarding", "params_redacted": ["to"], "summary": "set forwarding rule to ..." }
  ],
  "input_chunks": [
    { "chunk_id": "...", "origin": "system", "level": "L3" },
    { "chunk_id": "...", "origin": "user",   "level": "L2" },
    { "chunk_id": "...", "origin": "tool",   "level": "L0" }
  ],
  "timestamp": 1714492334.187
}
```

The wrapper structure adds a tamper-evident hash chain:

```json
{
  "seq": 1234,
  "ts": 1714492334.187,
  "prev_hash": "sha256:9f3a2b...",
  "hash": "sha256:7a3c8d...",
  "payload": { ...the schema above... }
}
```

### Properties

- **Versioned schema.** Top-level `schema: "aegis.decision/v1"`. Bumping the format requires a major-version-style change.
- **Hash-chained.** `prev_hash` of entry N+1 = `hash` of entry N. Tampering breaks every subsequent hash.
- **Truncation-detectable.** Sidecar `<log>.tip` file records the latest seq+hash atomically. `aegis verify` cross-checks it.
- **Redacted parameters.** `params_redacted` lists keys but never values (no PII, no secrets in the log).
- **Per-tenant filtering.** `tenant_id` and `user_id` are optional fields populated from `Session.metadata` for SIEM filtering.

### Ingestion

Most operators pipe the log into Splunk / Elastic / Datadog with Vector / Fluent Bit / Filebeat:

```toml
# Vector example
[sources.aegis]
type = "file"
include = ["/var/aegis/aegis-decisions.log"]
read_from = "beginning"

[sinks.splunk]
type = "splunk_hec_logs"
inputs = ["aegis"]
endpoint = "https://splunk.internal:8088"
```

### Where this lives in the code

- [`aegis/log.py`](../aegis/log.py) — `DecisionLog`, `iter_log`, `verify_log`, sidecar tip pointer.
- [`aegis/proxy/orchestrator.py`](../aegis/proxy/orchestrator.py) — `_log_payload` builds the `aegis.decision/v1` schema.
- Tests: [`tests/test_log.py`](../tests/test_log.py), [`tests/security/test_log_integrity.py`](../tests/security/test_log_integrity.py).

---

## How to choose the right surface

| You are… | Use… |
|---|---|
| An end user of an agent that uses AEGIS | (Nothing — AEGIS is invisible to you) |
| A developer building an agent on top of AEGIS | The Python SDK ([`aegis.sdk`](../aegis/sdk/)) — typed `AegisDecision` / `AegisDecisionBlocked` |
| An operator running the proxy | The CLI (`aegis logs show`, `aegis status`, `aegis verify`) |
| A solo dev wanting eyes on it | The dashboard (`/aegis/dashboard`) |
| A SIEM / SOC team / compliance auditor | The JSONL audit log (schema `aegis.decision/v1`) |
| A platform team running observability | Prometheus `/metrics` |

Every surface is a view onto the structured audit log. If you ever need ground truth, that's where it lives.
