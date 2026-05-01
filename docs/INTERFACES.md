# Interfaces

AEGIS exposes five distinct interface surfaces. Each is tuned for a different audience.

| Surface | Audience | What it looks like |
|---|---|---|
| End user | Humans interacting with the agent | Structured `aegis_denied` block returned to the agent; user sees whatever the agent does with it |
| Developer SDK | Application authors | Typed `AegisDecision` objects with `suggested_fix` |
| CLI | Operators | Verb-oriented (`aegis logs show <id>`) |
| Dashboard | Solo devs / small teams | Single-page HTML at `/aegis/dashboard` |
| Audit log | SIEMs, forensics, compliance | Schema-versioned hash-chained JSONL |

---

## End user

Tool-call blocks return HTTP 200 with the `tool_use` block rewritten to a structured `aegis_denied` message and an accompanying `text` block summarizing the reason. The agent loop sees a normal-shaped response and decides what to do, retry, surface the denial, or stop. With a well-behaved agent, end users see something like:

> *"I noticed an instruction in that email asking me to set up forwarding. That looked unusual, so I didn't act on it. Here's the summary you asked for."*

The recovery quality is a property of the agent, not AEGIS. AEGIS guarantees that the side-effecting call never reaches the upstream provider; turning that into a graceful UX is on the application.

Hard blocks (canary leaks, broken envelopes) return HTTP 451 with a brief non-technical reason, no layer names, scores, or token IDs.

Implementation: `_is_tool_call_only_block` and `_rewrite_response_with_blocked_tool_results` in [`aegis/proxy/app.py`](../aegis/proxy/app.py). Per-provider rewrite logic for Anthropic, OpenAI, and Google formats.

---

## Developer SDK

```python
from aegis.sdk import AegisDecision, AegisDecisionBlocked

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

decision.votes["lattice"].verdict   # 'ALLOW'
decision.warnings                   # tuple of AegisWarning for any WARN votes
decision.blocked_by                 # tuple of layer names that voted BLOCK
```

For a hard-blocked request, parse the HTTP 451 body:

```python
import aegis.sdk

try:
    result = client.messages.create(...)
except httpx.HTTPStatusError as exc:
    if exc.response.status_code == 451:
        err = aegis.sdk.AegisDecisionBlocked.from_http_error(exc.response.json())
        print(err.pretty())
        # AegisDecisionBlocked: L0 cannot authorize tool calls
        #   request_id: req_...
        #   blocked_by: ['lattice', 'capability', 'intent_drift']
        #   reasons:
        #     lattice:      L0 cannot authorize tool calls
        #     capability:   no capability token presented for tool=set_email_forwarding
        #     intent_drift: intent drift: similarity=0.18 < threshold=0.22
        #
        # Suggested fix:
        #   [capability]
        #   Mint a capability token for this exact (tool, parameters) before the call:
        #       session.capabilities.mint("<tool>", constraints={...})
```

Code: [`aegis/sdk/decision.py`](../aegis/sdk/decision.py).

---

## CLI

```bash
aegis status                            # health, version, uptime, counters
aegis sessions list                     # active session count
aegis sessions show <session_id>        # one session's metadata

aegis logs tail [-n 50] [-f]            # tail recent decisions
aegis logs show <request_id>            # full formatted detail
aegis logs query --since 1h --decision BLOCK --tool bash
aegis logs export                       # JSONL/NDJSON for SIEM ingest

aegis verify <log-path>                 # walk hash chain + tip pointer

aegis policy validate <path>
aegis policy show
aegis policy explain --decision-id <req>

aegis bench [--mode balanced]           # adversarial corpus
aegis bench-perf                        # latency / throughput

aegis up [--port 8080] [--policy ./p.yaml]
aegis genkey
aegis mcp-wrap -- <mcp-cmd>             # wrap an MCP server
```

Code: [`aegis/cli.py`](../aegis/cli.py).

---

## Dashboard

```bash
aegis up
open http://localhost:8080/aegis/dashboard
```

Single-page HTML, no external resources, under 50 KB. Polls `/aegis/decisions` every second. Shows:

- Live decision stream, reverse-chronological, color-coded, click-through to full payload JSON
- Counters, total / allow / warn / block in the current window
- Block-rate sparkline, last 5 minutes, SVG-rendered
- Per-layer ALLOW vs BLOCK bars
- Top blocked tools

For larger / multi-tenant deployments, prefer Prometheus + Grafana via `/metrics`.

Code: [`aegis/proxy/dashboard.py`](../aegis/proxy/dashboard.py).

---

## Audit log

Schema `aegis.decision/v1`:

```json
{
  "schema": "aegis.decision/v1",
  "policy_version": "0.9.0",
  "request_id": "req_01H8Y3K9M2NQRX7P4VBFCZTAH",
  "session_id": "ses_4f2a2c8b",
  "user_id": null,
  "tenant_id": null,
  "upstream": "anthropic",
  "decision": "BLOCK",
  "blocked_by": ["lattice", "capability", "intent_drift"],
  "reason": "L0 cannot authorize tool calls",
  "score": 0.78,
  "mode": "balanced",
  "votes": {
    "ccpt_verify":  { "verdict": "ALLOW", "reason": "all envelopes signed",    "confidence": 1.0, "metadata": {"chunks": 3} },
    "canary":       { "verdict": "ALLOW", "reason": "no canary leakage",       "confidence": 1.0, "metadata": {} },
    "lattice":      { "verdict": "BLOCK", "reason": "L0 cannot authorize ...", "confidence": 1.0, "metadata": {"effective_level": "L0"} },
    "intent_drift": { "verdict": "BLOCK", "reason": "intent drift: ...",       "confidence": 0.75, "metadata": {"similarity": 0.18, "threshold": 0.22} },
    "capability":   { "verdict": "BLOCK", "reason": "no capability token ...", "confidence": 1.0, "metadata": {"tool": "set_email_forwarding"} }
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

Wrapped with a hash chain:

```json
{
  "seq": 1234,
  "ts": 1714492334.187,
  "prev_hash": "sha256:9f3a2b...",
  "hash": "sha256:7a3c8d...",
  "payload": { ...the schema above... }
}
```

Properties:

- Versioned `schema` field. Schema changes bump the version.
- `prev_hash` of entry N+1 = `hash` of entry N. Tampering breaks every subsequent hash.
- Sidecar `<log>.tip` records the latest seq+hash atomically. `aegis verify` cross-checks it for tail-truncation detection.
- `params_redacted` lists keys but not values.
- `tenant_id` and `user_id` are optional, populated from `Session.metadata`.

Vector pipeline example:

```toml
[sources.aegis]
type = "file"
include = ["/var/aegis/aegis-decisions.log"]
read_from = "beginning"

[sinks.splunk]
type = "splunk_hec_logs"
inputs = ["aegis"]
endpoint = "https://splunk.internal:8088"
```

Code: [`aegis/log.py`](../aegis/log.py), [`aegis/proxy/orchestrator.py:_log_payload`](../aegis/proxy/orchestrator.py).

---

## Choosing the right surface

| You are… | Use… |
|---|---|
| An end user | Nothing. AEGIS is invisible to you |
| A developer building an agent | The Python SDK. `AegisDecision` / `AegisDecisionBlocked` |
| An operator running the proxy | The CLI |
| A solo dev wanting eyes on it | `/aegis/dashboard` |
| A SIEM / SOC / compliance team | The JSONL audit log |
| A platform team running observability | Prometheus `/metrics` |

Every surface is a view onto the structured audit log. Ground truth lives there.
