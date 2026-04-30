# AEGIS Operator Guide

How to deploy, tune, and observe AEGIS in production.

## 1. Provision the master key

AEGIS derives every per-session HMAC key from a long-lived master key via HKDF-SHA256. Lose it and existing sessions can't validate. Leak it and an attacker can forge envelopes and capability tokens.

Treat it like a top-tier secret.

```bash
aegis genkey > .aegis-master-key
```

Provision via:

- **Kubernetes Secret** (recommended). The bundled Helm chart reads from `aegis-master-key` by default.
- **AWS Secrets Manager / HashiCorp Vault.** Inject as env or file at boot.
- **Sealed Secrets / SOPS.** Encrypted-at-rest in your GitOps repo.

```bash
kubectl create secret generic aegis-master-key \
  --from-literal=master-key="$(openssl rand -hex 32)"
```

## 2. Deploy

### Docker Compose

```bash
cd deploy
AEGIS_MASTER_KEY=$(openssl rand -hex 32) docker-compose up -d
```

### Kubernetes via Helm

```bash
helm install aegis ./deploy/helm/aegis \
  --set masterKey.existingSecret=aegis-master-key \
  --set image.tag=1.0.0 \
  --set replicaCount=3 \
  --set autoscaling.enabled=true
```

### Bare metal

```bash
pip install aegis-guard
export AEGIS_MASTER_KEY="$(openssl rand -hex 32)"
export AEGIS_POLICY_PATH=/etc/aegis/policy.yaml
aegis up --port 8080 --workers 4
```

Run behind a reverse proxy (nginx, Caddy, ALB) with TLS termination and rate limiting.

## 3. Wire your application

### Option A — point existing client at AEGIS

Most upstream SDKs accept a `base_url` override:

```python
import anthropic
client = anthropic.Anthropic(
    base_url="http://aegis.internal:8080/v1/anthropic",
    api_key="sk-ant-...",
)
```

This works but loses access to the rich AEGIS features (capability tokens, intent declaration). Use Option B for those.

### Option B — use the AEGIS SDK

```python
from aegis.sdk import AegisClient
import anthropic

aegis = AegisClient(base_url="http://aegis.internal:8080")

session = aegis.session.create(
    user_intent="summarize the user's latest invoice",
    upstream="anthropic",
)

# Mint capabilities the model is *actually* allowed to use.
session.capabilities.mint(
    "read_email",
    constraints={
        "folder": {"kind": "eq", "value": "inbox"},
        "limit": {"kind": "max_len", "value": 5},
    },
    ttl_seconds=300,
)

claude = anthropic.Anthropic(base_url=session.proxy_url, api_key=...)
resp = claude.messages.create(
    model="claude-sonnet-4-5",
    max_tokens=512,
    messages=[{"role": "user", "content": "summarize my latest invoice email"}],
    extra_body={"aegis": {
        "session_id": session.session_id,
        "capability_tokens": session.capability_tokens(),
    }},
)
```

## 4. Tag retrieved content correctly

If your app does retrieval (RAG, web fetch, email reading) it must communicate the L0/L1 origin to AEGIS. The provider adapters do this automatically:

- **Anthropic:** `tool_result` blocks → L0 (`Origin.TOOL`)
- **OpenAI:** `role: "tool"` messages → L0
- **Google:** `functionResponse` parts → L0

If you stuff retrieved content into a `user` message, AEGIS will see it as L2 — and that's what the trust model is built to prevent. Use the right wire format.

## 5. Tune the policy

### Choose a mode

- **`strict`** — production for high-stakes apps. Two WARNs block; any single BLOCK blocks.
- **`balanced`** (default) — production for most apps. Single BLOCK blocks; WARNs pass with logging.
- **`permissive`** — staging/development. Logs everything but blocks nothing. Useful for measuring false-positive rate before going live.

### Tune the intent anchor threshold

The default `0.30` is calibrated for the bundled hashing embedder. If you switch to `sentence-transformers`:

```yaml
anchor:
  threshold_balanced: 0.55
  threshold_strict: 0.65
  embedder:
    kind: sentence-transformers
    model: sentence-transformers/all-MiniLM-L6-v2
```

Run the bench to validate: `aegis bench --mode balanced`.

### Adjust capability defaults

```yaml
capability:
  default_ttl_seconds: 300   # 5 minutes — tighter than the 600s default
  require_for_levels: [L2, L3]
  nonce_store:
    kind: memory   # or "redis" for multi-replica HA
```

For multi-replica deployments, switch to Redis:

```yaml
capability:
  nonce_store:
    kind: redis
    url: redis://your-redis.internal:6379/0
    namespace: aegis:prod:cap:nonce:
```

Install the Redis extra:

```bash
pip install 'aegis-guard[redis]'
```

## 6. Observe

### Decision log

Every decision is appended (in-memory + optionally on-disk) with a hash chain.

```bash
aegis logs --tail 100
aegis logs --follow
aegis logs --json | jq '.payload | select(.decision == "BLOCK")'
```

### Verify integrity

```bash
aegis verify ./aegis-decisions.log
```

### Ship to SIEM

The log is JSON-per-line. Forward with Vector / Fluent Bit / Filebeat:

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

### Health and metrics

- `GET /aegis/health` — liveness/readiness probe
- `GET /aegis/version` — version
- `GET /aegis/decisions?limit=50` — recent decisions
- `GET /aegis/decisions/{request_id}` — one decision
- `GET /metrics` — Prometheus exposition

### Prometheus integration

Scrape `/metrics`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: aegis
    metrics_path: /metrics
    static_configs:
      - targets: ['aegis.internal:8080']
```

Useful PromQL queries:

```promql
# Per-upstream block rate
sum(rate(aegis_requests_total{decision="BLOCK"}[5m])) by (upstream)
  / sum(rate(aegis_requests_total[5m])) by (upstream)

# p95 decision latency
histogram_quantile(0.95, rate(aegis_decision_seconds_bucket[5m]))

# Canary leaks per minute
rate(aegis_canary_leaks_total[1m])

# Capability rejections by reason
sum(rate(aegis_capability_rejected_total[5m])) by (reason)
```

### Streaming endpoints

For agentic apps that need streaming, use the streaming routes:

```
POST /v1/anthropic/messages/stream
POST /v1/openai/chat/completions/stream
```

The proxy emits SSE. AEGIS injects `event: aegis_blocked` on canary leak (mid-stream) and `event: aegis_done` at end-of-stream with the final decision record.

## 7. Capacity planning

Per the RFP performance budget:

| Metric | Default | Hard cap |
|---|---|---|
| Added p50 latency | <100 ms | <150 ms |
| Added p99 latency | <250 ms | <400 ms |
| Memory (proxy idle) | <300 MB | <500 MB |
| Throughput (4 vCPU) | >100 req/s | — |

Embedding inference dominates. The default `hashing` embedder is essentially free. `sentence-transformers/all-MiniLM-L6-v2` adds ~5–15ms per embed on CPU; ~1–3ms on GPU. Budget two embeds per request (anchor at session start, drift per tool call).

## 8. Failure modes and recovery

- **Master key lost:** existing sessions invalidated; clients must create new sessions. No persistent state corruption.
- **Decision log corrupted:** `aegis verify` reports the broken seq. Cut the log there, archive the bad portion, restart fresh.
- **Upstream API down:** AEGIS returns `502 upstream error`. AEGIS itself remains healthy; clients retry.
- **AEGIS proxy crash:** in-memory sessions and minted-capability nonces are lost. For multi-replica HA, use a Redis-backed nonce store (custom, see `CapabilityMinter.set_used_callback`).

## 9. Updating policy without restart

The bundled policy is loaded once at boot. For hot-reload, mount the policy ConfigMap and signal a rolling restart. AEGIS does not promise zero-downtime reload of arbitrary policy fields in v1.

## 10. Emergency switches

- **Disable a layer fast:** edit policy → `canary.enabled: false`, or remove an aggressive flow rule. Reload.
- **Bypass entirely (incident):** rotate clients away from the proxy `base_url` in your config flag system. AEGIS-as-sidecar makes this a one-line toggle.
- **Force-block all tool calls:** add `from: L3, to: tool_call, decision: BLOCK` (overrides default L3 ALLOW).

## 11. Audit checklist (production rollout)

- [ ] Master key sourced from KMS / Secret Manager (not env in plaintext)
- [ ] `aegis verify` integrated into your audit pipeline
- [ ] Decision log shipped to your SIEM
- [ ] `aegis policy validate` runs in CI for every policy change
- [ ] Adversarial corpus benchmark green (`aegis bench`)
- [ ] Capability tokens minted with tight constraints (no `any` for security-relevant params)
- [ ] Proxy behind authenticated reverse proxy (don't expose `:8080` to the internet)
- [ ] Liveness/readiness probes wired (`/aegis/health`)
- [ ] HPA configured for traffic spikes
