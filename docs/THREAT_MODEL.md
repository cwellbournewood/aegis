# AEGIS Threat Model

## 1. Goal

AEGIS aims to dramatically raise the cost of successful prompt injection in production LLM applications. It targets the structural mismatch at the heart of injection: LLMs do not distinguish instructions from data at the token level.

This is not "prevent all attacks." It is "make the attack hard enough that defense-in-depth makes the application meaningfully more secure than an unprotected baseline."

## 2. In-scope attack vectors

| Vector | Description | Primary AEGIS Defenses |
|---|---|---|
| **Direct injection** | Adversarial text in user-controlled input asking the model to do something it shouldn't | Capability tokens, Intent drift, Canaries |
| **Indirect injection** | Adversarial text in retrieved/tool content (RAG, web pages, emails) | Lattice (L0/L1 cannot authorize), Capability tokens, Canaries |
| **Multi-turn / memory poisoning** | Injection planted in earlier turn or persistent memory | Intent Anchor, Canaries, Lattice |
| **Multi-agent contamination** | One agent's output corrupting another agent's context | CCPT cross-agent, Capability tokens, Lattice |

## 3. Out of scope

- **Jailbreaks targeting model alignment** ("DAN"-style). These are alignment failures, not injection failures. AEGIS may incidentally catch some via canaries/drift, but it is not designed for them.
- **Model extraction / training data attacks.** These are concerns for the model provider, not the application.
- **Classic supply-chain attacks on the model itself.** AEGIS treats the model as a black box.
- **Side-channel attacks on inference infrastructure.** Hardware-level concerns are downstream.
- **Denial-of-service against the proxy.** Standard rate-limiting and auth (your reverse proxy / API gateway) handles this.
- **Compromise of the master key.** If the operator's `AEGIS_MASTER_KEY` leaks, all session HMACs and capability tokens are forgeable. Treat the master key as a top-tier secret (KMS, Vault, sealed Secret).

## 4. Trust boundaries

| Entity | Trust | Notes |
|---|---|---|
| The application's developer | Trusted | Sets policy, mints capabilities, owns master key |
| The authenticated end-user | Semi-trusted (L2) | Their requests can authorize tool calls if a capability token was minted |
| The retrieval / RAG layer | Untrusted (L1) | Their content can inform answers but cannot authorize actions by itself |
| Tool outputs / web pages / email | Adversarial (L0) | Treated as actively malicious |
| Other agents (sub-agents) | Untrusted (L1 by default) | Cross-agent CCPT for v2 |
| The model provider's API | Trusted to follow wire contract | Compromise of upstream API is out-of-scope |

## 5. Attacker model

We assume an attacker who:

- Has full read access to AEGIS source code (open-source)
- Can craft arbitrary content in any L0 surface (web pages, retrieved docs, emails, file uploads, prior tool outputs)
- Can craft arbitrary content in L2 user input (if they are the authenticated user)
- Cannot read the operator's `AEGIS_MASTER_KEY`
- Cannot directly observe per-session HMAC keys
- Cannot bypass the proxy (i.e., cannot send requests directly to the LLM API)

The attacker's goal: make the model invoke a tool with parameters that exfiltrate data, escalate privilege, or harm the application's integrity.

## 6. Per-layer defense properties

### CCPT
- **Property:** Origin claims are unforgeable. A retrieved document cannot impersonate L3.
- **Failure modes:** Master key compromise. Application bug that mis-tags input origin (operator error).
- **Mitigations:** Master key in KMS. Adapter test coverage on origin assignment.

### Trust Lattice
- **Property:** L0 inputs cannot authorize tool calls. L1 inputs can warn but cannot authorize alone.
- **Failure modes:** Misconfigured policy (e.g., explicitly allowing L0 → tool_call).
- **Mitigations:** `aegis policy validate`. Default policy is conservative.

### Intent Anchor
- **Property:** Tool calls semantically distant from the user's original intent are flagged.
- **Failure modes:** Multi-step tasks that legitimately drift. Embedder paraphrase blindness.
- **Mitigations:** One signal among several. Tunable thresholds. Per-step re-anchoring (operator opt-in).

### Canaries
- **Property:** A canary leak is high-confidence evidence of injection.
- **Failure modes:** Canary-aware attackers crafting "do not output any AEGIS tokens" injections; sophisticated attackers who know multiple template patterns.
- **Mitigations:** Per-session random tokens, multiple canary instructions with different trigger phrases, treated as one signal among several rather than a sole gate.

### Capability Tokens
- **Property:** Tool execution requires a token the model cannot produce; tokens bind tool + parameter constraints + session.
- **Failure modes:** Token leakage in logs (mitigated by redaction). Operator minting overly-broad tokens (e.g., `send_email` with no constraints).
- **Mitigations:** Single-use, time-bounded, per-session. Constraint primitives encourage tight binding (`eq`, `in`, `regex`).

## 7. Defense-in-depth invariant

For any successful attack on a tool call, the attacker must defeat **all** of:

1. The lattice rule for the effective causal-origin level
2. The capability gate (no token, or token doesn't bind the proposed parameters)
3. The intent drift gate (proposed action is far from user's stated intent)
4. (Optionally) the canary scan if a leak occurred

A single misconfigured policy still leaves multiple independent gates. This is the structural reason AEGIS does not collapse with a single layer's failure.

## 8. Known limitations

1. **Causal origin propagation through model paraphrase.** If the model summarizes L0 content into its own response and that response is then re-fed into the next turn's context, the new envelope's level depends on how the application re-tags it. v1 ships an explicit `derive_child` API for taint propagation; principled taint analysis is an open research direction.
2. **Streaming responses.** The current decision pipeline operates on full responses. Streaming-aware per-chunk evaluation is not implemented; until/unless it is, streaming is best disabled or buffered upstream of the proxy.
3. **Model provider wire-format drift.** Providers evolve their APIs. AEGIS adapters track stable surfaces; on breakage, we ship a patch.
4. **Client SDK telemetry.** AEGIS does not phone home. Decision logs stay local unless you choose to ship them to your SIEM.

## 9. Reporting security issues

Please report vulnerabilities by opening a **[private GitHub Security Advisory](https://github.com/cwellbournewood/aegis/security/advisories/new)**. Do not file public issues for actively exploitable bugs.

This is a community-maintained project; there is no triage or fix-turnaround SLA. Reports are handled on a best-effort basis. If timely vendor support matters to you, fork and self-maintain.

## 10. Cryptographic primitives

| Primitive | Library | Notes |
|---|---|---|
| HMAC-SHA256 | Python stdlib `hmac` | CCPT envelope sig, capability token sig |
| HKDF-SHA256 | `cryptography` package | Per-session key derivation |
| `secrets.token_*` | Python stdlib | Nonces, request IDs, canary tokens |
| Constant-time compare | `hmac.compare_digest` | Sig verification |

No custom crypto. No homemade primitives.
