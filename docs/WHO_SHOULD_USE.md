# Who should use AEGIS

This is a personal project. I'd rather you skip it than deploy it for the wrong use case and conclude it doesn't work.

## 30-second fit check

Three yes/no questions:

1. **Does your LLM call tools that write, send, delete, deploy, or execute?**
2. **Does it ever process content from sources you don't fully control?** (RAG, web fetch, user-uploaded documents, third-party APIs, MCP servers.)
3. **Would a successful prompt injection cost you more than a day to recover from?**

| Answers | Recommendation |
|---|---|
| Three yes | AEGIS is probably useful. Try it. |
| Two yes | Run it in `permissive` mode for the audit trail. Tighten over time. |
| One yes or fewer | Use simpler tools. Content classifiers and basic input validation cover your case. |

## The three conditions, expanded

### 1. The LLM has agency that touches the real world

AEGIS's strongest layer is capability tokens. If there are no consequential tool calls to authorize, that layer is meaningless. A pure chatbot answering questions doesn't need AEGIS.

### 2. The LLM ingests untrusted content as part of normal operation

Indirect injection enters through the surfaces where attacker-controlled text reaches the model: RAG, web fetch, email reading, MCP calls. If your LLM only sees content you wrote yourself, you don't need AEGIS for indirect injection. Direct injection from your own users is still covered, but standard application security is enough for that surface alone.

### 3. The consequences of a successful attack are non-trivial

Worth the modest latency overhead and engineering effort to prevent.

## Where it fits naturally

- An agent (yours or someone else's, like Claude Code) that calls third-party MCP servers. The MCP wrap path is where AEGIS gives strong protection to a setup that's otherwise wide-open.
- An internal agent that reads tickets, emails, or CRM data and can take actions on them.
- A RAG agent over user-uploaded documents that can write to anything.
- A research project on LLM security that needs a structural baseline to test attacks against.

## Infrastructure

- 2 vCPU, 1 GB RAM, Docker. No GPU, no Kubernetes required.
- Default hashing embedder is essentially free. Optional `sentence-transformers` extra adds an ~80 MB CPU model.

Deployment shapes:

| Shape | When |
|---|---|
| **Localhost sidecar** | Individual developer with Claude Code + MCP. ~5 minutes to install. |
| **Per-pod sidecar** | Kubernetes; one AEGIS container next to each application pod. |
| **Shared internal gateway** | Multi-tenant platforms; per-tenant key derivation via HKDF. |
| **Wrapped MCP** | Each MCP server fronted by `aegis mcp-wrap`. Defends the boundary where attacker-controlled content actually enters. |

Not a fit:

- Serverless functions with cold-start sensitivity. Python startup and (if enabled) embedding-model load are non-zero.
- Mobile or embedded devices. A future native-language port is plausible but not in scope for 1.0.

## When AEGIS is the wrong tool

- Pure chatbots. Use a content classifier.
- Agents that only see content you authored. Standard application security.
- Pre-product prototypes. Come back when you know what your agent does.
- Looking for a complete AI security stack. AEGIS is the action-authorization piece, not a substitute for content classification, PII detection, or jailbreak filtering.

## Compared to other tools

| Tool | Approach |
|---|---|
| Lakera, Pangea, ProtectAI | Content classification: "does this text look malicious?" |
| NeMo Guardrails | Conversation-flow rules, output validation. |
| Rebuff | Canary tokens + prompt detection. |
| OWASP / NIST AI RMF | Frameworks, not tools. |
| AEGIS | Structural authorization + provenance + drift + canary, composed. |

AEGIS is complementary to most of these, not a replacement.

## Still not sure?

Run AEGIS in `permissive` mode for a week. It logs every decision but blocks nothing. Review the log. If it would have blocked attacks you actually worry about, you have your answer.
