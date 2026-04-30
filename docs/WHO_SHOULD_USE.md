# Who should use AEGIS

AEGIS is not for everyone running an LLM. Targeting it well makes adoption faster and the project useful where it matters; targeting it broadly would make it look unserious. This page is the explicit "is this for me?" filter.

## The 30-second decision rubric

Three yes/no questions:

1. **Does your LLM call tools that write, send, delete, deploy, or execute?**
   (Send email, modify a database, post to an API, run shell commands, deploy code, move money, change configurations.)
2. **Does it ever process content from sources you don't fully control?**
   (RAG over user-uploaded documents. Web browsing. Reading emails. Customer support tickets. Third-party APIs. MCP servers maintained by other parties.)
3. **Would a successful prompt injection cost you more than a day of engineering time to recover from?**
   (Financial loss. Data exfiltration. Regulatory exposure. Reputational damage. Safety incident.)

| Answers | Recommendation |
|---|---|
| **Three yes** | AEGIS is built for you. Deploy it. |
| **Two yes** | AEGIS is worth deploying in `permissive` mode for the audit trail alone. Consider tightening over time. |
| **One yes or fewer** | There are simpler tools. Don't deploy AEGIS — you'll create false friction before identifying the real threat surface. |

We'd rather you not deploy AEGIS than deploy it badly and conclude it doesn't work.

## The fit criteria, expanded

AEGIS earns its keep when **all three** are simultaneously true:

### 1. The LLM has agency that touches the real world

AEGIS's strongest layer (capability tokens) is meaningless if there are no consequential tool calls to authorize. A pure chatbot answering questions doesn't need AEGIS — content classifiers and standard input filtering handle that case fine.

If you can't name a tool the model can call that has a real-world effect, you don't need AEGIS yet.

### 2. The LLM ingests untrusted content as part of normal operation

The whole reason indirect injection is interesting is that *attacker-controlled text ends up in the model's context window through legitimate channels*. RAG, web fetch, email reading, MCP calls — these are the surfaces where injection enters. If your LLM only ever sees content you wrote yourself, the indirect-injection threat doesn't exist for you. (Direct injection from your own users still does, but that's covered by the lattice and capability layers without much ceremony.)

### 3. The consequences of a successful attack are non-trivial

Worth spending engineering effort and the (modest) latency overhead to prevent. Most production agentic systems clear this bar.

---

## Ideal user profiles

Where the three criteria intersect, five profiles dominate:

### Profile 1 — Enterprise AI platform teams

A company building internal agents — a customer-support agent reading tickets, a sales agent reading CRM, an ops agent that can restart services. They have an MLSecOps or AppSec function that needs an audit trail and a defensible "what did we do about prompt injection" answer for SOC 2, ISO 27001, or upcoming AI regulations (EU AI Act high-risk classifications, NIST AI RMF).

AEGIS gives them the structural defense plus the hash-chained tamper-evident log.

### Profile 2 — Agentic SaaS vendors

Products like AI assistants for legal, finance, healthcare, or DevOps that take actions on customer data. Threat model is severe (one bad action across a multi-tenant system is catastrophic), and customers are starting to ask hard questions in security questionnaires.

AEGIS becomes both a control and a marketing artifact.

### Profile 3 — Security-conscious builders of MCP-using agents

Probably the largest near-term audience. Anyone running Claude Code, Cursor, Cline, or similar with multiple MCP servers connected — especially MCP servers maintained by third parties.

The `aegis-mcp-wrap` deployment path is built for exactly this user.

### Profile 4 — Red teams and AI security researchers

Not deployers in production, but heavy users in evaluation contexts. They need a structural baseline to test attacks against, and the open-source nature lets them probe and improve it. This audience matters because they're who validates the project's claims publicly.

### Profile 5 — Regulated-industry pilots

Banks, hospitals, government agencies running pilots of agentic AI. Cannot ship without a documented threat model and a control to point to. AEGIS plus its threat model is one of the few open-source artifacts that meets that bar.

---

## Infrastructure profile

AEGIS is **lightweight by design** — no GPU, no Kubernetes required, no managed cloud dependency.

Realistic minimum: a single Linux host or container with **2 vCPU and 1 GB RAM** running Docker. The default hashing embedder is essentially free (hashing-feature-vectors, not a transformer). For higher-quality drift detection, the optional `sentence-transformers` extra adds a CPU-friendly ~80 MB model.

Deployment shapes that fit naturally:

| Shape | When |
|---|---|
| **Localhost sidecar** | Individual developers running Claude Code with MCPs. Single Docker container, pointed at by `ANTHROPIC_BASE_URL`. ~5 minutes. |
| **Per-pod sidecar** | Kubernetes deployment, where each application pod has an AEGIS container alongside it. Standard service-mesh pattern. |
| **Shared internal gateway** | Multi-tenant platforms, one AEGIS deployment serves many internal applications. Per-tenant key derivation via HKDF. |
| **Wrapped MCP** | Claude Code or any MCP-using agent. Each MCP server fronted by `aegis-mcp-wrap`. Defends the perimeter where it actually matters. |

Infrastructure that does **not** fit AEGIS well:

- **Serverless functions** where cold-start time matters (the embedding model load adds ~2–4 seconds with the `embed` extra; the default hashing embedder is fine but Python startup itself isn't free).
- **Mobile / embedded devices** where running a Python proxy is impractical. A future C++/Rust port is plausible but not in scope for v1.

---

## Who should NOT deploy AEGIS

This belongs in the README too as a credibility move.

- **Pure chatbots.** No tools = no capability layer to anchor on. Use a content classifier and basic input validation.
- **Agents that only see content you wrote yourself.** No untrusted input surface = no indirect-injection threat. Standard application security suffices.
- **Pre-product prototypes.** Until you've decided what your agent does, AEGIS will create false friction before you've identified the real threat surface. Come back when you ship v1.
- **Looking for a complete AI security solution.** AEGIS doesn't do PII detection, toxicity filtering, or jailbreak classification. It's the action authorization layer. Pair it with a content classifier if you need both.

---

## How AEGIS compares to alternatives

| Tool | Approach | Fit |
|---|---|---|
| **Lakera, Pangea, ProtectAI** | Content classification — "does this text look malicious?" | Useful for content filtering. Bypassed by sufficiently creative natural language. |
| **NeMo Guardrails** | Conversation-flow rules + output validation | Strong on conversation shaping. Less focused on tool-call authorization. |
| **Rebuff** | Canary tokens + prompt detection | Single-layer defense. Great for low-stakes detection. |
| **OWASP guidance / NIST AI RMF** | Framework, not a tool | Pair with AEGIS — they give you the why, AEGIS gives you the how. |
| **AEGIS** | Structural authorization + provenance + drift + canary, composed | Built for agents that take consequential actions. |

AEGIS is complementary to most of these, not a replacement. The threat model document explicitly recommends pairing AEGIS with a content classifier where PII/toxicity matters.

---

## Still not sure?

Run AEGIS in `permissive` mode for a week. It logs every decision but blocks nothing. Review the log. If you see attempted blocks that match the attack vectors you actually worry about, you have your answer.
