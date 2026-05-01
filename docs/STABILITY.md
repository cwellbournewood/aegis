# Stability and compatibility

AEGIS is pre-1.0. This doc says explicitly which surfaces are frozen and which can still move, so an integrator can decide what to depend on and where to add a shim.

The baseline rule: anything not listed here is "in motion" until 1.0.

## Frozen at 0.9

These shapes will not break before 1.0. Bug fixes are in scope; semantics are not.

| Surface | What's frozen |
|---|---|
| **HTTP, `/aegis/health`** | Path, response shape (`status`, `version`, `uptime_seconds`, `active_sessions`, `log_entries`, `policy_mode`). |
| **HTTP, `/aegis/decisions`** | Path, response shape (`count`, `entries[]`). Per-entry `seq` is monotonic and stable. |
| **HTTP, `/metrics`** | Prometheus exposition format. Counter and histogram names beginning with `aegis_` are stable; new metrics may be added, existing ones will not be renamed before 1.0. |
| **Wire-format adapters** | `/v1/anthropic/messages`, `/v1/openai/chat/completions`, `/v1/google/...:generateContent` accept and return the upstream provider's wire format unchanged. AEGIS-specific extension fields live under `extra_body.aegis`. |
| **Decision log schema** | `aegis.decision/v1`. Per-record fields (`request_id`, `session_id`, `decision`, `reason`, `votes`, `blocked_by`, `tool_calls`, `input_chunks`, `prev_hash`, `entry_hash`) are stable. New fields may be added; existing ones will not be removed or retyped before 1.0. |
| **Hash chain** | Algorithm (SHA-256 over canonical JSON), tip-pointer sidecar format, `aegis verify` semantics. |
| **CLI verbs** | `aegis up`, `status`, `genkey`, `verify`, `bench`, `bench-perf`, `mcp-wrap`, `policy {validate\|show\|explain}`, `logs {tail\|show\|query\|export}`, `sessions {list\|show}`. Flag names may grow; existing flags will not be repurposed. |
| **Master key derivation** | HKDF-SHA256 over the 32-byte master key, info string `aegis/session/v1/<session_id>`. Existing logs remain verifiable. |
| **CCPT envelope format** | HMAC-SHA256 over canonical JSON of `{origin, level, content_hash, ts, kid}`, base64url tag. The wire structure (envelope wrapper around content) is stable. |
| **MCP wrapper** | JSON-RPC framing, canary-leak BLOCK error shape (`code: -32000`, `data.aegis.{decision,reason,hits}`). |

## Likely to move before 1.0

These are the surfaces under active development. Pin to a specific 0.9.x patch if you depend on them.

| Surface | What may change |
|---|---|
| **Policy YAML schema** | Field names and structure for `flows`, `anchor`, `canary`, `capability`. A pre-1.0 release will publish a policy-migration tool. |
| **Capability constraint kinds** | The set is `eq`, `prefix`, `regex`, `max_len`, `range`, `any`. Additional kinds (e.g. `glob`, `oneof`) may land; the existing kinds' semantics are stable. |
| **Anchor thresholds** | Defaults for `threshold_balanced` / `threshold_strict` may be retuned as the embedder evolves. Set explicit thresholds in your policy if you don't want this. |
| **Default embedder** | `kind: hashing` is the default. Calibrated `sentence-transformers` defaults are pending and may become the new default in 1.0. |
| **Streaming events** | The `aegis_blocked` SSE event shape is provisional. The fact that streaming chunks are scanned is stable; the exact event payload may grow fields. |
| **Python and TS SDKs** | The `AegisClient` shape is stable in spirit; specific method names (`session.capabilities.mint` vs `session.mint_capability`) may be unified across SDKs before 1.0. |
| **Dashboard** | `/aegis/dashboard` is a single static HTML page meant for operators. The fact that it polls `/aegis/health` and `/aegis/decisions` is stable; the layout will keep evolving. |

## What 1.0 commits to

1.0 freezes the policy YAML schema and the SDK surface. After that, breaking changes require a major version bump and a documented migration path.

The hash chain, wire-format adapters, decision log, and HTTP API are already stable at 0.9 and will remain stable across the 0.9 → 1.0 transition. A 0.9.x decision log will verify with a 1.0.x `aegis verify`.

## Versioning

[SemVer](https://semver.org/). Pre-1.0 the rule is:

- 0.9.x → 0.9.y is a patch (bug fixes, doc changes, internal refactors).
- 0.9.x → 0.10.0 is allowed to break the surfaces in the "Likely to move" table above.
- Anything in the "Frozen at 0.9" table will only break across a 0.x → 1.0 boundary, with a migration note in CHANGELOG.

Each release publishes:

- A multi-arch container image at `ghcr.io/cwellbournewood/aegis:<version>` (and `:latest` for the most recent stable release).
- A cosign keyless signature.
- A SLSA build-provenance attestation.
- An SPDX SBOM, attached to the GitHub Release and as a cosign attestation against the image.

Verification:

```bash
cosign verify ghcr.io/cwellbournewood/aegis:0.9.0 \
  --certificate-identity-regexp='https://github.com/cwellbournewood/aegis/.+' \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com

gh attestation verify --owner cwellbournewood \
  oci://ghcr.io/cwellbournewood/aegis:0.9.0
```
