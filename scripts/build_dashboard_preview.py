"""Generate a static, mock-populated copy of the live dashboard.

The live dashboard at `aegis/proxy/dashboard.py` polls `/aegis/health` and
`/aegis/decisions` for live data. Without a running proxy it shows empty
panels, useful for the empty state but not great as a visual preview.

This script bakes in a mock fetch override so the file at `ui/dashboard.html`
shows the dashboard fully populated for design review and screenshots.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from aegis.proxy.dashboard import DASHBOARD_HTML  # noqa: E402

MOCK_INIT = r"""<script>
// PREVIEW MODE, bake in mock events so the static file shows a populated state.
// In the real dashboard at /aegis/dashboard, these come from /aegis/health and
// /aegis/decisions on the running proxy.
(function () {
  const now = Date.now() / 1000;
  const MOCK_HEALTH = {
    status: 'ok',
    version: '1.0.0',
    uptime_seconds: 1224732,
    active_sessions: 23,
    log_entries: 14832,
    policy_mode: 'balanced'
  };
  const MOCK_ENTRIES = [
    { seq: 14832, ts: now - 5, payload: {
      request_id: 'req_01H8Y3K9M2NQRX7', session_id: 'ses_4f2a2c8b',
      upstream: 'anthropic', decision: 'BLOCK',
      reason: 'L0 cannot authorize tool calls (effective=L0, tool=set_email_forwarding)',
      score: 0.78, mode: 'balanced', latency_ms: 43, timestamp: now - 5,
      blocked_by: ['lattice', 'capability', 'intent_drift'],
      votes: {
        ccpt_verify: { verdict: 'ALLOW', reason: '3 envelopes verified, all signatures valid' },
        canary:      { verdict: 'ALLOW', reason: 'no canary tokens leaked in output' },
        lattice:     { verdict: 'BLOCK', reason: 'L0 origin: retrieved email msg_id=8821 cannot authorize tool_call' },
        intent_drift:{ verdict: 'BLOCK', reason: 'cosine=0.18 below threshold=0.22, anchor: "summarize my latest invoice email"' },
        capability:  { verdict: 'BLOCK', reason: 'no token bound to set_email_forwarding, 2 in scope: read_email, send_email(self)' }
      },
      tool_calls: [{ tool: 'set_email_forwarding', summary: 'set forwarding rule to attacker@evil.example', params_redacted: ['to'] }],
      input_chunks: [
        { chunk_id: 'a3f8...', origin: 'system', level: 'L3' },
        { chunk_id: 'b2c4...', origin: 'user',   level: 'L2' },
        { chunk_id: 'c8e1...', origin: 'tool',   level: 'L0' }
      ]
    }},
    { seq: 14831, ts: now - 12, payload: {
      request_id: 'req_01H8X8M2', session_id: 'ses_4f2a2c8b', upstream: 'anthropic',
      decision: 'ALLOW', reason: 'all gates ALLOW', score: 0.0, mode: 'balanced',
      latency_ms: 92, timestamp: now - 12, blocked_by: [],
      votes: {
        ccpt_verify: { verdict: 'ALLOW', reason: 'envelopes verified' },
        canary:      { verdict: 'ALLOW', reason: 'clean' },
        lattice:     { verdict: 'ALLOW', reason: 'L2 to tool_call permitted' },
        intent_drift:{ verdict: 'ALLOW', reason: 'cosine=0.81, aligned with anchor' },
        capability:  { verdict: 'ALLOW', reason: 'token cap_9b3d consumed' }
      },
      tool_calls: [{ tool: 'read_email', summary: 'read invoice from inbox', params_redacted: ['folder', 'limit'] }],
      input_chunks: [{ chunk_id: 'd9a2...', origin: 'system', level: 'L3' }, { chunk_id: 'e1b5...', origin: 'user', level: 'L2' }]
    }},
    { seq: 14830, ts: now - 18, payload: {
      request_id: 'req_01H8X7P4', session_id: 'ses_4f2a2c8b', upstream: 'anthropic',
      decision: 'ALLOW', reason: 'all gates ALLOW', score: 0.0, mode: 'balanced',
      latency_ms: 78, timestamp: now - 18, blocked_by: [],
      votes: {
        ccpt_verify:       { verdict: 'ALLOW', reason: 'all envelopes verified' },
        canary:            { verdict: 'ALLOW', reason: '3 canaries seeded' },
        lattice:           { verdict: 'ALLOW', reason: 'no tool calls' },
        intent_drift_text: { verdict: 'ALLOW', reason: 'anchor established' }
      },
      tool_calls: [],
      input_chunks: [{ chunk_id: 'f2e8...', origin: 'user', level: 'L2' }]
    }},
    { seq: 14829, ts: now - 56, payload: {
      request_id: 'req_01H8Z1A0', session_id: 'ses_8c1e7f2d', upstream: 'openai',
      decision: 'WARN', reason: 'intent drift below balanced threshold',
      score: 0.28, mode: 'balanced', latency_ms: 105, timestamp: now - 56, blocked_by: [],
      votes: {
        ccpt_verify: { verdict: 'ALLOW', reason: 'envelopes verified' },
        canary:      { verdict: 'ALLOW', reason: 'clean' },
        lattice:     { verdict: 'ALLOW', reason: 'L2 origin' },
        intent_drift:{ verdict: 'WARN',  reason: 'cosine=0.42 below balanced threshold (0.55), would BLOCK in strict mode' },
        capability:  { verdict: 'ALLOW', reason: 'token cap_71fa consumed' }
      },
      tool_calls: [{ tool: 'bash', summary: 'list current directory contents', params_redacted: ['cmd'] }],
      input_chunks: []
    }},
    { seq: 14828, ts: now - 72, payload: {
      request_id: 'req_01H902B9', session_id: 'ses_8c1e7f2d', upstream: 'openai',
      decision: 'ALLOW', reason: 'all gates ALLOW', score: 0.0, mode: 'balanced',
      latency_ms: 71, timestamp: now - 72, blocked_by: [],
      votes: {
        ccpt_verify:       { verdict: 'ALLOW', reason: 'verified' },
        canary:            { verdict: 'ALLOW', reason: 'clean' },
        lattice:           { verdict: 'ALLOW', reason: 'no tool calls' },
        intent_drift_text: { verdict: 'ALLOW', reason: 'aligned' }
      },
      tool_calls: [],
      input_chunks: []
    }},
    { seq: 14827, ts: now - 86, payload: {
      request_id: 'req_01H903F1', session_id: 'ses_a1b2c3d4', upstream: 'anthropic',
      decision: 'BLOCK', reason: 'canary leak detected', score: 0.85, mode: 'balanced',
      latency_ms: 38, timestamp: now - 86,
      blocked_by: ['canary', 'intent_drift'],
      votes: {
        ccpt_verify: { verdict: 'ALLOW', reason: 'verified' },
        canary:      { verdict: 'BLOCK', reason: 'canary token AEGIS-CANARY-9F2A leaked in tool params, injection confirmed' },
        lattice:     { verdict: 'ALLOW', reason: 'L2 origin' },
        intent_drift:{ verdict: 'BLOCK', reason: 'cosine=0.09, severe drift, anchor: "generate a quarterly chart"' },
        capability:  { verdict: 'WARN',  reason: 'bash token in scope but params do not match schema' }
      },
      tool_calls: [{ tool: 'bash', summary: 'rm -rf, system reset request', params_redacted: ['cmd'] }],
      input_chunks: [{ chunk_id: 'aa11...', origin: 'tool', level: 'L0' }]
    }}
  ];

  const origFetch = window.fetch;
  window.fetch = async function (url, opts) {
    if (typeof url === 'string') {
      if (url.includes('/aegis/health')) {
        return new Response(JSON.stringify(MOCK_HEALTH), {
          status: 200, headers: { 'content-type': 'application/json' }
        });
      }
      if (url.includes('/aegis/decisions')) {
        return new Response(JSON.stringify({ count: MOCK_ENTRIES.length, entries: MOCK_ENTRIES }), {
          status: 200, headers: { 'content-type': 'application/json' }
        });
      }
    }
    return origFetch(url, opts);
  };
})();
</script>
"""


def main() -> None:
    out_path = REPO_ROOT / "ui" / "dashboard.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Inject the mock script just before the existing inline <script>.
    rendered = DASHBOARD_HTML.replace("<script>", MOCK_INIT + "<script>", 1)
    out_path.write_text(rendered, encoding="utf-8")
    print(f"wrote {len(rendered):,} bytes to {out_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
