"""Single-page operator dashboard, served from `/aegis/dashboard`.

Self-contained: one HTML file with inline CSS and a small amount of vanilla JS.
No external dependencies (no React, no Vue, no CDN). Polls `/aegis/decisions`
every second by default; renders block-rate sparkline, layer health, and a
live decision stream.

Why no JS framework: keeps the dependency surface small, lets ops teams audit
the dashboard's behavior without running through a build chain, and means the
dashboard works on the most locked-down internal networks.
"""

from __future__ import annotations

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AEGIS — Operator Dashboard</title>
<style>
  :root {
    --bg: #0b0d10;
    --fg: #e6e6e6;
    --dim: #888;
    --accent: #4fa3ff;
    --allow: #2bb673;
    --warn: #f5a623;
    --block: #e85a5a;
    --panel: #14171c;
    --border: #22272e;
  }
  * { box-sizing: border-box; }
  body {
    font: 13px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    margin: 0;
    background: var(--bg);
    color: var(--fg);
  }
  header {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  header h1 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
    letter-spacing: 0.02em;
  }
  header h1 .badge {
    display: inline-block;
    padding: 2px 6px;
    background: var(--accent);
    color: var(--bg);
    border-radius: 3px;
    font-size: 10px;
    margin-left: 6px;
    vertical-align: middle;
  }
  .uptime { color: var(--dim); font-size: 11px; }
  main {
    display: grid;
    grid-template-columns: 320px 1fr;
    gap: 16px;
    padding: 16px;
  }
  section {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
  }
  section h2 {
    margin: 0 0 8px;
    font-size: 11px;
    font-weight: 600;
    color: var(--dim);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .counters { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .counter { padding: 10px 0; }
  .counter .v { font-size: 24px; font-weight: 600; }
  .counter .l { color: var(--dim); font-size: 11px; }
  .counter.allow .v { color: var(--allow); }
  .counter.warn  .v { color: var(--warn); }
  .counter.block .v { color: var(--block); }
  .counter.requests .v { color: var(--accent); }
  .layers { display: flex; flex-direction: column; gap: 4px; margin-top: 8px; }
  .layer-row { display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 12px; }
  .layer-row .name { width: 110px; color: var(--dim); }
  .layer-row .bar { flex: 1; display: flex; height: 6px; border-radius: 3px; overflow: hidden; background: var(--border); }
  .layer-row .seg.allow { background: var(--allow); }
  .layer-row .seg.warn  { background: var(--warn); }
  .layer-row .seg.block { background: var(--block); }
  .stream { display: flex; flex-direction: column; gap: 0; max-height: 70vh; overflow-y: auto; }
  .row {
    display: grid;
    grid-template-columns: 90px 70px 130px 1fr 90px;
    gap: 8px;
    padding: 6px 8px;
    border-bottom: 1px solid var(--border);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    cursor: pointer;
  }
  .row:hover { background: #1b1f25; }
  .row .ts { color: var(--dim); }
  .row .dec { font-weight: 600; }
  .row .dec.allow { color: var(--allow); }
  .row .dec.warn { color: var(--warn); }
  .row .dec.block { color: var(--block); }
  .row .reason { color: var(--fg); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .row .req, .row .lat { color: var(--dim); text-align: right; }
  details { margin: 6px 0; }
  summary { cursor: pointer; user-select: none; color: var(--accent); font-size: 12px; }
  pre {
    background: #06080a;
    border-radius: 3px;
    padding: 10px;
    overflow-x: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11px;
    color: #cfd2d6;
    margin: 6px 0 0;
  }
  .spark { width: 100%; height: 60px; }
  footer { color: var(--dim); padding: 12px 20px; font-size: 11px; border-top: 1px solid var(--border); }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
</style>
</head>
<body>
<header>
  <h1>AEGIS <span class="badge">operator</span></h1>
  <div class="uptime" id="uptime">…</div>
</header>
<main>
  <aside>
    <section>
      <h2>Decisions (this view)</h2>
      <div class="counters">
        <div class="counter requests"><div class="v" id="c-total">0</div><div class="l">total</div></div>
        <div class="counter allow"><div class="v" id="c-allow">0</div><div class="l">allow</div></div>
        <div class="counter warn"><div class="v" id="c-warn">0</div><div class="l">warn</div></div>
        <div class="counter block"><div class="v" id="c-block">0</div><div class="l">block</div></div>
      </div>
    </section>
    <section style="margin-top:16px">
      <h2>Block rate (last 5 min)</h2>
      <svg class="spark" id="spark" viewBox="0 0 200 60" preserveAspectRatio="none"></svg>
    </section>
    <section style="margin-top:16px">
      <h2>Per-layer ALLOW vs BLOCK</h2>
      <div class="layers" id="layers"></div>
    </section>
    <section style="margin-top:16px">
      <h2>Top blocked tools</h2>
      <div id="top-tools" style="font-family:ui-monospace,Menlo,monospace;font-size:12px"></div>
    </section>
  </aside>
  <section>
    <h2>Live decision stream</h2>
    <div class="stream" id="stream"></div>
  </section>
</main>
<footer>
  Polling <code>/aegis/decisions</code> every 1s.
  Click any row for full detail. <a href="/aegis/health">/aegis/health</a> ·
  <a href="/metrics">/metrics</a>
</footer>
<script>
const els = {
  total: document.getElementById('c-total'),
  allow: document.getElementById('c-allow'),
  warn: document.getElementById('c-warn'),
  block: document.getElementById('c-block'),
  stream: document.getElementById('stream'),
  layers: document.getElementById('layers'),
  topTools: document.getElementById('top-tools'),
  spark: document.getElementById('spark'),
  uptime: document.getElementById('uptime'),
};

let lastSeq = 0;
const blockHistory = []; // sliding window of (timestamp, was_block)

async function fetchHealth() {
  try {
    const r = await fetch('/aegis/health');
    const h = await r.json();
    const u = Math.round(h.uptime_seconds || 0);
    const hours = Math.floor(u / 3600);
    const mins = Math.floor((u % 3600) / 60);
    els.uptime.textContent = `v${h.version} · ${hours}h${mins}m · ${h.policy_mode} · ` +
                             `${h.active_sessions} active sessions · ${h.log_entries} log entries`;
  } catch (e) { /* ignore */ }
}

async function poll() {
  try {
    const r = await fetch('/aegis/decisions?limit=200');
    const data = await r.json();
    render(data.entries || []);
  } catch (e) { /* ignore */ }
}

function render(entries) {
  const stream = els.stream;
  const decision_counts = { ALLOW: 0, WARN: 0, BLOCK: 0 };
  const layer_counts = {};
  const blocked_tools = {};
  const recent = entries.slice(-200);

  for (const e of recent) {
    const p = e.payload || {};
    const d = p.decision || '?';
    decision_counts[d] = (decision_counts[d] || 0) + 1;
    blockHistory.push({ ts: p.timestamp || e.timestamp, block: d === 'BLOCK' });
    for (const [layer, vote] of Object.entries(p.votes || {})) {
      const v = vote.verdict || 'ALLOW';
      layer_counts[layer] = layer_counts[layer] || { ALLOW: 0, WARN: 0, BLOCK: 0 };
      layer_counts[layer][v] = (layer_counts[layer][v] || 0) + 1;
    }
    if (d === 'BLOCK') {
      for (const tc of (p.tool_calls || [])) {
        const tool = tc.tool || '?';
        blocked_tools[tool] = (blocked_tools[tool] || 0) + 1;
      }
    }
  }

  // Trim blockHistory to last 5 minutes.
  const cutoff = Date.now() / 1000 - 300;
  while (blockHistory.length && blockHistory[0].ts < cutoff) blockHistory.shift();

  els.total.textContent = recent.length;
  els.allow.textContent = decision_counts.ALLOW;
  els.warn.textContent = decision_counts.WARN;
  els.block.textContent = decision_counts.BLOCK;

  // Stream rows.
  if (entries.length && entries[entries.length - 1].seq !== lastSeq) {
    stream.innerHTML = '';
    for (const e of recent.slice(-100).reverse()) {
      const p = e.payload || {};
      const d = (p.decision || '?').toLowerCase();
      const ts = new Date((p.timestamp || e.timestamp) * 1000);
      const tsStr = ts.toLocaleTimeString();
      const reason = (p.reason || '').slice(0, 80);
      const req = (p.request_id || '').slice(0, 12);
      const row = document.createElement('div');
      row.className = 'row';
      row.innerHTML = `
        <span class="ts">${tsStr}</span>
        <span class="dec ${d}">${(p.decision || '?').toUpperCase()}</span>
        <span>${(p.upstream || '?')}/${(p.tool_calls && p.tool_calls[0]?.tool) || 'msg'}</span>
        <span class="reason">${escapeHtml(reason)}</span>
        <span class="req">${escapeHtml(req)}</span>
      `;
      const detailWrap = document.createElement('details');
      detailWrap.innerHTML = `
        <summary>view full decision</summary>
        <pre>${escapeHtml(JSON.stringify(p, null, 2))}</pre>
      `;
      row.appendChild(detailWrap);
      stream.appendChild(row);
    }
    lastSeq = entries[entries.length - 1].seq;
  }

  // Per-layer bars.
  els.layers.innerHTML = '';
  for (const [layer, counts] of Object.entries(layer_counts)) {
    const total = counts.ALLOW + counts.WARN + counts.BLOCK;
    const segs = total === 0 ? '' : `
      <span class="seg allow" style="flex:${counts.ALLOW}"></span>
      <span class="seg warn" style="flex:${counts.WARN}"></span>
      <span class="seg block" style="flex:${counts.BLOCK}"></span>
    `;
    const div = document.createElement('div');
    div.className = 'layer-row';
    div.innerHTML = `
      <span class="name">${escapeHtml(layer)}</span>
      <span class="bar">${segs}</span>
      <span style="width:50px;text-align:right;color:var(--dim);font-family:ui-monospace,Menlo,monospace">${total}</span>
    `;
    els.layers.appendChild(div);
  }

  // Top blocked tools.
  const sorted = Object.entries(blocked_tools).sort((a, b) => b[1] - a[1]).slice(0, 5);
  els.topTools.innerHTML = sorted.length === 0
    ? '<span style="color:var(--dim)">— no blocks yet —</span>'
    : sorted.map(([tool, n]) => `${tool}<span style="float:right;color:var(--dim)">${n}</span>`).join('<br>');

  // Sparkline.
  drawSparkline();
}

function drawSparkline() {
  const W = 200, H = 60;
  els.spark.innerHTML = '';
  if (!blockHistory.length) return;
  const buckets = 30;
  const start = Date.now() / 1000 - 300;
  const interval = 300 / buckets;
  const counts = new Array(buckets).fill(0).map(() => ({ b: 0, n: 0 }));
  for (const e of blockHistory) {
    const i = Math.min(buckets - 1, Math.max(0, Math.floor((e.ts - start) / interval)));
    counts[i].n++;
    if (e.block) counts[i].b++;
  }
  const rates = counts.map(c => c.n ? c.b / c.n : 0);
  const max = Math.max(0.01, ...rates);
  const w = W / (buckets - 1);
  let path = '';
  for (let i = 0; i < buckets; i++) {
    const x = i * w;
    const y = H - (rates[i] / max) * (H - 4) - 2;
    path += (i === 0 ? 'M' : 'L') + x + ',' + y;
  }
  const stroke = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  stroke.setAttribute('d', path);
  stroke.setAttribute('stroke', 'var(--block)');
  stroke.setAttribute('fill', 'none');
  stroke.setAttribute('stroke-width', '1.5');
  els.spark.appendChild(stroke);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

fetchHealth();
poll();
setInterval(fetchHealth, 5000);
setInterval(poll, 1000);
</script>
</body>
</html>
"""


def render_dashboard() -> str:
    return DASHBOARD_HTML
