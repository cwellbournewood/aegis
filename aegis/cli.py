"""AEGIS CLI.

Commands:
    aegis up               start the proxy on host:port
    aegis logs             tail the decision log
    aegis verify           verify the decision log's hash chain
    aegis policy validate  validate a policy YAML
    aegis policy show      print the effective policy
    aegis bench            run the adversarial corpus benchmark locally
    aegis genkey           generate a hex master key
"""

from __future__ import annotations

import json
import os
import secrets
import sys

import click
from rich.console import Console
from rich.table import Table

from aegis import __version__
from aegis.log import iter_log, verify_log
from aegis.policy import Policy, load_policy, load_policy_from_env_or_default, validate_policy

console = Console()


@click.group()
@click.version_option(__version__, prog_name="aegis")
def main() -> None:
    """AEGIS — Authenticated Execution Gateway for Injection Security."""


@main.command("up")
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8080, type=int, show_default=True)
@click.option("--policy", "policy_path", default=None, help="Path to policy YAML.")
@click.option("--reload/--no-reload", default=False, help="Enable auto-reload (development).")
@click.option("--workers", default=1, type=int, show_default=True)
def up(host: str, port: int, policy_path: str | None, reload: bool, workers: int) -> None:
    """Start the AEGIS proxy."""
    if policy_path:
        os.environ["AEGIS_POLICY_PATH"] = policy_path

    try:
        import uvicorn
    except ImportError:
        console.print("[red]uvicorn is required. Install with: pip install 'aegis-guard[server]' or 'uvicorn[standard]'.[/red]")
        sys.exit(1)

    console.print(f"[bold green]AEGIS {__version__}[/bold green] starting on [cyan]http://{host}:{port}[/cyan]")
    if policy_path:
        console.print(f"  policy: {policy_path}")
    if "AEGIS_MASTER_KEY" not in os.environ and "AEGIS_MASTER_KEY_FILE" not in os.environ:
        console.print(
            "[yellow]Warning: no AEGIS_MASTER_KEY set — using ephemeral key. Sessions won't survive restart.[/yellow]"
        )

    uvicorn.run(
        "aegis.proxy.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        workers=workers if not reload else 1,
    )


def _render_log_table(entries) -> None:
    if not entries:
        console.print("[dim]no entries[/dim]")
        return
    t = Table(show_lines=False)
    t.add_column("#", style="dim")
    t.add_column("decision")
    t.add_column("upstream")
    t.add_column("session", style="dim")
    t.add_column("request", style="dim")
    t.add_column("reason")
    for e in entries:
        p = e.payload
        d = str(p.get("decision", "?"))
        color = {"ALLOW": "green", "WARN": "yellow", "BLOCK": "red"}.get(d, "white")
        t.add_row(
            str(e.seq),
            f"[{color}]{d}[/{color}]",
            str(p.get("upstream", "?")),
            str(p.get("session_id", ""))[:14],
            str(p.get("request_id", ""))[:14],
            str(p.get("reason", ""))[:80],
        )
    console.print(t)


@main.command("status")
@click.option("--url", default="http://localhost:8080", help="Proxy URL.", show_default=True)
def status(url: str) -> None:
    """Show health, version, uptime, and live counters for a running proxy."""
    import httpx as _httpx

    try:
        h = _httpx.get(f"{url.rstrip('/')}/aegis/health", timeout=5.0).json()
    except Exception as exc:
        console.print(f"[red]Could not reach AEGIS at {url}: {exc}[/red]")
        sys.exit(2)

    t = Table(title=f"AEGIS @ {url}")
    t.add_column("field", style="bold")
    t.add_column("value")
    for k, v in h.items():
        t.add_row(str(k), str(v))
    console.print(t)


@main.group("logs")
def logs_group() -> None:
    """Inspect, query, and tail the decision log."""


@logs_group.command("tail")
@click.option("--path", default=None, help="Path to log file (else read policy).")
@click.option("--n", "tail_n", default=20, type=int, show_default=True)
@click.option("--follow", "-f", is_flag=True, help="Follow the log file.")
@click.option("--json", "as_json", is_flag=True, help="Emit raw JSON lines.")
def logs_tail(path: str | None, tail_n: int, follow: bool, as_json: bool) -> None:
    """Tail recent decisions (alias for the legacy `aegis logs` command)."""
    _logs_tail_impl(path, tail_n, follow, as_json)


@logs_group.command("show")
@click.argument("request_id")
@click.option("--path", default=None, help="Path to log file (else read policy).")
def logs_show(request_id: str, path: str | None) -> None:
    """Show the full formatted detail for a single decision."""
    if path is None:
        policy = load_policy_from_env_or_default()
        path = policy.log_path
    if not path or not os.path.exists(path):
        console.print(f"[red]No log file at {path or '<unset>'}[/red]")
        sys.exit(2)

    target = None
    for entry in iter_log(path):
        if entry.payload.get("request_id") == request_id:
            target = entry
            break
    if target is None:
        console.print(f"[red]No entry with request_id {request_id}[/red]")
        sys.exit(1)

    _render_decision_detail(target)


@logs_group.command("query")
@click.option("--path", default=None, help="Path to log file (else read policy).")
@click.option("--decision", "decision_filter", default=None, type=click.Choice(["ALLOW", "WARN", "BLOCK"]))
@click.option("--upstream", default=None, help="Filter to a specific upstream provider.")
@click.option("--tool", "tool_filter", default=None, help="Filter to entries that proposed a specific tool.")
@click.option("--since", default=None, help="Filter to entries since e.g. '1h', '15m', or an ISO timestamp.")
@click.option("--limit", default=100, type=int, show_default=True)
def logs_query(
    path: str | None,
    decision_filter: str | None,
    upstream: str | None,
    tool_filter: str | None,
    since: str | None,
    limit: int,
) -> None:
    """Filter the decision log by decision, upstream, tool, and time."""
    import re
    import time as _time

    if path is None:
        policy = load_policy_from_env_or_default()
        path = policy.log_path
    if not path or not os.path.exists(path):
        console.print(f"[red]No log file at {path or '<unset>'}[/red]")
        sys.exit(2)

    cutoff: float | None = None
    if since:
        m = re.fullmatch(r"(\d+)([smhd])", since)
        if m:
            n = int(m.group(1))
            unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
            cutoff = _time.time() - n * unit
        else:
            try:
                from datetime import datetime
                cutoff = datetime.fromisoformat(since).timestamp()
            except ValueError:
                console.print(f"[red]Invalid --since: {since}[/red]")
                sys.exit(2)

    matches = []
    for entry in iter_log(path):
        p = entry.payload
        if decision_filter and p.get("decision") != decision_filter:
            continue
        if upstream and p.get("upstream") != upstream:
            continue
        if tool_filter:
            tools = [tc.get("tool") for tc in (p.get("tool_calls") or [])]
            if tool_filter not in tools:
                continue
        if cutoff is not None and float(p.get("timestamp") or entry.timestamp) < cutoff:
            continue
        matches.append(entry)
        if len(matches) >= limit:
            break

    _render_log_table(matches)
    console.print(f"\n[dim]{len(matches)} matching entr{'y' if len(matches) == 1 else 'ies'}.[/dim]")


@logs_group.command("export")
@click.option("--path", default=None, help="Path to log file (else read policy).")
@click.option("--format", "fmt", default="jsonl", type=click.Choice(["jsonl", "ndjson"]))
def logs_export(path: str | None, fmt: str) -> None:
    """Stream the audit log to stdout in JSONL/NDJSON for SIEM ingest."""
    if path is None:
        policy = load_policy_from_env_or_default()
        path = policy.log_path
    if not path or not os.path.exists(path):
        console.print(f"[red]No log file at {path or '<unset>'}[/red]")
        sys.exit(2)

    for entry in iter_log(path):
        click.echo(
            json.dumps(
                {
                    "seq": entry.seq,
                    "ts": entry.timestamp,
                    "prev_hash": entry.prev_hash,
                    "hash": entry.hash,
                    "payload": entry.payload,
                },
                separators=(",", ":"),
                default=str,
            )
        )


def _logs_tail_impl(path: str | None, tail_n: int, follow: bool, as_json: bool) -> None:
    if path is None:
        policy = load_policy_from_env_or_default()
        path = policy.log_path
    if not path or not os.path.exists(path):
        console.print(f"[red]No log file found at {path or '<unset>'}[/red]")
        sys.exit(1)

    entries = list(iter_log(path))
    show = entries[-tail_n:] if tail_n > 0 else entries

    if as_json:
        for e in show:
            click.echo(
                json.dumps({"seq": e.seq, "ts": e.timestamp, "hash": e.hash, "payload": e.payload})
            )
    else:
        _render_log_table(show)

    if follow:
        import time as _time

        last_seq = entries[-1].seq if entries else 0
        try:
            while True:
                _time.sleep(0.5)
                latest = list(iter_log(path))
                new = [e for e in latest if e.seq > last_seq]
                if new:
                    if as_json:
                        for e in new:
                            click.echo(
                                json.dumps({"seq": e.seq, "ts": e.timestamp, "hash": e.hash, "payload": e.payload})
                            )
                    else:
                        _render_log_table(new)
                    last_seq = new[-1].seq
        except KeyboardInterrupt:
            return


def _render_decision_detail(entry) -> None:
    """The drill-down view for a single decision."""
    p = entry.payload
    decision = str(p.get("decision", "?"))
    color = {"ALLOW": "green", "WARN": "yellow", "BLOCK": "red"}.get(decision, "white")
    console.print()
    console.print(f"[bold]DECISION:[/bold] [{color}]{decision}[/{color}]   "
                  f"[dim]ts={entry.timestamp}[/dim]")
    console.print(f"[bold]Request:[/bold]  {p.get('request_id', '?')}")
    console.print(f"[bold]Session:[/bold]  {p.get('session_id', '?')}")
    console.print(f"[bold]Upstream:[/bold] {p.get('upstream', '?')}    "
                  f"[bold]Mode:[/bold] {p.get('mode', '?')}    "
                  f"[bold]Score:[/bold] {p.get('score', 0)}")
    if p.get("reason"):
        console.print(f"[bold]Reason:[/bold]   {p['reason']}")
    blocked_by = p.get("blocked_by") or []
    if blocked_by:
        console.print(f"[bold]Blocked by:[/bold] [red]{', '.join(blocked_by)}[/red]")

    votes = p.get("votes") or {}
    if votes:
        vt = Table(title="Layer Votes")
        vt.add_column("layer")
        vt.add_column("verdict")
        vt.add_column("reason")
        vt.add_column("conf", justify="right")
        for layer, vote in votes.items():
            v = str(vote.get("verdict", "?"))
            color = {"ALLOW": "green", "WARN": "yellow", "BLOCK": "red"}.get(v, "white")
            vt.add_row(
                layer,
                f"[{color}]{v}[/{color}]",
                str(vote.get("reason", ""))[:80],
                f"{vote.get('confidence', 0):.2f}",
            )
        console.print(vt)

    tool_calls = p.get("tool_calls") or []
    if tool_calls:
        tt = Table(title="Proposed Tool Calls")
        tt.add_column("tool")
        tt.add_column("params (redacted)")
        tt.add_column("summary")
        for tc in tool_calls:
            tt.add_row(
                str(tc.get("tool", "?")),
                ", ".join(tc.get("params_redacted") or tc.get("parameters_redacted") or []),
                str(tc.get("summary") or "")[:80],
            )
        console.print(tt)

    chunks = p.get("input_chunks") or []
    if chunks:
        ct = Table(title="Input Chunks")
        ct.add_column("chunk_id")
        ct.add_column("origin")
        ct.add_column("level")
        for c in chunks:
            level = c.get("level", "")
            color = {"L0": "red", "L1": "yellow", "L2": "cyan", "L3": "green"}.get(level, "white")
            ct.add_row(
                str(c.get("chunk_id", ""))[:16],
                str(c.get("origin", "")),
                f"[{color}]{level}[/{color}]",
            )
        console.print(ct)


@main.command("verify")
@click.argument("log_path", type=click.Path(exists=True))
def verify(log_path: str) -> None:
    """Verify the integrity of a decision log's hash chain."""
    result = verify_log(log_path)
    if result.ok:
        console.print(f"[green]OK[/green] — verified {result.entries_checked} entries.")
        sys.exit(0)
    else:
        console.print(
            f"[red]FAIL[/red] — chain broken at entry {result.broken_at} (checked {result.entries_checked}). "
            f"Reason: {result.reason}"
        )
        sys.exit(2)


@main.group("policy")
def policy_group() -> None:
    """Inspect and validate policies."""


@policy_group.command("validate")
@click.argument("path", type=click.Path(exists=True))
def policy_validate(path: str) -> None:
    """Validate a policy YAML file."""
    policy = load_policy(path)
    errors = validate_policy(policy)
    if errors:
        for err in errors:
            console.print(f"[red]✗[/red] {err}")
        sys.exit(2)
    console.print(f"[green]✓[/green] policy at {path} is valid.")
    _print_policy_summary(policy)


@policy_group.command("show")
@click.option("--path", default=None, help="Policy YAML to load (else env / default).")
def policy_show(path: str | None) -> None:
    """Show the effective policy."""
    policy = load_policy(path) if path else load_policy_from_env_or_default()
    _print_policy_summary(policy)


def _print_policy_summary(policy: Policy) -> None:
    t = Table(title="Effective Policy")
    t.add_column("setting", style="bold")
    t.add_column("value")
    t.add_row("mode", policy.mode.value)
    t.add_row("session_ttl", str(policy.session_ttl_seconds) + "s")
    t.add_row("log_path", policy.log_path or "<in-memory>")
    t.add_row("anchor.thresh_balanced", str(policy.anchor.threshold_balanced))
    t.add_row("anchor.thresh_strict", str(policy.anchor.threshold_strict))
    t.add_row("anchor.embedder", str(policy.anchor.embedder))
    t.add_row("canary.enabled", str(policy.canary.enabled))
    t.add_row("canary.count", str(policy.canary.count))
    t.add_row("capability.ttl", str(policy.capability.default_ttl_seconds) + "s")
    console.print(t)

    rt = Table(title="Flow Rules")
    rt.add_column("from")
    rt.add_column("to")
    rt.add_column("decision")
    rt.add_column("require")
    rt.add_column("reason", style="dim")
    for r in policy.rules:
        decision_color = {"ALLOW": "green", "WARN": "yellow", "BLOCK": "red"}.get(r.decision.value, "white")
        rt.add_row(
            r.from_level.value,
            r.to,
            f"[{decision_color}]{r.decision.value}[/{decision_color}]",
            ", ".join(r.require) or "—",
            r.reason or "",
        )
    console.print(rt)


@main.command("genkey")
@click.option("--bytes", "n_bytes", default=32, type=int, show_default=True)
def genkey(n_bytes: int) -> None:
    """Generate a hex-encoded master key for AEGIS_MASTER_KEY."""
    click.echo(secrets.token_bytes(n_bytes).hex())


@main.group("sessions")
def sessions_group() -> None:
    """Inspect active AEGIS sessions."""


@sessions_group.command("list")
@click.option("--url", default="http://localhost:8080", help="Proxy URL.")
def sessions_list(url: str) -> None:
    """List active sessions on a running proxy.

    Note: AEGIS does not expose every session via API by default for privacy
    reasons. This command shows the count from /aegis/health and points
    operators at the decision log for per-session forensics.
    """
    import httpx as _httpx

    try:
        h = _httpx.get(f"{url.rstrip('/')}/aegis/health", timeout=5.0).json()
    except Exception as exc:
        console.print(f"[red]Could not reach AEGIS at {url}: {exc}[/red]")
        sys.exit(2)
    console.print(f"Active sessions: [bold]{h.get('active_sessions', 0)}[/bold]")
    console.print(f"Log entries:     [bold]{h.get('log_entries', 0)}[/bold]")
    console.print(
        "\n[dim]Per-session forensics: `aegis logs query --since 1h` "
        "or `aegis logs show <request_id>` for a specific decision.[/dim]"
    )


@sessions_group.command("show")
@click.argument("session_id")
@click.option("--url", default="http://localhost:8080")
def sessions_show(session_id: str, url: str) -> None:
    """Show one session's metadata."""
    import httpx as _httpx

    try:
        body = _httpx.get(f"{url.rstrip('/')}/aegis/session/{session_id}", timeout=5.0)
    except Exception as exc:
        console.print(f"[red]Could not reach AEGIS at {url}: {exc}[/red]")
        sys.exit(2)
    if body.status_code == 404:
        console.print(f"[red]No session with id {session_id}[/red]")
        sys.exit(1)
    if body.status_code >= 400:
        console.print(f"[red]Error: {body.status_code} {body.text}[/red]")
        sys.exit(1)

    data = body.json()
    t = Table(title=f"Session {session_id}")
    t.add_column("field", style="bold")
    t.add_column("value")
    for k, v in data.items():
        t.add_row(str(k), str(v))
    console.print(t)


@policy_group.command("explain")
@click.option("--decision-id", "request_id", default=None, help="Look up a specific decision in the audit log.")
@click.option("--path", default=None, help="Path to log file.")
def policy_explain(request_id: str | None, path: str | None) -> None:
    """Explain why a request decided the way it did, or show the active policy summary."""
    if request_id:
        if path is None:
            policy = load_policy_from_env_or_default()
            path = policy.log_path
        if not path or not os.path.exists(path):
            console.print(f"[red]No log file at {path or '<unset>'}[/red]")
            sys.exit(2)
        target = None
        for entry in iter_log(path):
            if entry.payload.get("request_id") == request_id:
                target = entry
                break
        if target is None:
            console.print(f"[red]No entry with request_id {request_id}[/red]")
            sys.exit(1)
        _render_decision_detail(target)
    else:
        # Show what the active policy *would* do at each level.
        policy = load_policy_from_env_or_default()
        _print_policy_summary(policy)
        console.print(
            "\n[dim]To explain a specific decision: `aegis policy explain --decision-id req_...`[/dim]"
        )


@main.command(
    "mcp-wrap",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.option("--proxy-url", default=None, help="Optional AEGIS proxy URL for richer integration.")
@click.option("--policy", "policy_mode", default="balanced", type=click.Choice(["strict", "balanced", "permissive"]))
@click.option("--canaries", default=3, type=int, show_default=True, help="Number of canary tokens to seed.")
@click.option("--no-l0-label", is_flag=True, help="Disable adding _aegis metadata to tool responses.")
@click.argument("cmd", nargs=-1, required=True)
def mcp_wrap(proxy_url: str | None, policy_mode: str, canaries: int, no_l0_label: bool, cmd: tuple[str, ...]) -> None:
    """Wrap an MCP server with AEGIS-level inspection.

    Example:
        aegis mcp-wrap --policy strict -- npx @modelcontextprotocol/server-github
    """
    from aegis.mcp import run_wrapper

    cmd_list = list(cmd)
    if cmd_list and cmd_list[0] == "--":
        cmd_list = cmd_list[1:]
    if not cmd_list:
        console.print("[red]Specify the MCP command after `--`.[/red]")
        sys.exit(2)

    run_wrapper(
        cmd=cmd_list,
        proxy_url=proxy_url,
        policy_mode=policy_mode,
        canary_count=canaries,
        label_l0=not no_l0_label,
    )


@main.command("bench-perf")
@click.option("--iterations", default=300, type=int, show_default=True)
@click.option("--workload", default="all", type=click.Choice(["all", "simple", "tool", "tool4", "context"]))
def bench_perf(iterations: int, workload: str) -> None:
    """Measure orchestrator latency and throughput on representative workloads."""
    from tests.perf.harness import (
        build_async_tool_call_workload,
        build_large_context_workload,
        build_simple_text_workload,
        build_tool_call_workload,
        measure_async,
        measure_sync,
        measure_throughput,
    )

    table = Table(title=f"AEGIS Performance ({iterations} iters)")
    table.add_column("workload")
    table.add_column("p50 ms", justify="right")
    table.add_column("p90 ms", justify="right")
    table.add_column("p99 ms", justify="right")
    table.add_column("mean ms", justify="right")
    table.add_column("max ms", justify="right")

    if workload in ("all", "simple"):
        _, run = build_simple_text_workload()
        r = measure_sync(run, iterations=iterations)
        table.add_row("simple text", f"{r.p50_ms:.3f}", f"{r.p90_ms:.3f}", f"{r.p99_ms:.3f}", f"{r.mean_ms:.3f}", f"{r.max_ms:.3f}")

    if workload in ("all", "tool"):
        _, run = build_tool_call_workload(num_tool_calls=1)
        r = measure_sync(run, iterations=iterations)
        table.add_row("1 tool call (sync)", f"{r.p50_ms:.3f}", f"{r.p90_ms:.3f}", f"{r.p99_ms:.3f}", f"{r.mean_ms:.3f}", f"{r.max_ms:.3f}")

    if workload in ("all", "tool4"):
        _, run = build_tool_call_workload(num_tool_calls=4)
        r = measure_sync(run, iterations=iterations)
        table.add_row("4 tool calls (sync)", f"{r.p50_ms:.3f}", f"{r.p90_ms:.3f}", f"{r.p99_ms:.3f}", f"{r.mean_ms:.3f}", f"{r.max_ms:.3f}")

        import asyncio as _a
        _, arun = build_async_tool_call_workload(num_tool_calls=4)
        ar = _a.run(measure_async(arun, iterations=max(iterations // 3, 50)))
        table.add_row("4 tool calls (async)", f"{ar.p50_ms:.3f}", f"{ar.p90_ms:.3f}", f"{ar.p99_ms:.3f}", f"{ar.mean_ms:.3f}", f"{ar.max_ms:.3f}")

    if workload in ("all", "context"):
        _, run = build_large_context_workload(num_messages=50)
        r = measure_sync(run, iterations=max(iterations // 3, 50))
        table.add_row("50-msg context", f"{r.p50_ms:.3f}", f"{r.p90_ms:.3f}", f"{r.p99_ms:.3f}", f"{r.mean_ms:.3f}", f"{r.max_ms:.3f}")

    console.print(table)

    if workload == "all":
        _, run = build_simple_text_workload()
        rps = measure_throughput(run, duration_seconds=1.0)
        console.print(f"\nThroughput (simple workload, 1 sec): [bold cyan]{rps:.0f} req/s[/bold cyan]")


@main.command("bench")
@click.option("--corpus", default=None, help="Path to corpus JSON (else use bundled).")
@click.option("--mode", default="balanced", type=click.Choice(["strict", "balanced", "permissive"]))
def bench(corpus: str | None, mode: str) -> None:
    """Run the adversarial corpus benchmark and report block rate."""
    from aegis.bench import load_corpus, run_benchmark

    cases = load_corpus(corpus)
    results = run_benchmark(cases, mode=mode)
    _render_bench_results(results)


def _render_bench_results(results: dict) -> None:
    t = Table(title=f"Adversarial Corpus Benchmark (mode={results.get('mode')})")
    t.add_column("category")
    t.add_column("attempts", justify="right")
    t.add_column("blocked", justify="right")
    t.add_column("warned", justify="right")
    t.add_column("allowed", justify="right")
    t.add_column("block rate", justify="right")
    for cat, stats in results["categories"].items():
        rate = (stats["blocked"] / stats["attempts"]) if stats["attempts"] else 0.0
        t.add_row(
            cat,
            str(stats["attempts"]),
            f"[red]{stats['blocked']}[/red]",
            f"[yellow]{stats['warned']}[/yellow]",
            f"[green]{stats['allowed']}[/green]",
            f"{rate:.1%}",
        )
    overall = results["overall"]
    rate = (overall["blocked"] / overall["attempts"]) if overall["attempts"] else 0.0
    t.add_section()
    t.add_row(
        "[bold]ALL[/bold]",
        f"[bold]{overall['attempts']}[/bold]",
        f"[bold red]{overall['blocked']}[/bold red]",
        f"[bold yellow]{overall['warned']}[/bold yellow]",
        f"[bold green]{overall['allowed']}[/bold green]",
        f"[bold]{rate:.1%}[/bold]",
    )
    console.print(t)


if __name__ == "__main__":
    main()
