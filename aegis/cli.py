"""AEGIS CLI.

Commands:
    aegis up               start the proxy on host:port
    aegis down             stop a running proxy (PID file or --port fallback)
    aegis logs             tail the decision log
    aegis verify           verify the decision log's hash chain
    aegis policy validate  validate a policy YAML
    aegis policy show      print the effective policy
    aegis bench            run the adversarial corpus benchmark locally
    aegis genkey           generate a hex master key
"""

from __future__ import annotations

import atexit
import contextlib
import json
import os
import secrets
import signal
import subprocess
import sys
import time

import click
from rich.box import ASCII as _BOX_ASCII
from rich.console import Console
from rich.table import Table
from rich.theme import Theme

from aegis import __version__
from aegis.log import iter_log, verify_log
from aegis.policy import Policy, load_policy, load_policy_from_env_or_default, validate_policy
from aegis.session import DEFAULT_KEY_FILENAME

# ============================================================
# AEGIS . Bronze & Obsidian theme for `rich`
# Two plates (bronze + parchment) on obsidian, with one signal.
# Used by every `console.print` call in this module.
# ============================================================
AEGIS_THEME = Theme(
    {
        # Decision verdicts
        "allow":   "bold #9DAA7B",          # laurel-bright
        "warn":    "bold #E8C26C",          # amber-bright
        "block":   "bold #E76F4C",          # cinnabar-bright
        # Brand
        "bronze":  "#B0875A",
        "bronze.bright": "bold #D4A574",
        "bronze.dim":    "#6B5238",
        "parchment": "#F0E5C8",
        "parchment.dim": "#C9BFA4",
        "parchment.mute": "#8C8472",
        # Trust levels (inputs)
        "lvl.L0": "bold #E76F4C",
        "lvl.L1": "bold #E8C26C",
        "lvl.L2": "bold #B0875A",
        "lvl.L3": "bold #9DAA7B",
        # Generic semantic styles
        "title": "bold #F0E5C8",
        "label": "#B0875A",
        "subtle": "#8C8472",
        "ok": "bold #9DAA7B",
        "err": "bold #E76F4C",
        "rule": "#6B5238",
        # rich semantic overrides
        "table.header": "bold #B0875A",
        "table.title":  "italic #C9BFA4",
        "repr.number": "#D4A574",
        "repr.string": "#9DAA7B",
    }
)

console = Console(theme=AEGIS_THEME)


# ============================================================
# ASCII banner — printed on `aegis up`.
# Pure ASCII so it renders in any terminal (Windows cp1252 too).
# Just the AEGIS letterforms + Latin strap + tagline. No shield
# artwork — the CLI banner stays clean and typographic.
# ============================================================
_BANNER = """[bronze.bright]    _    _____  ____  ___  ____  [/bronze.bright]
[bronze.bright]   / \\  | ____|/ ___||_ _|/ ___| [/bronze.bright]
[bronze.bright]  / _ \\ |  _|  | |  _  | | \\___ \\ [/bronze.bright]
[bronze.bright] / ___ \\| |___ | |_| | | |  ___) |[/bronze.bright]
[bronze.bright]/_/   \\_\\_____| \\____||___||____/ [/bronze.bright]

[bronze.dim]---  SCVTVM  .  CONTRA  .  INIECTIONEM  ---[/bronze.dim]
[parchment.mute]Authenticated Execution Gateway  .  v{ver}[/parchment.mute]
"""


def _print_banner() -> None:
    """Print the AEGIS banner to the console."""
    console.print(_BANNER.format(ver=__version__))


@click.group()
@click.version_option(__version__, prog_name="aegis")
def main() -> None:
    """AEGIS. Authenticated Execution Gateway for Injection Security."""


DEFAULT_PID_FILENAME = ".aegis.pid"


def _write_pid_file(path: str = DEFAULT_PID_FILENAME) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
    except OSError:
        pass  # non-fatal, `aegis down` simply won't have a PID hint


def _remove_pid_file(path: str = DEFAULT_PID_FILENAME) -> None:
    with contextlib.suppress(OSError):
        os.unlink(path)


def _read_pid_file(path: str = DEFAULT_PID_FILENAME) -> int | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            r = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=5,
            )
            return f'"{pid}"' in r.stdout
        os.kill(pid, 0)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _kill_pid(pid: int, force: bool = False) -> bool:
    try:
        if os.name == "nt":
            args = ["taskkill", "/PID", str(pid), "/T"]  # /T = terminate child workers too
            if force:
                args.insert(1, "/F")
            r = subprocess.run(args, capture_output=True, text=True, timeout=10)
            return r.returncode == 0
        os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _find_pid_by_port(port: int) -> int | None:
    try:
        if os.name == "nt":
            r = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                # e.g. "  TCP    0.0.0.0:8080  0.0.0.0:0  LISTENING  16388"
                parts = line.split()
                if len(parts) >= 5 and parts[3] == "LISTENING" and parts[1].endswith(f":{port}"):
                    try:
                        return int(parts[4])
                    except ValueError:
                        continue
            return None
        r = subprocess.run(
            ["lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=5,
        )
        out = r.stdout.strip()
        if out:
            return int(out.splitlines()[0])
    except (subprocess.SubprocessError, OSError, ValueError):
        pass
    return None


@main.command("up")
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8080, type=int, show_default=True)
@click.option("--policy", "policy_path", default=None, help="Path to policy YAML.")
@click.option("--reload/--no-reload", default=False, help="Enable auto-reload (development).")
@click.option("--workers", default=1, type=int, show_default=True)
@click.option("--pid-file", default=DEFAULT_PID_FILENAME, show_default=True, help="Where to write the proxy's PID for `aegis down`.")
def up(host: str, port: int, policy_path: str | None, reload: bool, workers: int, pid_file: str) -> None:
    """Start the AEGIS proxy."""
    if policy_path:
        os.environ["AEGIS_POLICY_PATH"] = policy_path

    try:
        import uvicorn
    except ImportError:
        console.print("[err]uvicorn is required.[/err] Install with: [bronze]pip install 'aegis-guard[server]'[/bronze] or [bronze]'uvicorn[standard]'[/bronze].")
        sys.exit(1)

    _print_banner()
    console.print(f"[label]listening[/label]  [bronze.bright]http://{host}:{port}[/bronze.bright]")
    if policy_path:
        console.print(f"[label]policy[/label]     {policy_path}")
    console.print(f"[label]dashboard[/label]  [bronze]http://{host}:{port}/aegis/dashboard[/bronze]")
    if (
        "AEGIS_MASTER_KEY" not in os.environ
        and "AEGIS_MASTER_KEY_FILE" not in os.environ
        and not os.path.exists(DEFAULT_KEY_FILENAME)
    ):
        console.print(
            "[warn]![/warn]  no [bronze]AEGIS_MASTER_KEY[/bronze] set, using ephemeral key. Sessions won't survive restart."
        )
    console.print()

    _write_pid_file(pid_file)
    atexit.register(_remove_pid_file, pid_file)

    uvicorn.run(
        "aegis.proxy.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        workers=workers if not reload else 1,
    )


@main.command("down")
@click.option("--pid-file", default=DEFAULT_PID_FILENAME, show_default=True)
@click.option("--port", default=None, type=int, help="Fallback: kill whatever is listening on this port if no PID file exists.")
@click.option("--force", is_flag=True, help="Skip graceful SIGTERM, terminate immediately.")
@click.option("--timeout", default=5.0, type=float, show_default=True, help="Seconds to wait for graceful shutdown before force-kill.")
def down(pid_file: str, port: int | None, force: bool, timeout: float) -> None:
    """Stop a running AEGIS proxy started with `aegis up`."""
    pid = _read_pid_file(pid_file)
    if pid is not None and not _process_alive(pid):
        _remove_pid_file(pid_file)
        console.print("[subtle]stale pid file removed[/subtle]")
        pid = None

    if pid is None and port is not None:
        pid = _find_pid_by_port(port)
        if pid is not None:
            console.print(f"[subtle]found process on port {port}[/subtle]")

    if pid is None:
        console.print("[subtle]no running AEGIS process found[/subtle]")
        return

    console.print(f"[label]stopping[/label]   pid {pid}{' [warn](force)[/warn]' if force else ''}")
    if not _kill_pid(pid, force=force):
        console.print(f"[err]failed to signal pid {pid}[/err]")
        sys.exit(1)

    if not force:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not _process_alive(pid):
                break
            time.sleep(0.2)
        if _process_alive(pid):
            console.print(f"[warn]still alive after {timeout:.0f}s, forcing[/warn]")
            _kill_pid(pid, force=True)

    _remove_pid_file(pid_file)
    console.print("[ok]stopped[/ok]")


_VERDICT_STYLE = {"ALLOW": "allow", "WARN": "warn", "BLOCK": "block"}


def _render_log_table(entries) -> None:
    if not entries:
        console.print("[subtle]no entries[/subtle]")
        return
    t = Table(show_lines=False, box=_BOX_ASCII, border_style="rule", header_style="table.header")
    t.add_column("#", style="subtle", justify="right")
    t.add_column("decision")
    t.add_column("upstream", style="bronze")
    t.add_column("session", style="subtle")
    t.add_column("request", style="subtle")
    t.add_column("reason", style="parchment.dim")
    for e in entries:
        p = e.payload
        d = str(p.get("decision", "?"))
        style = _VERDICT_STYLE.get(d, "parchment")
        t.add_row(
            str(e.seq),
            f"[{style}]{d}[/{style}]",
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
        console.print(f"[err]Could not reach AEGIS at {url}:[/err] {exc}")
        sys.exit(2)

    t = Table(title=f"AEGIS @ {url}", box=_BOX_ASCII, border_style="rule", header_style="table.header", title_style="table.title")
    t.add_column("field", style="label")
    t.add_column("value", style="parchment")
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
        console.print(f"[err]No log file at {path or '<unset>'}[/err]")
        sys.exit(2)

    target = None
    for entry in iter_log(path):
        if entry.payload.get("request_id") == request_id:
            target = entry
            break
    if target is None:
        console.print(f"[err]No entry with request_id {request_id}[/err]")
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
        console.print(f"[err]No log file at {path or '<unset>'}[/err]")
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
                console.print(f"[err]Invalid --since: {since}[/err]")
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
    console.print(f"\n[subtle]{len(matches)} matching entr{'y' if len(matches) == 1 else 'ies'}.[/subtle]")


@logs_group.command("export")
@click.option("--path", default=None, help="Path to log file (else read policy).")
@click.option("--format", "fmt", default="jsonl", type=click.Choice(["jsonl", "ndjson"]))
def logs_export(path: str | None, fmt: str) -> None:
    """Stream the audit log to stdout in JSONL/NDJSON for SIEM ingest."""
    if path is None:
        policy = load_policy_from_env_or_default()
        path = policy.log_path
    if not path or not os.path.exists(path):
        console.print(f"[err]No log file at {path or '<unset>'}[/err]")
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
        console.print(f"[err]No log file found at {path or '<unset>'}[/err]")
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
    style = _VERDICT_STYLE.get(decision, "parchment")
    console.print()
    console.print(
        f"[label]DECISION[/label]  [{style}]{decision}[/{style}]   "
        f"[subtle]ts={entry.timestamp}[/subtle]"
    )
    console.print(f"[label]REQUEST[/label]   {p.get('request_id', '?')}")
    console.print(f"[label]SESSION[/label]   {p.get('session_id', '?')}")
    console.print(
        f"[label]UPSTREAM[/label]  {p.get('upstream', '?')}    "
        f"[label]MODE[/label] {p.get('mode', '?')}    "
        f"[label]SCORE[/label] {p.get('score', 0)}"
    )
    if p.get("reason"):
        console.print(f"[label]REASON[/label]    {p['reason']}")
    blocked_by = p.get("blocked_by") or []
    if blocked_by:
        console.print(
            f"[label]BLOCKED BY[/label]  [block]{' / '.join(blocked_by).upper()}[/block]"
        )

    votes = p.get("votes") or {}
    if votes:
        vt = Table(
            title="-- Layer Votes --",
            box=_BOX_ASCII,
            border_style="rule",
            header_style="table.header",
            title_style="table.title",
        )
        vt.add_column("layer", style="bronze")
        vt.add_column("verdict")
        vt.add_column("reason", style="parchment.dim")
        vt.add_column("conf", justify="right", style="bronze.dim")
        for layer, vote in votes.items():
            v = str(vote.get("verdict", "?"))
            v_style = _VERDICT_STYLE.get(v, "parchment")
            vt.add_row(
                layer,
                f"[{v_style}]{v}[/{v_style}]",
                str(vote.get("reason", ""))[:80],
                f"{vote.get('confidence', 0):.2f}",
            )
        console.print(vt)

    tool_calls = p.get("tool_calls") or []
    if tool_calls:
        tt = Table(
            title="-- Proposed Tool Calls --",
            box=_BOX_ASCII,
            border_style="rule",
            header_style="table.header",
            title_style="table.title",
        )
        tt.add_column("tool", style="bronze.bright")
        tt.add_column("params (redacted)", style="parchment.mute")
        tt.add_column("summary", style="parchment.dim")
        for tc in tool_calls:
            tt.add_row(
                str(tc.get("tool", "?")),
                ", ".join(tc.get("params_redacted") or tc.get("parameters_redacted") or []),
                str(tc.get("summary") or "")[:80],
            )
        console.print(tt)

    chunks = p.get("input_chunks") or []
    if chunks:
        ct = Table(
            title="-- Input Chunks --",
            box=_BOX_ASCII,
            border_style="rule",
            header_style="table.header",
            title_style="table.title",
        )
        ct.add_column("chunk_id", style="subtle")
        ct.add_column("origin", style="parchment.dim")
        ct.add_column("level")
        for c in chunks:
            level = c.get("level", "")
            ct.add_row(
                str(c.get("chunk_id", ""))[:16],
                str(c.get("origin", "")),
                f"[lvl.{level}]{level}[/lvl.{level}]" if level else "",
            )
        console.print(ct)


@main.command("verify")
@click.argument("log_path", type=click.Path(exists=True))
def verify(log_path: str) -> None:
    """Verify the integrity of a decision log's hash chain."""
    result = verify_log(log_path)
    if result.ok:
        console.print(f"[ok]✓ OK[/ok]  verified [bronze.bright]{result.entries_checked}[/bronze.bright] entries.")
        sys.exit(0)
    else:
        console.print(
            f"[err]✕ FAIL[/err]  chain broken at entry [bronze.bright]{result.broken_at}[/bronze.bright] "
            f"(checked {result.entries_checked}). Reason: {result.reason}"
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
            console.print(f"[err]✕[/err] {err}")
        sys.exit(2)
    console.print(f"[ok]✓[/ok] policy at [bronze.bright]{path}[/bronze.bright] is valid.")
    _print_policy_summary(policy)


@policy_group.command("show")
@click.option("--path", default=None, help="Policy YAML to load (else env / default).")
def policy_show(path: str | None) -> None:
    """Show the effective policy."""
    policy = load_policy(path) if path else load_policy_from_env_or_default()
    _print_policy_summary(policy)


def _print_policy_summary(policy: Policy) -> None:
    t = Table(
        title="-- Effective Policy --",
        box=_BOX_ASCII,
        border_style="rule",
        header_style="table.header",
        title_style="table.title",
    )
    t.add_column("setting", style="label")
    t.add_column("value", style="parchment")
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

    rt = Table(
        title="-- Flow Rules --",
        box=_BOX_ASCII,
        border_style="rule",
        header_style="table.header",
        title_style="table.title",
    )
    rt.add_column("from", style="bronze")
    rt.add_column("to", style="parchment")
    rt.add_column("decision")
    rt.add_column("require", style="parchment.dim")
    rt.add_column("reason", style="subtle")
    for r in policy.rules:
        v_style = _VERDICT_STYLE.get(r.decision.value, "parchment")
        rt.add_row(
            r.from_level.value,
            r.to,
            f"[{v_style}]{r.decision.value}[/{v_style}]",
            ", ".join(r.require) or " ",
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
        console.print(f"[err]Could not reach AEGIS at {url}:[/err] {exc}")
        sys.exit(2)
    console.print(f"[label]Active sessions[/label]  [bronze.bright]{h.get('active_sessions', 0)}[/bronze.bright]")
    console.print(f"[label]Log entries[/label]      [bronze.bright]{h.get('log_entries', 0)}[/bronze.bright]")
    console.print(
        "\n[subtle]Per-session forensics: `aegis logs query --since 1h` "
        "or `aegis logs show <request_id>` for a specific decision.[/subtle]"
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
        console.print(f"[err]Could not reach AEGIS at {url}:[/err] {exc}")
        sys.exit(2)
    if body.status_code == 404:
        console.print(f"[err]No session with id {session_id}[/err]")
        sys.exit(1)
    if body.status_code >= 400:
        console.print(f"[err]Error: {body.status_code} {body.text}[/err]")
        sys.exit(1)

    data = body.json()
    t = Table(
        title=f"-- Session {session_id} --",
        box=_BOX_ASCII,
        border_style="rule",
        header_style="table.header",
        title_style="table.title",
    )
    t.add_column("field", style="label")
    t.add_column("value", style="parchment")
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
            console.print(f"[err]No log file at {path or '<unset>'}[/err]")
            sys.exit(2)
        target = None
        for entry in iter_log(path):
            if entry.payload.get("request_id") == request_id:
                target = entry
                break
        if target is None:
            console.print(f"[err]No entry with request_id {request_id}[/err]")
            sys.exit(1)
        _render_decision_detail(target)
    else:
        # Show what the active policy *would* do at each level.
        policy = load_policy_from_env_or_default()
        _print_policy_summary(policy)
        console.print(
            "\n[subtle]To explain a specific decision: `aegis policy explain --decision-id req_...`[/subtle]"
        )


@main.command(
    "mcp-wrap",
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.option(
    "--proxy-url",
    default=None,
    help=(
        "URL of a running AEGIS proxy. When set, the wrapper polls "
        "/aegis/canaries/active and scans MCP traffic against the same canary "
        "tokens the proxy planted in the LLM's prompts, the only mode in "
        "which canary-leak detection has real security value."
    ),
)
@click.option(
    "--policy",
    "policy_mode",
    default="balanced",
    type=click.Choice(["strict", "balanced", "permissive"]),
    help=(
        "strict / balanced: block on canary leak (default). "
        "permissive: log + count, but pass traffic through unmodified."
    ),
)
@click.option("--canaries", default=3, type=int, show_default=True, help="Number of canary tokens to seed in the per-process garden.")
@click.option("--no-l0-label", is_flag=True, help="Disable adding _aegis metadata to tool responses.")
@click.argument("cmd", nargs=-1, required=True)
def mcp_wrap(proxy_url: str | None, policy_mode: str, canaries: int, no_l0_label: bool, cmd: tuple[str, ...]) -> None:
    """Wrap an MCP server with AEGIS-level inspection.

    Without --proxy-url the wrapper provides L0 boundary tagging and
    structural plumbing for the proxy's lattice gate, but its canary scan can
    only catch echo-back leaks (the LLM never sees the wrapper's tokens).
    Pair with --proxy-url for end-to-end canary leak detection.

    Example:
        aegis mcp-wrap --proxy-url http://localhost:8080 -- npx @modelcontextprotocol/server-github
    """
    from aegis.mcp import run_wrapper

    cmd_list = list(cmd)
    if cmd_list and cmd_list[0] == "--":
        cmd_list = cmd_list[1:]
    if not cmd_list:
        console.print("[err]Specify the MCP command after `--`.[/err]")
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

    table = Table(
        title=f"-- AEGIS Performance . {iterations} iters --",
        box=_BOX_ASCII,
        border_style="rule",
        header_style="table.header",
        title_style="table.title",
    )
    table.add_column("workload", style="bronze")
    table.add_column("p50 ms", justify="right", style="parchment")
    table.add_column("p90 ms", justify="right", style="parchment")
    table.add_column("p99 ms", justify="right", style="parchment")
    table.add_column("mean ms", justify="right", style="parchment.dim")
    table.add_column("max ms", justify="right", style="parchment.dim")

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
        console.print(f"\nThroughput (simple workload, 1 sec): [bronze.bright]{rps:.0f} req/s[/bronze.bright]")


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
    t = Table(
        title=f"-- Adversarial Corpus Benchmark . mode={results.get('mode')} --",
        box=_BOX_ASCII,
        border_style="rule",
        header_style="table.header",
        title_style="table.title",
    )
    t.add_column("category", style="bronze")
    t.add_column("attempts", justify="right", style="parchment.dim")
    t.add_column("blocked", justify="right")
    t.add_column("warned", justify="right")
    t.add_column("allowed", justify="right")
    t.add_column("block rate", justify="right", style="bronze.bright")
    for cat, stats in results["categories"].items():
        rate = (stats["blocked"] / stats["attempts"]) if stats["attempts"] else 0.0
        t.add_row(
            cat,
            str(stats["attempts"]),
            f"[block]{stats['blocked']}[/block]",
            f"[warn]{stats['warned']}[/warn]",
            f"[allow]{stats['allowed']}[/allow]",
            f"{rate:.1%}",
        )
    overall = results["overall"]
    rate = (overall["blocked"] / overall["attempts"]) if overall["attempts"] else 0.0
    t.add_section()
    t.add_row(
        "[title]ALL[/title]",
        f"[title]{overall['attempts']}[/title]",
        f"[block]{overall['blocked']}[/block]",
        f"[warn]{overall['warned']}[/warn]",
        f"[allow]{overall['allowed']}[/allow]",
        f"[bronze.bright]{rate:.1%}[/bronze.bright]",
    )
    console.print(t)


if __name__ == "__main__":
    main()
