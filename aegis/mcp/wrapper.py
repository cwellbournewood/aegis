"""MCP stdio wrapper.

MCP messages are JSON-RPC 2.0 over stdio, one JSON object per line. We:

    1. Read messages on our stdin from the agent (Claude Code, Cursor, etc).
    2. Forward them to the wrapped MCP server's stdin.
    3. Read the wrapped server's stdout and inspect each message:
        - tools/list responses: forward unchanged.
        - tools/call responses: scan for canary leaks; if a leak is detected
          and we have a session canary garden, replace the response with an
          MCP error result.
        - everything else: forward unchanged.
    4. Forward sanitized messages back to the agent over our stdout.

The wrapper does NOT need a network round-trip to the AEGIS proxy for canary
scanning, it can use a local `CanaryGarden`. For richer integration (full
five-layer decision per tool call), the wrapper can talk to a configured AEGIS
proxy URL and use its `/aegis/session` + `/aegis/capability` endpoints.

This implementation keeps the dependency surface small: it only needs the
local AEGIS package, no MCP-specific SDK. JSON-RPC framing is simple enough.
"""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from aegis.canary import Canary, CanaryGarden, CanaryHit
from aegis.metrics import metrics

PROXY_CANARY_REFRESH_SECONDS = 5.0


def _emit_log(level: str, msg: str, **fields: Any) -> None:
    """Structured stderr logging, stderr is for the agent's host, not the MCP channel."""
    record = {"ts": time.time(), "level": level, "msg": msg, "src": "aegis-mcp-wrap", **fields}
    print(json.dumps(record, separators=(",", ":")), file=sys.stderr, flush=True)


# Register a wrapper-level metric (will no-op if registry already has it).
try:
    metrics.register_counter(
        "aegis_mcp_messages_total",
        "MCP messages crossed by the wrapper, labeled by direction and method.",
    )
    metrics.register_counter(
        "aegis_mcp_blocks_total",
        "MCP responses replaced with errors by the wrapper, labeled by reason.",
    )
except Exception:
    pass


@dataclass
class MCPWrapperConfig:
    cmd: list[str]
    proxy_url: str | None = None
    policy_mode: str = "balanced"
    canary_count: int = 3
    log_path: str | None = None
    label_l0: bool = True


class MCPWrapper:
    """Synchronous-ish MCP stdio proxy with AEGIS-level inspection.

    Two canary scanning modes:

    * **Standalone** (default): the wrapper carries a per-process CanaryGarden.
      The model never sees these tokens, so the scan can only catch echo-back
      cases (e.g. a downstream MCP server that copies prompt contents into
      responses). Useful for the L0-tagging boundary; weak as a tripwire.

    * **Proxy-integrated** (`--proxy-url`): the wrapper fetches the union of
      canary tokens across all live AEGIS proxy sessions. Those *are* the
      tokens the proxy planted in the LLM's system prompt, so a leak through
      MCP traffic is a real injection signal.
    """

    def __init__(self, config: MCPWrapperConfig) -> None:
        self.config = config
        # Per-process garden. Always present; harmless when proxy garden is also active.
        self.garden = CanaryGarden.generate(count=config.canary_count)
        # Proxy-fetched canary garden. Empty until the first successful refresh.
        self._proxy_garden: CanaryGarden = CanaryGarden(canaries=())
        self._proxy_garden_fetched_at: float = 0.0
        self._proxy_garden_lock = threading.Lock()
        # Single lock around our stdout, both threads may write to the agent.
        self._stdout_lock = threading.Lock()
        self._proc: subprocess.Popen[bytes] | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if not self.config.cmd:
            _emit_log("error", "no MCP command specified")
            sys.exit(2)

        cmd = list(self.config.cmd)
        # On Windows, subprocess.Popen needs the full path including .cmd/.bat
        # for shell-script wrappers like `npx`, `npm`, `yarn`. shutil.which
        # resolves that for us; on Linux/macOS this is a no-op when the bin
        # is already on PATH.
        resolved = shutil.which(cmd[0])
        if resolved is not None:
            cmd[0] = resolved

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,
                bufsize=0,
                env=os.environ.copy(),
            )
        except FileNotFoundError as exc:
            _emit_log("error", f"failed to launch MCP server: {exc}")
            sys.exit(127)

        # Best-effort initial proxy fetch so we don't run blind on the first message.
        if self.config.proxy_url:
            self._refresh_proxy_garden()

        _emit_log(
            "info",
            "wrapper started",
            cmd=" ".join(shlex.quote(c) for c in self.config.cmd),
            policy=self.config.policy_mode,
            canaries_local=len(self.garden.canaries),
            canaries_proxy=len(self._proxy_garden.canaries),
            proxy_url=self.config.proxy_url or "",
        )

        # Forward stdin (agent → server) on one thread; stdout (server → agent)
        # on the main loop so we can inspect each line as it arrives.
        forward_thread = threading.Thread(target=self._forward_in, daemon=True)
        forward_thread.start()

        try:
            self._forward_out()
        finally:
            self.stop()
            forward_thread.join(timeout=2.0)

    def stop(self) -> None:
        self._stop.set()
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.send_signal(signal.SIGTERM)
                self._proc.wait(timeout=2.0)
            except (subprocess.TimeoutExpired, OSError):
                with contextlib.suppress(Exception):
                    self._proc.kill()

    def _write_to_agent(self, payload: bytes) -> bool:
        """Serialize writes to our stdout, both threads can synthesize replies."""
        out = sys.stdout.buffer
        with self._stdout_lock:
            try:
                out.write(payload)
                out.flush()
                return True
            except BrokenPipeError:
                return False

    # ------------------------------------------------------------------ proxy canaries
    def _refresh_proxy_garden(self) -> None:
        """Fetch the union of live-session canaries from `--proxy-url`.

        Cheap, cached for `PROXY_CANARY_REFRESH_SECONDS`. Failures are logged
        and tolerated, the wrapper falls back to whatever it already has.
        """
        proxy_url = self.config.proxy_url
        if not proxy_url:
            return
        with self._proxy_garden_lock:
            now = time.time()
            if now - self._proxy_garden_fetched_at < PROXY_CANARY_REFRESH_SECONDS:
                return
            url = proxy_url.rstrip("/") + "/aegis/canaries/active"
            try:
                with urllib.request.urlopen(url, timeout=2.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                tokens = list(data.get("tokens", []))
                self._proxy_garden = CanaryGarden(
                    canaries=tuple(Canary(token=t, instruction="") for t in tokens)
                )
                self._proxy_garden_fetched_at = now
            except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as exc:
                _emit_log("warn", "proxy canary refresh failed", proxy_url=proxy_url, error=str(exc))
                self._proxy_garden_fetched_at = now  # don't hot-loop on persistent failures

    def _scan_for_canary_leaks(self, payload: object, location: str) -> list[CanaryHit]:
        """Scan `payload` against both the local garden and proxy-fetched tokens."""
        if self.config.proxy_url:
            self._refresh_proxy_garden()
        hits = list(self.garden.scan_structured(payload, location=location))
        if self._proxy_garden.canaries:
            hits.extend(self._proxy_garden.scan_structured(payload, location=location))
        return hits

    # ------------------------------------------------------------------ stdin
    def _forward_in(self) -> None:
        """Read agent messages from our stdin → write to wrapped server stdin.

        Tool-call requests are scanned for canary leaks in their parameters
        before being forwarded. A leak short-circuits the request: a JSON-RPC
        error reply goes back to the agent and the request never reaches the
        wrapped MCP server.
        """
        assert self._proc is not None
        in_stream = sys.stdin.buffer
        out_stream = self._proc.stdin
        if out_stream is None:
            return
        try:
            for line in iter(in_stream.readline, b""):
                if self._stop.is_set():
                    break
                method = "<no-method>"
                msg: dict[str, Any] | None = None
                try:
                    msg = json.loads(line.decode("utf-8", errors="replace"))
                    method = msg.get("method", "") or "<no-method>"
                except (json.JSONDecodeError, UnicodeDecodeError):
                    method = "<unparseable>"
                metrics.counter("aegis_mcp_messages_total").inc(
                    labels={"direction": "agent_to_server", "method": method}
                )

                # Tool-call requests can carry canary leaks in their params.
                if msg is not None and method == "tools/call":
                    params = msg.get("params") or {}
                    hits = self._scan_for_canary_leaks(params, location="mcp:tool_call_params")
                    if hits and self.config.policy_mode != "permissive":
                        self._block_tool_call_request(msg, hits)
                        continue

                try:
                    out_stream.write(line)
                    out_stream.flush()
                except BrokenPipeError:
                    break
        finally:
            if out_stream is not None:
                with contextlib.suppress(Exception):
                    out_stream.close()

    def _block_tool_call_request(self, msg: dict[str, Any], hits: list[CanaryHit]) -> None:
        """Synthesize an error response back to the agent without forwarding."""
        _emit_log(
            "warn",
            "canary leak detected in MCP tool call request, refusing to forward",
            hits=len(hits),
            first_location=hits[0].location,
            tool=(msg.get("params") or {}).get("name"),
        )
        metrics.counter("aegis_mcp_blocks_total").inc(labels={"reason": "canary_leak_request"})
        error_msg = {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "error": {
                "code": -32000,
                "message": "AEGIS: tool call blocked due to canary leak in parameters (model likely hijacked)",
                "data": {
                    "aegis": {
                        "decision": "BLOCK",
                        "reason": "canary leak in tool call request",
                        "hits": len(hits),
                    }
                },
            },
        }
        self._write_to_agent((json.dumps(error_msg, separators=(",", ":")) + "\n").encode("utf-8"))

    # ------------------------------------------------------------------ stdout
    def _forward_out(self) -> None:
        """Read wrapped server stdout → inspect → write to our stdout (the agent)."""
        assert self._proc is not None
        in_stream = self._proc.stdout
        if in_stream is None:
            return
        for line in iter(in_stream.readline, b""):
            if self._stop.is_set():
                break
            sanitized = self._inspect_server_message(line)
            if not self._write_to_agent(sanitized):
                break
        # Server exited.

    # ------------------------------------------------------------------ inspection
    def _inspect_server_message(self, raw: bytes) -> bytes:
        """Parse a single JSON-RPC message from the MCP server. If it's a
        tool/call response, scan it for canary leaks; otherwise pass through.
        Always returns bytes (a JSON object terminated by newline)."""
        try:
            msg = json.loads(raw.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            metrics.counter("aegis_mcp_messages_total").inc(
                labels={"direction": "server_to_agent", "method": "<unparseable>"}
            )
            return raw

        method = msg.get("method", "")
        # In JSON-RPC, server→agent responses are typed by `result`/`error`,
        # not `method`, but tool-call results are typically tagged with the
        # tools/call request id.
        is_tool_call_response = (
            "result" in msg and isinstance(msg["result"], dict) and (
                "content" in msg["result"]  # MCP "tools/call" result shape
                or "toolResult" in msg["result"]
            )
        )

        metrics.counter("aegis_mcp_messages_total").inc(
            labels={"direction": "server_to_agent", "method": method or ("tool_response" if is_tool_call_response else "<other>")}
        )

        if not is_tool_call_response:
            return raw

        # Scan the result content for canary leakage.
        result = msg["result"]
        hits = self._scan_for_canary_leaks(result, location="mcp:tool_result")
        if hits and self.config.policy_mode != "permissive":
            _emit_log(
                "warn",
                "canary leak detected in MCP tool response, replacing with error",
                hits=len(hits),
                first_location=hits[0].location,
            )
            metrics.counter("aegis_mcp_blocks_total").inc(labels={"reason": "canary_leak_response"})
            error_msg = {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "error": {
                    "code": -32000,
                    "message": "AEGIS: tool response blocked due to canary leak (suspected injection upstream)",
                    "data": {
                        "aegis": {
                            "decision": "BLOCK",
                            "reason": "canary leak in tool response",
                            "hits": len(hits),
                        }
                    },
                },
            }
            return (json.dumps(error_msg, separators=(",", ":")) + "\n").encode("utf-8")
        if hits:
            # permissive: log, count, but pass through.
            _emit_log("warn", "canary leak detected (permissive mode, passing through)", hits=len(hits))
            metrics.counter("aegis_mcp_blocks_total").inc(labels={"reason": "canary_leak_response_permissive"})

        # Optionally annotate the response so a downstream AEGIS-proxy-aware
        # client knows the content is L0. Most clients ignore unknown fields.
        if self.config.label_l0 and isinstance(result, dict):
            result.setdefault("_aegis", {})
            result["_aegis"].update({"origin": "tool", "level": "L0", "wrapped_by": "aegis-mcp-wrap"})
            return (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")

        return raw


def run_wrapper(
    cmd: list[str],
    proxy_url: str | None = None,
    policy_mode: str = "balanced",
    canary_count: int = 3,
    log_path: str | None = None,
    label_l0: bool = True,
) -> None:
    """Entry point used by the `aegis mcp-wrap` CLI subcommand."""
    config = MCPWrapperConfig(
        cmd=cmd,
        proxy_url=proxy_url,
        policy_mode=policy_mode,
        canary_count=canary_count,
        log_path=log_path,
        label_l0=label_l0,
    )
    wrapper = MCPWrapper(config)
    try:
        wrapper.start()
    except KeyboardInterrupt:
        wrapper.stop()
