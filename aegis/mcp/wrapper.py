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
from dataclasses import dataclass
from typing import Any

from aegis.canary import CanaryGarden
from aegis.metrics import metrics


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
    """Synchronous-ish MCP stdio proxy with AEGIS-level inspection."""

    def __init__(self, config: MCPWrapperConfig) -> None:
        self.config = config
        # The wrapper holds a single canary garden for the lifetime of the wrap.
        # If integrating with the proxy, we'd ideally use the agent's session
        # canaries; for now we maintain our own, scoped to this MCP server.
        self.garden = CanaryGarden.generate(count=config.canary_count)
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

        _emit_log(
            "info",
            "wrapper started",
            cmd=" ".join(shlex.quote(c) for c in self.config.cmd),
            policy=self.config.policy_mode,
            canaries=len(self.garden.canaries),
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

    # ------------------------------------------------------------------ stdin
    def _forward_in(self) -> None:
        """Read agent messages from our stdin → write to wrapped server stdin."""
        assert self._proc is not None
        in_stream = sys.stdin.buffer
        out_stream = self._proc.stdin
        if out_stream is None:
            return
        try:
            for line in iter(in_stream.readline, b""):
                if self._stop.is_set():
                    break
                try:
                    msg = json.loads(line.decode("utf-8", errors="replace"))
                    method = msg.get("method", "")
                    metrics.counter("aegis_mcp_messages_total").inc(
                        labels={"direction": "agent_to_server", "method": method or "<no-method>"}
                    )
                except (json.JSONDecodeError, UnicodeDecodeError):
                    metrics.counter("aegis_mcp_messages_total").inc(
                        labels={"direction": "agent_to_server", "method": "<unparseable>"}
                    )
                try:
                    out_stream.write(line)
                    out_stream.flush()
                except BrokenPipeError:
                    break
        finally:
            if out_stream is not None:
                with contextlib.suppress(Exception):
                    out_stream.close()

    # ------------------------------------------------------------------ stdout
    def _forward_out(self) -> None:
        """Read wrapped server stdout → inspect → write to our stdout (the agent)."""
        assert self._proc is not None
        in_stream = self._proc.stdout
        out_stream = sys.stdout.buffer
        if in_stream is None:
            return
        for line in iter(in_stream.readline, b""):
            if self._stop.is_set():
                break
            sanitized = self._inspect_server_message(line)
            try:
                out_stream.write(sanitized)
                out_stream.flush()
            except BrokenPipeError:
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
        hits = self.garden.scan_structured(result, location="mcp:tool_result")
        if hits:
            _emit_log(
                "warn",
                "canary leak detected in MCP tool response, replacing with error",
                hits=len(hits),
                first_location=hits[0].location,
            )
            metrics.counter("aegis_mcp_blocks_total").inc(labels={"reason": "canary_leak"})
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
