"""AEGIS Model Context Protocol (MCP) wrapper.

Wraps an MCP server's stdio transport so that AEGIS can:
    1. Tag every tool/response from the wrapped server as L0 (untrusted) when
       it surfaces in the agent's context.
    2. Scan tool responses for canary leaks before forwarding them.
    3. Optionally enforce per-tool capability tokens at the MCP boundary.
    4. Log every cross-boundary message in the AEGIS decision log.

The wrapper is invoked as a subprocess of the agent (e.g., Claude Code):

    aegis mcp-wrap [--proxy-url URL] [--policy MODE] -- <mcp-command> <args...>

It speaks MCP's JSON-RPC-over-stdio on its own stdin/stdout (matching the
agent's expectations) and proxies to the real MCP server it spawned.
"""

from aegis.mcp.wrapper import MCPWrapper, run_wrapper

__all__ = ["MCPWrapper", "run_wrapper"]
