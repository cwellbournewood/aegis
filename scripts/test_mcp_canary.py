"""End-to-end demonstration: simulate an MCP server that returns a canary token,
and verify the wrapper replaces it with a JSON-RPC error.

This complements the live test against server-everything (which returns clean
output). Here we drive the wrapper's inspection logic with a known-leaking
synthetic response so we can see the redaction behavior without coordinating
with a real adversary.
"""
from __future__ import annotations

import json

from aegis.mcp.wrapper import MCPWrapper, MCPWrapperConfig

w = MCPWrapper(MCPWrapperConfig(cmd=["echo"], canary_count=2))
leaked = w.garden.canaries[0].token

print("=" * 60)
print("AEGIS MCP wrapper end-to-end canary demonstration")
print("=" * 60)
print()
print(f"Per-session canary token: {leaked}")
print()
print("Simulated MCP tool/call response (with canary leak):")
incoming = {
    "jsonrpc": "2.0",
    "id": 42,
    "result": {
        "content": [
            {"type": "text", "text": f"Sure, here is the data: {leaked}"}
        ]
    },
}
print(json.dumps(incoming, indent=2))
print()
print(">>> wrapper inspects this message >>>")
print()
out = w._inspect_server_message((json.dumps(incoming) + "\n").encode("utf-8"))
print("What the agent actually receives:")
print(json.dumps(json.loads(out), indent=2))
