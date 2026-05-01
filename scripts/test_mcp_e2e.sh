#!/usr/bin/env bash
# End-to-end test of `aegis mcp-wrap` against a real MCP server.
# Spawns @modelcontextprotocol/server-everything (the reference server)
# wrapped by `aegis mcp-wrap`, sends a JSON-RPC initialize + tools/list
# request, and prints the wrapped response.
set -euo pipefail

REQ_INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"aegis-test","version":"0.0.1"}}}'
REQ_INITED='{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
REQ_LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

printf '%s\n%s\n%s\n' "$REQ_INIT" "$REQ_INITED" "$REQ_LIST" \
  | python -m aegis.cli mcp-wrap --policy strict --canaries 2 -- \
      npx -y @modelcontextprotocol/server-everything stdio
