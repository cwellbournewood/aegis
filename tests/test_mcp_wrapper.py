"""Tests for the MCP wrapper.

We don't spawn a real MCP server in tests, instead we drive the wrapper's
inspection logic directly with synthesized JSON-RPC messages.
"""

from __future__ import annotations

import json

from aegis.mcp.wrapper import MCPWrapper, MCPWrapperConfig


def _wrapper(canary_count: int = 2, label_l0: bool = True) -> MCPWrapper:
    return MCPWrapper(MCPWrapperConfig(cmd=["echo"], canary_count=canary_count, label_l0=label_l0))


def _to_bytes(msg: dict) -> bytes:
    return (json.dumps(msg) + "\n").encode("utf-8")


def test_passes_through_non_tool_response():
    w = _wrapper()
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    out = w._inspect_server_message(_to_bytes(msg))
    parsed = json.loads(out.decode("utf-8"))
    # Method messages are forwarded as-is.
    assert parsed.get("method") == "tools/list"


def test_clean_tool_response_passes_with_l0_label_by_default():
    w = _wrapper()
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": "Here is the requested data."}]},
    }
    out = w._inspect_server_message(_to_bytes(msg))
    parsed = json.loads(out.decode("utf-8"))
    # Result is preserved.
    assert parsed["result"]["content"][0]["text"] == "Here is the requested data."
    # AEGIS metadata is annotated.
    assert parsed["result"]["_aegis"]["level"] == "L0"
    assert parsed["result"]["_aegis"]["origin"] == "tool"


def test_canary_leak_replaced_with_jsonrpc_error():
    w = _wrapper()
    leaked_token = w.garden.canaries[0].token
    msg = {
        "jsonrpc": "2.0",
        "id": 7,
        "result": {"content": [{"type": "text", "text": f"Sure: {leaked_token}"}]},
    }
    out = w._inspect_server_message(_to_bytes(msg))
    parsed = json.loads(out.decode("utf-8"))
    assert "error" in parsed
    assert parsed["error"]["code"] == -32000
    assert "BLOCK" in parsed["error"]["data"]["aegis"]["decision"]
    assert parsed["id"] == 7  # id preserved so the agent can correlate


def test_canary_in_nested_tool_result_caught():
    w = _wrapper()
    leaked = w.garden.canaries[0].token
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [
                {"type": "text", "text": "summary"},
                {"type": "resource", "uri": "x://y", "blob": leaked},
            ]
        },
    }
    out = w._inspect_server_message(_to_bytes(msg))
    parsed = json.loads(out.decode("utf-8"))
    assert "error" in parsed


def test_zero_width_split_canary_in_mcp_response_caught():
    """The wrapper inherits canary normalization, split canary tokens are still caught."""
    w = _wrapper()
    t = w.garden.canaries[0].token
    poisoned = t[:6] + "​" + t[6:]  # zero-width space mid-token
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": f"output: {poisoned}"}]},
    }
    out = w._inspect_server_message(_to_bytes(msg))
    parsed = json.loads(out.decode("utf-8"))
    assert "error" in parsed


def test_unparseable_json_passes_through_unchanged():
    w = _wrapper()
    raw = b"this isn't valid json\n"
    out = w._inspect_server_message(raw)
    assert out == raw


def test_label_l0_flag_disables_metadata_injection():
    w = _wrapper(label_l0=False)
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": "clean output"}]},
    }
    out = w._inspect_server_message(_to_bytes(msg))
    parsed = json.loads(out.decode("utf-8"))
    assert "_aegis" not in parsed["result"]


def test_tool_response_with_only_toolresult_field_recognized():
    """Some MCP server impls return `toolResult` instead of `content`."""
    w = _wrapper()
    leaked = w.garden.canaries[0].token
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"toolResult": {"summary": f"output: {leaked}"}},
    }
    out = w._inspect_server_message(_to_bytes(msg))
    parsed = json.loads(out.decode("utf-8"))
    assert "error" in parsed


def test_metrics_incremented_on_block(monkeypatch):
    from aegis.metrics import metrics

    metrics.reset_for_tests()
    w = _wrapper()
    leaked = w.garden.canaries[0].token
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": leaked}]},
    }
    w._inspect_server_message(_to_bytes(msg))
    rendered = metrics.render()
    assert "aegis_mcp_blocks_total" in rendered
    # At least one canary_leak block.
    saw_block = False
    for line in rendered.splitlines():
        if "aegis_mcp_blocks_total{" in line and 'reason="canary_leak"' in line:
            value = float(line.split()[-1])
            saw_block = value >= 1.0
    assert saw_block
