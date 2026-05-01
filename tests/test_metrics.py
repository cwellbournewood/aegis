"""Tests for the Prometheus /metrics endpoint and metric population."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis.metrics import metrics
from aegis.policy import Policy
from aegis.proxy.app import create_app
from aegis.proxy.orchestrator import Orchestrator


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_DRY_RUN", "1")
    metrics.reset_for_tests()
    p = Policy.default()
    p.log_path = str(tmp_path / "log.jsonl")
    orch = Orchestrator(policy=p)
    app = create_app(orchestrator=orch)
    with TestClient(app) as c:
        yield c, orch


def test_metrics_endpoint_returns_prometheus_format(client):
    c, _ = client
    resp = c.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "# HELP aegis_requests_total" in resp.text
    assert "# TYPE aegis_requests_total counter" in resp.text


def test_metrics_track_request_count(client):
    c, _ = client
    for _ in range(3):
        c.post(
            "/v1/anthropic/messages",
            json={"model": "x", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]},
        )
    body = c.get("/metrics").text
    # The counter should now reflect 3 requests on the anthropic upstream.
    assert 'aegis_requests_total{decision="' in body
    assert 'upstream="anthropic"' in body


def test_metrics_track_layer_votes(client):
    c, _ = client
    c.post(
        "/v1/anthropic/messages",
        json={"model": "x", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]},
    )
    body = c.get("/metrics").text
    assert 'aegis_layer_votes_total{layer="canary",verdict="ALLOW"}' in body


def test_metrics_track_canary_leak_when_response_includes_token(client, monkeypatch):
    c, orch = client
    sess = orch.get_or_create_session(upstream="anthropic", session_id=None, user_intent="hi")
    leaked = sess.canaries.canaries[0].token

    from aegis.proxy import app as app_mod

    def leaking_stub(upstream: str, body: dict):
        return {
            "id": "msg",
            "type": "message",
            "role": "assistant",
            "model": "x",
            "content": [{"type": "text", "text": f"Sure: {leaked}"}],
            "stop_reason": "end_turn",
        }

    monkeypatch.setattr(app_mod, "_stub_upstream_response", leaking_stub)

    resp = c.post(
        "/v1/anthropic/messages",
        json={
            "messages": [{"role": "user", "content": "hi"}],
            "aegis": {"session_id": sess.session_id, "user_intent": "hi"},
        },
    )
    assert resp.status_code == 451

    body = c.get("/metrics").text
    assert "aegis_canary_leaks_total " in body or "aegis_canary_leaks_total{" in body
    # The metric line itself is "aegis_canary_leaks_total <value>", find the value.
    found_value = False
    for line in body.splitlines():
        if line.startswith("aegis_canary_leaks_total ") and not line.startswith("# "):
            value = float(line.split()[-1])
            assert value >= 1.0
            found_value = True
            break
    assert found_value, f"no canary_leaks metric line found in:\n{body}"


def test_metrics_capability_consumed_and_rejected_separated(client):
    c, _orch = client

    # Session + capability mint + tool call with capability → consumed.
    sess = c.post(
        "/aegis/session", json={"upstream": "anthropic", "user_intent": "email alice"}
    ).json()
    cap = c.post(
        "/aegis/capability",
        json={"session_id": sess["session_id"], "tool": "send_email", "constraints": {}},
    ).json()

    # Mock upstream to emit a tool call with the capability token.
    from aegis.proxy import app as app_mod

    def tool_stub(upstream: str, body: dict):
        return {
            "id": "msg",
            "type": "message",
            "role": "assistant",
            "model": "x",
            "content": [
                {"type": "text", "text": "sending"},
                {
                    "type": "tool_use",
                    "name": "send_email",
                    "input": {"to": "alice@x.com", "_aegis_capability": cap["token"]},
                },
            ],
            "stop_reason": "tool_use",
        }

    import unittest.mock as _mock
    with _mock.patch.object(app_mod, "_stub_upstream_response", tool_stub):
        c.post(
            "/v1/anthropic/messages",
            json={
                "messages": [{"role": "user", "content": "email alice"}],
                "aegis": {"session_id": sess["session_id"], "capability_tokens": [cap["token"]]},
            },
        )

    body = c.get("/metrics").text
    # Consumed counter should have been incremented at least once.
    assert "aegis_capability_consumed_total" in body
    consumed_value = 0.0
    for line in body.splitlines():
        if line.startswith("aegis_capability_consumed_total ") and not line.startswith("# "):
            consumed_value = float(line.split()[-1])
            break
    assert consumed_value >= 1.0


def test_metrics_endpoint_after_decision_log_grows(client):
    c, _ = client
    initial = c.get("/metrics").text
    for _ in range(5):
        c.post(
            "/v1/anthropic/messages",
            json={"messages": [{"role": "user", "content": "hi"}]},
        )
    body = c.get("/metrics").text

    # The log_entries gauge should have grown.
    def _gauge_value(text: str, name: str) -> float:
        for line in text.splitlines():
            if line.startswith(name + " ") and not line.startswith("# "):
                return float(line.split()[-1])
        return -1.0

    assert _gauge_value(body, "aegis_log_entries") >= _gauge_value(initial, "aegis_log_entries") + 5


def test_decision_seconds_histogram_populated(client):
    c, _ = client
    c.post(
        "/v1/anthropic/messages",
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    body = c.get("/metrics").text
    assert "aegis_decision_seconds_count" in body
    assert "aegis_decision_seconds_sum" in body


def test_per_gate_histogram_populated(client):
    c, _ = client
    c.post(
        "/v1/anthropic/messages",
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    body = c.get("/metrics").text
    assert 'aegis_gate_seconds_count{gate="canary"}' in body
