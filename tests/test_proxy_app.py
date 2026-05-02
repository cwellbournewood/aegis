"""Tests for the FastAPI app endpoints (using TestClient + AEGIS_DRY_RUN)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aegis.policy import Policy
from aegis.proxy.app import create_app
from aegis.proxy.orchestrator import Orchestrator


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_DRY_RUN", "1")
    p = Policy.default()
    p.log_path = str(tmp_path / "log.jsonl")
    orch = Orchestrator(policy=p)
    app = create_app(orchestrator=orch)
    with TestClient(app) as c:
        yield c, orch


def test_health(client):
    c, _ = client
    resp = c.get("/aegis/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["policy_mode"] == "balanced"


def test_create_session(client):
    c, _ = client
    resp = c.post("/aegis/session", json={"upstream": "anthropic", "user_intent": "summarize email"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["session_id"].startswith("ses_")
    assert body["canary_count"] >= 1


def test_mint_capability(client):
    c, _ = client
    s = c.post("/aegis/session", json={"upstream": "anthropic", "user_intent": "send mail"}).json()
    resp = c.post(
        "/aegis/capability",
        json={
            "session_id": s["session_id"],
            "tool": "send_email",
            "constraints": {"to": {"kind": "eq", "value": "alice@x.com"}},
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token"].startswith("aegis_cap.")
    assert body["tool"] == "send_email"


def test_mint_capability_invalid_session(client):
    c, _ = client
    resp = c.post("/aegis/capability", json={"session_id": "nope", "tool": "x", "constraints": {}})
    assert resp.status_code == 404


def test_anthropic_dry_run_allows_safe_request(client):
    c, _ = client
    resp = c.post(
        "/v1/anthropic/messages",
        json={
            "model": "claude-sonnet-4-5",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "hello"}],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["aegis"]["decision"] in ("ALLOW", "WARN")


def test_anthropic_route_blocks_canary_leak_via_session_attached_canaries(client, monkeypatch):
    """If we install a synthetic upstream that returns a known canary, the proxy blocks."""
    c, orch = client

    # Pre-create the session and learn its canary tokens.
    sess = orch.get_or_create_session(upstream="anthropic", session_id=None, user_intent="hi")
    leaked_token = sess.canaries.canaries[0].token

    # Monkeypatch the dry-run stub to leak.
    from aegis.proxy import app as app_mod

    def leaking_stub(upstream: str, body: dict):  # type: ignore[no-untyped-def]
        return {
            "id": "msg",
            "type": "message",
            "role": "assistant",
            "model": "x",
            "content": [{"type": "text", "text": f"Sure: {leaked_token}"}],
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
    body = resp.json()
    assert body["aegis"]["decision"] == "BLOCK"


def test_decisions_listing(client):
    c, _ = client
    c.post(
        "/v1/anthropic/messages",
        json={"model": "claude", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 50},
    )
    resp = c.get("/aegis/decisions?limit=5")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 1


def test_session_get_404(client):
    c, _ = client
    resp = c.get("/aegis/session/does-not-exist")
    assert resp.status_code == 404
