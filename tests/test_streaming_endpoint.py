"""Integration tests for the streaming HTTP endpoint."""

from __future__ import annotations

import json

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
        yield c


def _parse_sse(text: str) -> list[dict]:
    """Trivial SSE parser for tests."""
    events = []
    current = {}
    for line in text.splitlines():
        if line == "":
            if current:
                events.append(current)
                current = {}
            continue
        if line.startswith("data:"):
            try:
                current["data"] = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                current["raw_data"] = line[5:].strip()
        elif line.startswith("event:"):
            current["event"] = line[6:].strip()
    if current:
        events.append(current)
    return events


def test_streaming_endpoint_emits_chunks_and_done(client):
    resp = client.post(
        "/v1/anthropic/messages/stream",
        json={
            "model": "claude",
            "max_tokens": 50,
            "messages": [{"role": "user", "content": "hello"}],
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")

    events = _parse_sse(resp.text)
    # Should have at least one text chunk and a done event.
    text_chunks = [e for e in events if "data" in e and "text" in e["data"]]
    done_events = [e for e in events if e.get("event") == "aegis_done"]
    assert len(text_chunks) >= 1
    assert len(done_events) == 1
    assert done_events[0]["data"]["aegis"]["decision"] in ("ALLOW", "WARN")


def test_streaming_endpoint_stream_param_optional(client):
    """Even without explicit `stream: true`, the streaming endpoint streams."""
    resp = client.post(
        "/v1/anthropic/messages/stream",
        json={"messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]


def test_streaming_endpoint_invalid_body_400(client):
    resp = client.post(
        "/v1/anthropic/messages/stream",
        content=b"not json",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 400
