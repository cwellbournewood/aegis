"""Tests for the operator dashboard."""

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
        yield c


def test_dashboard_returns_html(client):
    resp = client.get("/aegis/dashboard")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    body = resp.text
    assert "<title>AEGIS" in body
    # Must reference the data endpoints it polls.
    assert "/aegis/decisions" in body
    assert "/aegis/health" in body


def test_dashboard_only_external_resource_is_google_fonts(client):
    """The dashboard's only external dependency is the Google Fonts stylesheet
    that ships Orbitron + JetBrains Mono. Anything else would be a regression."""
    resp = client.get("/aegis/dashboard")
    body = resp.text
    # No external scripts.
    assert "<script src=" not in body.lower()
    # No external CDN imagery / generic CDN domains.
    assert "cdn." not in body.lower()
    assert "cdnjs" not in body.lower()
    assert "unpkg" not in body.lower()
    assert "jsdelivr" not in body.lower()
    # The only allowed external domain.
    import re

    external_urls = re.findall(r'https?://[^"\s]+', body)
    for url in external_urls:
        assert "fonts.googleapis.com" in url or "fonts.gstatic.com" in url, (
            f"unexpected external URL in dashboard: {url}"
        )


def test_dashboard_self_contained_html_under_50kb(client):
    """Sanity: dashboard payload stays small."""
    resp = client.get("/aegis/dashboard")
    assert len(resp.content) < 50_000
