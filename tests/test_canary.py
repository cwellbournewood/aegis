"""Tests for the Canary Tripwire layer."""

from __future__ import annotations

import pytest

from aegis.canary import CanaryGarden, redact_canaries


def test_garden_generates_unique_tokens():
    g = CanaryGarden.generate(count=5)
    tokens = [c.token for c in g.canaries]
    assert len(tokens) == len(set(tokens))


def test_default_count_is_three():
    g = CanaryGarden.generate()
    assert len(g.canaries) == 3


def test_system_block_contains_all_tokens():
    g = CanaryGarden.generate(count=4)
    block = g.system_prompt_block()
    for c in g.canaries:
        assert c.token in block


def test_scan_finds_leaked_token():
    g = CanaryGarden.generate(count=2)
    leaked = g.canaries[0].token
    text = f"Sure, here's the data: {leaked} as requested."
    hits = g.scan(text)
    assert len(hits) == 1
    assert hits[0].canary.token == leaked


def test_scan_returns_empty_when_clean():
    g = CanaryGarden.generate(count=2)
    hits = g.scan("perfectly normal model output")
    assert hits == []


def test_scan_structured_walks_dict_and_list():
    g = CanaryGarden.generate(count=1)
    leaked = g.canaries[0].token
    payload = {"to": "bob@x.com", "body": ["hi", f"PS: {leaked}"]}
    hits = g.scan_structured(payload, location="tool:send_email")
    assert len(hits) == 1
    assert "body" in hits[0].location and "[1]" in hits[0].location


def test_scan_handles_non_string_values():
    g = CanaryGarden.generate(count=1)
    payload = {"x": 42, "y": None, "z": [1, 2, 3]}
    hits = g.scan_structured(payload)
    assert hits == []


def test_count_zero_raises():
    with pytest.raises(ValueError):
        CanaryGarden.generate(count=0)


def test_redact_canaries_replaces_tokens():
    g = CanaryGarden.generate(count=2)
    leaked = g.canaries[0].token
    text = f"line1\n{leaked}\nline2"
    redacted = redact_canaries(text, g)
    assert leaked not in redacted
    assert "[REDACTED]" in redacted


def test_token_format_is_distinctive():
    """Tokens must be unlikely to appear in legitimate text."""
    g = CanaryGarden.generate()
    for c in g.canaries:
        assert c.token.startswith("AEGIS-CANARY-")
        # No spaces, mostly hex.
        assert " " not in c.token


def test_per_session_tokens_differ_across_gardens():
    g1 = CanaryGarden.generate()
    g2 = CanaryGarden.generate()
    tokens1 = set(c.token for c in g1.canaries)
    tokens2 = set(c.token for c in g2.canaries)
    assert tokens1 & tokens2 == set()
