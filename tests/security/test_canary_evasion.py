"""Security tests: attempts to evade canary detection.

A sophisticated attacker who knows AEGIS exists will try to defeat canary
scanning. These tests probe the limits of the current implementation.
"""

from __future__ import annotations

from aegis.canary import CanaryGarden, redact_canaries


def test_canary_token_appears_in_long_response():
    """Even buried in a long response, the canary is found."""
    g = CanaryGarden.generate(count=2)
    leaked = g.canaries[0].token
    long_text = "lorem ipsum " * 1000 + leaked + " dolor sit amet" * 500
    hits = g.scan(long_text)
    assert len(hits) == 1


def test_canary_with_surrounding_punctuation_is_caught():
    """An attacker might wrap the canary in markdown or punctuation."""
    g = CanaryGarden.generate(count=1)
    t = g.canaries[0].token
    for wrapper in (f"`{t}`", f"({t})", f"<{t}>", f'"{t}"', f"[code]{t}[/code]"):
        hits = g.scan(wrapper)
        assert len(hits) == 1, f"missed canary in {wrapper!r}"


def test_canary_split_with_zero_width_space_caught():
    """Hardening: zero-width characters inserted into the canary token are
    stripped during normalization, so the canary still surfaces."""
    g = CanaryGarden.generate(count=1)
    t = g.canaries[0].token
    # Insert a zero-width space in the middle of the token.
    poisoned = t[:5] + "​" + t[5:]
    hits = g.scan(poisoned)
    assert len(hits) == 1


def test_canary_split_with_rtl_override_caught():
    """RTL override / direction-marking characters are stripped too."""
    g = CanaryGarden.generate(count=1)
    t = g.canaries[0].token
    poisoned = t[:8] + "‮" + t[8:]
    hits = g.scan(poisoned)
    assert len(hits) == 1


def test_canary_split_with_soft_hyphen_caught():
    g = CanaryGarden.generate(count=1)
    t = g.canaries[0].token
    poisoned = t[:10] + "­" + t[10:]
    hits = g.scan(poisoned)
    assert len(hits) == 1


def test_canary_with_nfkc_compatibility_chars_caught():
    """NFKC folds fullwidth digits etc. — but our tokens are pure ASCII so
    this is a no-op for the token itself; the test verifies normalization
    doesn't break legitimate matches."""
    g = CanaryGarden.generate(count=1)
    t = g.canaries[0].token
    hits = g.scan(f"prefix {t} suffix")
    assert len(hits) == 1


def test_recursive_scan_finds_deeply_nested_token():
    """Tool-call params can be deeply nested; canary scan recurses."""
    g = CanaryGarden.generate(count=1)
    leaked = g.canaries[0].token
    payload = {"a": {"b": {"c": [{"d": [{"e": leaked}]}]}}}
    hits = g.scan_structured(payload)
    assert len(hits) == 1
    assert "a.b.c[0].d[0].e" in hits[0].location


def test_canary_in_array_index_zero():
    g = CanaryGarden.generate(count=1)
    leaked = g.canaries[0].token
    hits = g.scan_structured([leaked, "other"])
    assert len(hits) == 1


def test_canary_in_dict_key_caught():
    """Hardening: scan now inspects dict keys too, in case a model echoes
    prompt content into JSON keys."""
    g = CanaryGarden.generate(count=1)
    leaked = g.canaries[0].token
    hits = g.scan_structured({leaked: "value"})
    assert len(hits) >= 1
    assert any("key" in h.location for h in hits)


def test_redact_canaries_replaces_all_per_session_tokens():
    g = CanaryGarden.generate(count=3)
    text = " ".join(c.token for c in g.canaries) + " end"
    redacted = redact_canaries(text, g)
    for c in g.canaries:
        assert c.token not in redacted


def test_canary_count_zero_raises_not_silently_disabled():
    """Misconfiguring count=0 should be loud, not silent."""
    import pytest

    with pytest.raises(ValueError):
        CanaryGarden.generate(count=0)


def test_canary_tokens_random_per_session():
    """Two gardens should never share a token (with overwhelming probability)."""
    g1 = CanaryGarden.generate(count=5)
    g2 = CanaryGarden.generate(count=5)
    s1 = {c.token for c in g1.canaries}
    s2 = {c.token for c in g2.canaries}
    assert s1.isdisjoint(s2)


def test_canary_block_text_matches_directives_format():
    """The injected block uses a recognizable header so debugging is straightforward."""
    g = CanaryGarden.generate(count=2)
    block = g.system_prompt_block()
    assert "AEGIS_INTEGRITY_DIRECTIVES" in block
    assert "END_AEGIS_INTEGRITY_DIRECTIVES" in block


def test_canary_scan_handles_none_and_numeric_payloads():
    g = CanaryGarden.generate(count=1)
    assert g.scan_structured(None) == []
    assert g.scan_structured(42) == []
    assert g.scan_structured(3.14) == []
    assert g.scan_structured(True) == []


def test_canary_token_format_is_distinctive():
    """Token format must be unlikely to appear in legitimate text *and* easy to grep."""
    g = CanaryGarden.generate(count=5)
    for c in g.canaries:
        # Must contain prefix to be greppable.
        assert "AEGIS-CANARY-" in c.token
        # Must not contain whitespace.
        assert " " not in c.token
        assert "\t" not in c.token
        assert "\n" not in c.token
        # Length must be bounded but not tiny.
        assert 20 < len(c.token) < 60
