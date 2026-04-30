"""Tests for the Decision Engine."""

from __future__ import annotations

from aegis.decision import DecisionEngine, PolicyMode, Verdict, Vote


def _allow(layer: str = "x") -> Vote:
    return Vote(layer=layer, verdict=Verdict.ALLOW, reason="ok")


def _warn(layer: str = "x", reason: str = "soft") -> Vote:
    return Vote(layer=layer, verdict=Verdict.WARN, reason=reason)


def _block(layer: str = "x", reason: str = "hard") -> Vote:
    return Vote(layer=layer, verdict=Verdict.BLOCK, reason=reason)


def test_balanced_block_blocks():
    engine = DecisionEngine(PolicyMode.BALANCED)
    record = engine.combine([_allow(), _block("lattice", "L0 cannot tool")], session_id="s")
    assert record.decision == Verdict.BLOCK
    assert "L0 cannot tool" in record.reason


def test_balanced_warn_passes():
    engine = DecisionEngine(PolicyMode.BALANCED)
    record = engine.combine([_allow(), _warn("intent")], session_id="s")
    assert record.decision == Verdict.WARN


def test_balanced_all_allow_allows():
    engine = DecisionEngine(PolicyMode.BALANCED)
    record = engine.combine([_allow(), _allow(), _allow()], session_id="s")
    assert record.decision == Verdict.ALLOW


def test_strict_two_warns_block():
    engine = DecisionEngine(PolicyMode.STRICT)
    record = engine.combine([_warn("a"), _warn("b"), _allow()], session_id="s")
    assert record.decision == Verdict.BLOCK
    assert "two or more WARNs" in record.reason


def test_strict_one_warn_warns():
    engine = DecisionEngine(PolicyMode.STRICT)
    record = engine.combine([_warn("a"), _allow()], session_id="s")
    assert record.decision == Verdict.WARN


def test_strict_block_dominates():
    engine = DecisionEngine(PolicyMode.STRICT)
    record = engine.combine([_warn("a"), _warn("b"), _block("c")], session_id="s")
    assert record.decision == Verdict.BLOCK


def test_permissive_never_blocks():
    engine = DecisionEngine(PolicyMode.PERMISSIVE)
    record = engine.combine([_block("a"), _block("b")], session_id="s")
    assert record.decision == Verdict.ALLOW
    assert "would BLOCK" in record.reason


def test_request_id_assigned_when_missing():
    engine = DecisionEngine(PolicyMode.BALANCED)
    record = engine.combine([_allow()], session_id="s")
    assert record.request_id.startswith("req_")


def test_score_is_weighted_average():
    engine = DecisionEngine(PolicyMode.BALANCED)
    # Two ALLOW (weight 0) + one BLOCK (weight 1) at confidence 1 each → 0.333
    record = engine.combine([_allow(), _allow(), _block()], session_id="s")
    assert 0.32 < record.score < 0.34


def test_to_dict_serializes_votes():
    engine = DecisionEngine(PolicyMode.BALANCED)
    record = engine.combine([_warn("intent")], session_id="s")
    d = record.to_dict()
    assert d["decision"] == "WARN"
    assert "intent" in d["votes"]


def test_empty_votes_allow():
    engine = DecisionEngine(PolicyMode.BALANCED)
    record = engine.combine([], session_id="s")
    assert record.decision == Verdict.ALLOW
    assert record.score == 0.0
