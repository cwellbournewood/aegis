"""Tests for the typed SDK decision objects."""

from __future__ import annotations

import pytest

from aegis.sdk import (
    AegisDecision,
    AegisDecisionBlocked,
    AegisVote,
    attach_decision,
)


def _allow_response() -> dict:
    return {
        "id": "msg_x",
        "content": [{"type": "text", "text": "hello"}],
        "aegis": {
            "decision": "ALLOW",
            "request_id": "req_abc",
            "session_id": "ses_xyz",
            "score": 0.0,
            "mode": "balanced",
            "reason": "all gates ALLOW",
            "votes": {
                "ccpt_verify": {"verdict": "ALLOW", "reason": "all envelopes signed", "confidence": 1.0},
                "canary": {"verdict": "ALLOW", "reason": "no canary leakage", "confidence": 1.0},
            },
        },
    }


def _block_payload() -> dict:
    return {
        "error": {
            "type": "aegis_blocked",
            "message": "L0 cannot authorize tool calls",
            "request_id": "req_block",
            "session_id": "ses_xyz",
        },
        "aegis": {
            "decision": "BLOCK",
            "request_id": "req_block",
            "session_id": "ses_xyz",
            "score": 0.78,
            "mode": "balanced",
            "reason": "L0 cannot authorize tool calls",
            "blocked_by": ["lattice", "capability", "intent_drift"],
            "votes": {
                "lattice": {"verdict": "BLOCK", "reason": "L0 origin"},
                "capability": {"verdict": "BLOCK", "reason": "no capability token presented for tool=set_email_forwarding"},
                "intent_drift": {"verdict": "BLOCK", "reason": "intent drift: similarity=0.18 < threshold=0.30"},
                "ccpt_verify": {"verdict": "ALLOW", "reason": "all envelopes signed"},
                "canary": {"verdict": "ALLOW", "reason": "no canary leakage"},
            },
        },
    }


def test_decision_from_response_dict_allow():
    d = AegisDecision.from_response(_allow_response())
    assert d is not None
    assert d.decision == "ALLOW"
    assert d.request_id == "req_abc"
    assert "ccpt_verify" in d.votes
    assert d.votes["ccpt_verify"].verdict == "ALLOW"
    assert d.blocked_by == ()
    assert d.warnings == ()


def test_decision_from_response_returns_none_for_no_aegis_field():
    body = {"id": "msg_x", "content": [{"type": "text", "text": "hi"}]}
    assert AegisDecision.from_response(body) is None


def test_decision_iterates_votes():
    d = AegisDecision.from_response(_allow_response())
    layers = [v.layer for v in d]
    assert layers == ["ccpt_verify", "canary"]


def test_decision_pretty_renders_marks_for_each_verdict():
    d = AegisDecision.from_response(_allow_response())
    text = d.pretty()
    assert "AegisDecision(ALLOW" in text
    assert "ccpt_verify" in text


def test_warnings_extracted_from_warn_votes():
    body = _allow_response()
    body["aegis"]["votes"]["intent_drift"] = {
        "verdict": "WARN",
        "reason": "drift below balanced threshold",
        "confidence": 0.5,
    }
    d = AegisDecision.from_response(body)
    assert len(d.warnings) == 1
    assert d.warnings[0].layer == "intent_drift"
    assert "balanced" in d.warnings[0].message


def test_decision_blocked_from_http_error():
    err = AegisDecisionBlocked.from_http_error(_block_payload())
    assert err.decision.decision == "BLOCK"
    assert err.decision.request_id == "req_block"
    assert "lattice" in err.blocked_by
    assert "capability" in err.blocked_by
    assert "intent_drift" in err.blocked_by

    msg = str(err)
    # The pretty form names every blocking layer + suggested_fix.
    assert "lattice" in msg
    assert "capability" in msg
    assert "intent_drift" in msg
    assert "Suggested fix" in msg
    # The fix text mentions session.capabilities.mint for the capability layer.
    assert "session.capabilities.mint" in err.suggested_fix


def test_decision_blocked_with_no_layer_specific_fix():
    err = AegisDecisionBlocked.from_http_error({"error": {"message": "blocked"}, "aegis": {}})
    # Even with no votes, exception still constructs.
    assert err.decision.decision == "BLOCK"


def test_attach_decision_sets_attribute_on_dict_subclass():
    """If the response object accepts attribute assignment, attach_decision sets it."""

    class Bag(dict):
        pass

    body = Bag(_allow_response())
    decision = attach_decision(body)
    assert decision is not None
    assert body.aegis is decision  # type: ignore[attr-defined]


def test_attach_decision_returns_none_when_no_aegis():
    body = {"id": "x"}
    assert attach_decision(body) is None


def test_aegis_vote_is_immutable():
    """Frozen dataclasses raise FrozenInstanceError on field mutation."""
    from dataclasses import FrozenInstanceError

    v = AegisVote(layer="x", verdict="ALLOW", reason="ok")
    with pytest.raises(FrozenInstanceError):
        v.layer = "y"  # type: ignore[misc]
