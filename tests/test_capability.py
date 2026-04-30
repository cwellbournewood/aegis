"""Tests for Capability Tokens."""

from __future__ import annotations

from aegis.capability import (
    CapabilityMinter,
    ProposedCall,
    constraint_eq,
    constraint_in,
    constraint_max_len,
    constraint_prefix,
    constraint_regex,
)


def test_mint_and_validate_happy_path(session):
    minter = CapabilityMinter()
    token = minter.mint(
        tool="send_email",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"to": constraint_eq("alice@example.com")},
    )
    proposed = ProposedCall(tool="send_email", parameters={"to": "alice@example.com", "subject": "hi"})
    verdict = minter.verify(token.raw, session.hmac_key, proposed, expected_session_id=session.session_id)
    assert verdict.valid


def test_tool_mismatch_rejected(session):
    minter = CapabilityMinter()
    token = minter.mint(tool="read_email", session_id=session.session_id, session_key=session.hmac_key)
    proposed = ProposedCall(tool="send_email", parameters={})
    verdict = minter.verify(token.raw, session.hmac_key, proposed, expected_session_id=session.session_id)
    assert not verdict.valid
    assert "tool mismatch" in verdict.reason


def test_signature_mismatch_rejected(session, session_store):
    minter = CapabilityMinter()
    token = minter.mint(tool="x", session_id=session.session_id, session_key=session.hmac_key)
    other = session_store.create()
    proposed = ProposedCall(tool="x", parameters={})
    verdict = minter.verify(token.raw, other.hmac_key, proposed, expected_session_id=session.session_id)
    assert not verdict.valid
    assert "signature" in verdict.reason


def test_session_id_mismatch_rejected(session, session_store):
    minter = CapabilityMinter()
    other = session_store.create()
    token = minter.mint(tool="x", session_id=other.session_id, session_key=other.hmac_key)
    proposed = ProposedCall(tool="x", parameters={})
    verdict = minter.verify(token.raw, other.hmac_key, proposed, expected_session_id=session.session_id)
    assert not verdict.valid
    assert "session_id mismatch" in verdict.reason


def test_expired_token_rejected(session):
    minter = CapabilityMinter()
    token = minter.mint(
        tool="x", session_id=session.session_id, session_key=session.hmac_key, ttl_seconds=-1
    )
    proposed = ProposedCall(tool="x", parameters={})
    verdict = minter.verify(token.raw, session.hmac_key, proposed, expected_session_id=session.session_id)
    assert not verdict.valid
    assert "expired" in verdict.reason


def test_single_use_consumed_then_rejected(session):
    minter = CapabilityMinter()
    token = minter.mint(tool="x", session_id=session.session_id, session_key=session.hmac_key)
    proposed = ProposedCall(tool="x", parameters={})

    first = minter.verify(token.raw, session.hmac_key, proposed, expected_session_id=session.session_id)
    assert first.valid
    minter.consume(first.token)

    second = minter.verify(token.raw, session.hmac_key, proposed, expected_session_id=session.session_id)
    assert not second.valid
    assert "single-use" in second.reason


def test_constraint_eq(session):
    minter = CapabilityMinter()
    token = minter.mint(
        tool="send",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"to": constraint_eq("bob@x.com")},
    )
    good = minter.verify(token.raw, session.hmac_key, ProposedCall("send", {"to": "bob@x.com"}), expected_session_id=session.session_id)
    bad = minter.verify(token.raw, session.hmac_key, ProposedCall("send", {"to": "evil@x.com"}), expected_session_id=session.session_id)
    assert good.valid and not bad.valid


def test_constraint_in_set(session):
    minter = CapabilityMinter()
    token = minter.mint(
        tool="send",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"to": constraint_in(["alice@x.com", "bob@x.com"])},
    )
    good = minter.verify(token.raw, session.hmac_key, ProposedCall("send", {"to": "bob@x.com"}), expected_session_id=session.session_id)
    bad = minter.verify(token.raw, session.hmac_key, ProposedCall("send", {"to": "carol@x.com"}), expected_session_id=session.session_id)
    assert good.valid and not bad.valid


def test_constraint_regex(session):
    minter = CapabilityMinter()
    token = minter.mint(
        tool="send",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"to": constraint_regex(r"[a-z]+@example\.com")},
    )
    good = minter.verify(token.raw, session.hmac_key, ProposedCall("send", {"to": "alice@example.com"}), expected_session_id=session.session_id)
    bad = minter.verify(token.raw, session.hmac_key, ProposedCall("send", {"to": "alice@evil.com"}), expected_session_id=session.session_id)
    assert good.valid and not bad.valid


def test_constraint_prefix(session):
    minter = CapabilityMinter()
    token = minter.mint(
        tool="get",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"path": constraint_prefix("/api/v1/")},
    )
    good = minter.verify(token.raw, session.hmac_key, ProposedCall("get", {"path": "/api/v1/users"}), expected_session_id=session.session_id)
    bad = minter.verify(token.raw, session.hmac_key, ProposedCall("get", {"path": "/internal/admin"}), expected_session_id=session.session_id)
    assert good.valid and not bad.valid


def test_constraint_max_len(session):
    minter = CapabilityMinter()
    token = minter.mint(
        tool="search",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"query": constraint_max_len(10)},
    )
    good = minter.verify(token.raw, session.hmac_key, ProposedCall("search", {"query": "short"}), expected_session_id=session.session_id)
    bad = minter.verify(token.raw, session.hmac_key, ProposedCall("search", {"query": "this is way too long"}), expected_session_id=session.session_id)
    assert good.valid and not bad.valid


def test_missing_param_violates_constraint(session):
    minter = CapabilityMinter()
    token = minter.mint(
        tool="send",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"to": constraint_eq("bob@x.com")},
    )
    verdict = minter.verify(token.raw, session.hmac_key, ProposedCall("send", {}), expected_session_id=session.session_id)
    assert not verdict.valid
    assert "to:missing" in verdict.failed_constraints


def test_malformed_token_rejected(session):
    minter = CapabilityMinter()
    verdict = minter.verify("not-a-real-token", session.hmac_key, ProposedCall("x", {}))
    assert not verdict.valid
    assert "malformed" in verdict.reason


def test_multi_use_token_can_be_used_twice(session):
    minter = CapabilityMinter()
    token = minter.mint(
        tool="x", session_id=session.session_id, session_key=session.hmac_key, single_use=False
    )
    first = minter.verify(token.raw, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id)
    minter.consume(first.token)
    second = minter.verify(token.raw, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id)
    assert first.valid and second.valid
