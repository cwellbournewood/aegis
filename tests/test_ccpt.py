"""Tests for the CCPT layer."""

from __future__ import annotations

from aegis.ccpt import (
    Level,
    Origin,
    default_level_for,
    derive_child,
    deserialize,
    lowest_level,
    serialize,
    strip,
    tag,
    verify,
)


def test_tag_assigns_default_level(session):
    env = tag("hello", Origin.USER, session.hmac_key, session.session_id)
    assert env.origin == Origin.USER
    assert env.level == Level.L2
    assert env.payload == "hello"
    assert env.session_id == session.session_id
    assert env.sig != ""


def test_tag_round_trip_verifies(session):
    env = tag("hello", Origin.USER, session.hmac_key, session.session_id)
    assert verify(env, session.hmac_key, expected_session_id=session.session_id)


def test_strip_returns_payload(session):
    env = tag("model sees this", Origin.USER, session.hmac_key, session.session_id)
    assert strip(env) == "model sees this"


def test_tampered_payload_fails_verify(session):
    env = tag("hello", Origin.USER, session.hmac_key, session.session_id)
    env.payload = "evil"
    assert not verify(env, session.hmac_key, expected_session_id=session.session_id)


def test_tampered_level_fails_verify(session):
    env = tag("hello", Origin.RETRIEVED, session.hmac_key, session.session_id)
    env.level = Level.L3
    assert not verify(env, session.hmac_key, expected_session_id=session.session_id)


def test_tampered_origin_fails_verify(session):
    env = tag("hello", Origin.RETRIEVED, session.hmac_key, session.session_id)
    env.origin = Origin.SYSTEM
    assert not verify(env, session.hmac_key, expected_session_id=session.session_id)


def test_wrong_session_key_fails_verify(session, session_store):
    env = tag("hello", Origin.USER, session.hmac_key, session.session_id)
    other = session_store.create()
    assert not verify(env, other.hmac_key, expected_session_id=session.session_id)


def test_session_id_mismatch_fails_verify(session, session_store):
    other = session_store.create()
    env = tag("hello", Origin.USER, other.hmac_key, other.session_id)
    assert not verify(env, other.hmac_key, expected_session_id=session.session_id)


def test_default_level_mapping():
    assert default_level_for(Origin.SYSTEM) == Level.L3
    assert default_level_for(Origin.USER) == Level.L2
    assert default_level_for(Origin.RETRIEVED) == Level.L1
    assert default_level_for(Origin.TOOL) == Level.L0
    assert default_level_for(Origin.AGENT) == Level.L1


def test_level_ordering():
    assert Level.L3.rank > Level.L2.rank > Level.L1.rank > Level.L0.rank


def test_serialize_round_trip(session):
    env = tag("payload", Origin.RETRIEVED, session.hmac_key, session.session_id)
    blob = serialize(env)
    assert blob.startswith("ccpt1.")
    parsed = deserialize(blob)
    assert parsed.payload == env.payload
    assert parsed.sig == env.sig
    assert verify(parsed, session.hmac_key, expected_session_id=session.session_id)


def test_lowest_level_picks_minimum(session):
    a = tag("sys", Origin.SYSTEM, session.hmac_key, session.session_id)
    b = tag("usr", Origin.USER, session.hmac_key, session.session_id)
    c = tag("rag", Origin.RETRIEVED, session.hmac_key, session.session_id)
    d = tag("web", Origin.TOOL, session.hmac_key, session.session_id)
    assert lowest_level([a, b, c, d]) == Level.L0
    assert lowest_level([a, b]) == Level.L2
    assert lowest_level([]) == Level.L3


def test_derive_child_inherits_provenance(session):
    parent = tag("untrusted email", Origin.TOOL, session.hmac_key, session.session_id)
    child = derive_child(parent, "summary of email", Origin.AGENT, session.hmac_key)
    # Child level inherits parent's level (L0), taint propagation.
    assert child.level == Level.L0
    assert parent.chunk_id in child.parents
    assert verify(child, session.hmac_key, expected_session_id=session.session_id)


def test_explicit_level_override(session):
    env = tag("system override", Origin.RETRIEVED, session.hmac_key, session.session_id, level=Level.L3)
    assert env.level == Level.L3
    assert verify(env, session.hmac_key, expected_session_id=session.session_id)
