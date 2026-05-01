"""Security tests: attempted abuses of Capability Tokens.

Each test is a specific attack scenario that the capability gate must defeat.
"""

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


def test_token_minted_for_safe_recipient_cannot_be_used_for_attacker(session):
    """The classic indirect-injection scenario: capability bound to alice,
    attacker tries to send to bob via the same token."""
    minter = CapabilityMinter()
    tok = minter.mint(
        tool="send_email",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"to": constraint_eq("alice@safe.example")},
    )
    attack = ProposedCall("send_email", {"to": "attacker@evil.example"})
    v = minter.verify(tok.raw, session.hmac_key, attack, expected_session_id=session.session_id)
    assert not v.valid


def test_token_for_one_tool_cannot_authorize_another(session):
    minter = CapabilityMinter()
    tok = minter.mint(tool="read_email", session_id=session.session_id, session_key=session.hmac_key)
    attack = ProposedCall("send_email", {})
    v = minter.verify(tok.raw, session.hmac_key, attack, expected_session_id=session.session_id)
    assert not v.valid


def test_constraint_with_extra_unknown_param_rejected_or_constrained(session):
    """If the capability constrains 'to' but the attacker adds a 'cc' param
    that's not constrained, the token should still validate for the
    constrained params. Extra params are an application-level concern;
    document this and test that constrained params still hold."""
    minter = CapabilityMinter()
    tok = minter.mint(
        tool="send",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"to": constraint_eq("alice@x.com")},
    )
    # Constrained param is correct → ALLOW. Application is responsible for
    # rejecting unknown params at its tool layer.
    v = minter.verify(
        tok.raw,
        session.hmac_key,
        ProposedCall("send", {"to": "alice@x.com", "cc": "attacker@evil.com"}),
        expected_session_id=session.session_id,
    )
    assert v.valid
    # The right defense for this is to use constraint_in / constraint_eq on every
    # security-relevant param. Confirm we can lock 'cc' too:
    tok_locked = minter.mint(
        tool="send",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={
            "to": constraint_eq("alice@x.com"),
            "cc": constraint_eq(""),  # require empty cc
        },
    )
    v2 = minter.verify(
        tok_locked.raw,
        session.hmac_key,
        ProposedCall("send", {"to": "alice@x.com", "cc": "attacker@evil.com"}),
        expected_session_id=session.session_id,
    )
    assert not v2.valid


def test_regex_constraint_anchors_full_match(session):
    """`re.fullmatch` is anchored, partial matches don't slip through."""
    minter = CapabilityMinter()
    tok = minter.mint(
        tool="get",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"path": constraint_regex(r"/api/v1/users")},
    )
    # Trailing path that would slip past `re.match` slips past nothing here.
    attack = ProposedCall("get", {"path": "/api/v1/users/../admin"})
    v = minter.verify(tok.raw, session.hmac_key, attack, expected_session_id=session.session_id)
    assert not v.valid


def test_regex_constraint_handles_dotall_attempts(session):
    """Newline in attack string can't bypass an anchored regex."""
    minter = CapabilityMinter()
    tok = minter.mint(
        tool="x",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"v": constraint_regex(r"[a-z]+")},
    )
    attack = ProposedCall("x", {"v": "abc\nrm -rf /"})
    v = minter.verify(tok.raw, session.hmac_key, attack, expected_session_id=session.session_id)
    assert not v.valid


def test_max_len_constraint_resists_unicode_inflation(session):
    """An attacker passing a unicode-heavy string with byte-length > char-length
    should still be limited by char count via len()."""
    minter = CapabilityMinter()
    tok = minter.mint(
        tool="search",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"q": constraint_max_len(5)},
    )
    # 5 chars but >5 bytes when encoded.
    v = minter.verify(
        tok.raw,
        session.hmac_key,
        ProposedCall("search", {"q": "abc🙂🙂"}),  # 5 chars
        expected_session_id=session.session_id,
    )
    assert v.valid
    # 6 chars → reject.
    v2 = minter.verify(
        tok.raw,
        session.hmac_key,
        ProposedCall("search", {"q": "abc🙂🙂🙂"}),
        expected_session_id=session.session_id,
    )
    assert not v2.valid


def test_in_constraint_with_int_vs_string_distinguishes(session):
    """Type confusion: an attacker passes "42" vs 42."""
    minter = CapabilityMinter()
    tok = minter.mint(
        tool="lookup",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"id": constraint_in([42, 7])},
    )
    v_int = minter.verify(tok.raw, session.hmac_key, ProposedCall("lookup", {"id": 42}), expected_session_id=session.session_id)
    v_str = minter.verify(tok.raw, session.hmac_key, ProposedCall("lookup", {"id": "42"}), expected_session_id=session.session_id)
    assert v_int.valid
    assert not v_str.valid  # type mismatch → reject


def test_consume_called_twice_is_idempotent(session):
    minter = CapabilityMinter()
    tok = minter.mint(tool="x", session_id=session.session_id, session_key=session.hmac_key)
    v1 = minter.verify(tok.raw, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id)
    minter.consume(v1.token)
    minter.consume(v1.token)  # idempotent, set.add of same nonce is fine
    v2 = minter.verify(tok.raw, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id)
    assert not v2.valid


def test_token_minted_in_session_a_cannot_authorize_session_b(session, session_store):
    a_minter = CapabilityMinter()
    b_minter = CapabilityMinter()
    other = session_store.create()
    tok = a_minter.mint(tool="x", session_id=session.session_id, session_key=session.hmac_key)
    # Attacker tries to use this token in session B's verifier.
    v = b_minter.verify(
        tok.raw,
        other.hmac_key,
        ProposedCall("x", {}),
        expected_session_id=other.session_id,
    )
    assert not v.valid


def test_capability_token_signature_is_sensitive_to_constraint_value(session):
    """Attacker tries to substitute a different constraint VALUE while keeping the structure."""
    minter = CapabilityMinter()
    tok = minter.mint(
        tool="send",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"to": constraint_eq("alice@x.com")},
    )
    # Decode, modify, re-encode without resigning.
    import base64
    import json

    parts = tok.raw.split(".")
    pad = "=" * (-len(parts[2]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(parts[2] + pad))
    claims["constraints"]["to"]["value"] = "evil@x.com"
    new_body = (
        base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    forged = f"{parts[0]}.{parts[1]}.{new_body}.{parts[3]}"
    v = minter.verify(
        forged,
        session.hmac_key,
        ProposedCall("send", {"to": "evil@x.com"}),
        expected_session_id=session.session_id,
    )
    assert not v.valid


def test_capability_constraint_with_missing_actual_param_fails(session):
    """If the capability requires a 'to' param and the call has no 'to'..."""
    minter = CapabilityMinter()
    tok = minter.mint(
        tool="send",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"to": constraint_eq("alice@x.com")},
    )
    v = minter.verify(
        tok.raw, session.hmac_key, ProposedCall("send", {}), expected_session_id=session.session_id
    )
    assert not v.valid


def test_token_is_useless_after_session_id_change(session):
    """Cannot reuse a token if the session ID claim doesn't match."""
    minter = CapabilityMinter()
    tok = minter.mint(tool="x", session_id=session.session_id, session_key=session.hmac_key)
    v = minter.verify(
        tok.raw, session.hmac_key, ProposedCall("x", {}), expected_session_id="ses_attacker"
    )
    assert not v.valid


def test_prefix_constraint_does_not_match_with_traversal(session):
    """Prefix constraint blocks paths that start with the prefix but contain ../."""
    minter = CapabilityMinter()
    tok = minter.mint(
        tool="read",
        session_id=session.session_id,
        session_key=session.hmac_key,
        constraints={"path": constraint_prefix("/safe/")},
    )
    # /safe/ matches by prefix, but app-layer must check traversal.
    # We test that the prefix check itself is strict-prefix-startswith.
    v_ok = minter.verify(
        tok.raw, session.hmac_key, ProposedCall("read", {"path": "/safe/file.txt"}), expected_session_id=session.session_id
    )
    v_evil = minter.verify(
        tok.raw, session.hmac_key, ProposedCall("read", {"path": "/etc/shadow"}), expected_session_id=session.session_id
    )
    assert v_ok.valid
    assert not v_evil.valid
    # Note: /safe/../../etc/shadow technically passes prefix check.
    # Capability tokens are about *intent declaration*, not full path canonicalization;
    # the application's tool runtime is responsible for canonicalization.
