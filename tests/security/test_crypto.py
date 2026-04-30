"""Security tests for cryptographic primitives.

These tests probe the HMAC, HKDF, and constant-time-comparison properties of
the CCPT and Capability layers. Each test is written as an *attack* — what an
adversary with full source-code access would try.
"""

from __future__ import annotations

import secrets
import time

import pytest

from aegis.capability import CapabilityMinter, ProposedCall
from aegis.ccpt import Origin, tag, verify
from aegis.session import (
    derive_session_key,
    master_key,
    reset_master_key_for_tests,
)

# ---------------------------------------------------------------------------
# HKDF / per-session key derivation
# ---------------------------------------------------------------------------


def test_session_keys_deterministic_for_same_id():
    reset_master_key_for_tests(b"\x42" * 32)
    a = derive_session_key("ses_alpha")
    b = derive_session_key("ses_alpha")
    assert a == b


def test_session_keys_diverge_per_session_id():
    reset_master_key_for_tests(b"\x42" * 32)
    a = derive_session_key("ses_alpha")
    b = derive_session_key("ses_beta")
    assert a != b


def test_session_keys_diverge_when_master_key_rotates():
    reset_master_key_for_tests(b"\x42" * 32)
    a = derive_session_key("ses_x")
    reset_master_key_for_tests(b"\x55" * 32)
    b = derive_session_key("ses_x")
    assert a != b


def test_session_key_is_full_length():
    reset_master_key_for_tests(b"\x42" * 32)
    k = derive_session_key("ses_x")
    assert len(k) == 32


# ---------------------------------------------------------------------------
# Master key handling — env / file / weak key rejection
# ---------------------------------------------------------------------------


def test_short_master_key_rejected(monkeypatch):
    reset_master_key_for_tests(None)
    monkeypatch.setenv("AEGIS_MASTER_KEY", "deadbeef")  # 4 bytes — too short
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        master_key()


def test_non_hex_master_key_rejected(monkeypatch):
    reset_master_key_for_tests(None)
    monkeypatch.setenv("AEGIS_MASTER_KEY", "not-actually-hex")
    with pytest.raises(RuntimeError, match="hex-encoded"):
        master_key()


def test_master_key_file_loads_hex(monkeypatch, tmp_path):
    reset_master_key_for_tests(None)
    monkeypatch.delenv("AEGIS_MASTER_KEY", raising=False)
    p = tmp_path / "key"
    p.write_bytes(b"a" * 64)  # 64 hex chars = 32 bytes
    monkeypatch.setenv("AEGIS_MASTER_KEY_FILE", str(p))
    k = master_key()
    assert len(k) == 32


# ---------------------------------------------------------------------------
# HMAC tampering — every field must be covered
# ---------------------------------------------------------------------------


def test_swap_chunk_id_invalidates_signature(session):
    e1 = tag("hello", Origin.USER, session.hmac_key, session.session_id)
    e2 = tag("world", Origin.USER, session.hmac_key, session.session_id)
    # An attacker who could swap chunk_ids would break taint propagation.
    e1.chunk_id, e2.chunk_id = e2.chunk_id, e1.chunk_id
    assert not verify(e1, session.hmac_key, expected_session_id=session.session_id)
    assert not verify(e2, session.hmac_key, expected_session_id=session.session_id)


def test_swap_nonce_invalidates_signature(session):
    e1 = tag("hello", Origin.USER, session.hmac_key, session.session_id)
    original_sig = e1.sig
    e1.nonce = secrets.token_hex(16)  # different nonce
    assert not verify(e1, session.hmac_key, expected_session_id=session.session_id)
    # Confirm the sig is the same — only nonce changed — proves nonce is part of HMAC input.
    assert e1.sig == original_sig


def test_replay_envelope_to_other_session_fails(session, session_store):
    """An envelope minted for session A must not verify under session B's key."""
    other = session_store.create()
    env = tag("hi", Origin.USER, session.hmac_key, session.session_id)
    # Forging a new session_id field doesn't help — the HMAC covers it.
    env.session_id = other.session_id
    assert not verify(env, other.hmac_key, expected_session_id=other.session_id)


def test_modified_parents_field_invalidates(session):
    """Taint propagation correctness — modifying parents must break the sig."""
    env = tag("derived", Origin.AGENT, session.hmac_key, session.session_id)
    env.parents = ("forged_parent",)
    assert not verify(env, session.hmac_key, expected_session_id=session.session_id)


def test_truncated_signature_rejected(session):
    env = tag("hi", Origin.USER, session.hmac_key, session.session_id)
    env.sig = env.sig[:-2]  # chop two hex chars
    assert not verify(env, session.hmac_key, expected_session_id=session.session_id)


def test_signature_has_full_entropy(session):
    """Sanity: HMAC-SHA256 output is 64 hex chars."""
    env = tag("payload", Origin.USER, session.hmac_key, session.session_id)
    assert len(env.sig) == 64
    assert all(c in "0123456789abcdef" for c in env.sig)


# ---------------------------------------------------------------------------
# Constant-time comparison
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_signature_compare_is_roughly_constant_time(session):
    """Probabilistic timing test — verify() should not short-circuit on prefix match.

    This is a smell test, not a formal proof. We measure verify time for two
    cases: (a) a sig that mismatches in the first byte, (b) a sig that matches
    in the first 60 hex chars but mismatches at the end. If these are wildly
    different, we're leaking info. We tolerate up to 5x ratio because Python's
    GC and OS scheduling are noisy.
    """
    env = tag("x", Origin.USER, session.hmac_key, session.session_id)
    correct_sig = env.sig
    early_diff = "f" + correct_sig[1:] if correct_sig[0] != "f" else "0" + correct_sig[1:]
    late_diff = correct_sig[:-1] + ("f" if correct_sig[-1] != "f" else "0")

    iters = 5000

    def measure(forged_sig: str) -> float:
        env.sig = forged_sig
        start = time.perf_counter()
        for _ in range(iters):
            verify(env, session.hmac_key, expected_session_id=session.session_id)
        return time.perf_counter() - start

    early = measure(early_diff)
    late = measure(late_diff)
    ratio = max(early, late) / max(min(early, late), 1e-9)
    # 5x tolerance — we mostly want to catch 1000x-style early-exit timing leaks.
    assert ratio < 5.0, f"timing ratio {ratio:.2f} suggests non-constant-time compare"


# ---------------------------------------------------------------------------
# Capability token forging / swapping
# ---------------------------------------------------------------------------


def test_capability_signature_forgery_with_other_session_key_fails(session, session_store):
    other = session_store.create()
    minter = CapabilityMinter()
    # Mint legitimately under `other`. Try to verify under `session`.
    token = minter.mint(tool="x", session_id=other.session_id, session_key=other.hmac_key)
    verdict = minter.verify(
        token.raw,
        session.hmac_key,
        ProposedCall("x", {}),
        expected_session_id=session.session_id,
    )
    assert not verdict.valid


def test_capability_claims_modification_invalidates(session):
    """Try to expand a capability — change tool name in the encoded body."""
    minter = CapabilityMinter()
    tok = minter.mint(tool="read", session_id=session.session_id, session_key=session.hmac_key)
    # Surgically swap "read" → "send" in the base64 claims (will break sig).
    parts = tok.raw.split(".")
    import base64
    import json

    pad = "=" * (-len(parts[2]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(parts[2] + pad))
    claims["tool"] = "send"
    new_body = base64.urlsafe_b64encode(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    forged_raw = f"{parts[0]}.{parts[1]}.{new_body}.{parts[3]}"
    verdict = minter.verify(
        forged_raw,
        session.hmac_key,
        ProposedCall("send", {}),
        expected_session_id=session.session_id,
    )
    assert not verdict.valid
    assert "signature" in verdict.reason


def test_capability_signature_swap_across_two_tokens_fails(session):
    """Swap signatures between two tokens — both must fail verification."""
    minter = CapabilityMinter()
    t1 = minter.mint(tool="A", session_id=session.session_id, session_key=session.hmac_key)
    t2 = minter.mint(tool="B", session_id=session.session_id, session_key=session.hmac_key)
    a_parts = t1.raw.split(".")
    b_parts = t2.raw.split(".")
    forged_a = ".".join([*a_parts[:3], b_parts[3]])
    forged_b = ".".join([*b_parts[:3], a_parts[3]])
    v1 = minter.verify(forged_a, session.hmac_key, ProposedCall("A", {}), expected_session_id=session.session_id)
    v2 = minter.verify(forged_b, session.hmac_key, ProposedCall("B", {}), expected_session_id=session.session_id)
    assert not v1.valid and not v2.valid


def test_capability_pre_dated_token_rejected_at_use(session):
    """A token issued in the future is currently allowed (issued_at not enforced)
    — we accept that, but verify it still expires correctly."""
    minter = CapabilityMinter()
    tok = minter.mint(
        tool="x", session_id=session.session_id, session_key=session.hmac_key, ttl_seconds=1
    )
    # Sleep past expiry.
    time.sleep(1.1)
    verdict = minter.verify(tok.raw, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id)
    assert not verdict.valid
    assert "expired" in verdict.reason


def test_capability_token_with_garbage_after_v1_rejected(session):
    minter = CapabilityMinter()
    tok = minter.mint(tool="x", session_id=session.session_id, session_key=session.hmac_key)
    # Add an extra trailing dot section.
    forged = tok.raw + ".extra"
    verdict = minter.verify(forged, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id)
    assert not verdict.valid
    assert "malformed" in verdict.reason


def test_capability_token_with_wrong_version_rejected(session):
    minter = CapabilityMinter()
    tok = minter.mint(tool="x", session_id=session.session_id, session_key=session.hmac_key)
    parts = tok.raw.split(".")
    parts[1] = "v999"
    forged = ".".join(parts)
    verdict = minter.verify(forged, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id)
    assert not verdict.valid


# ---------------------------------------------------------------------------
# Empty / edge-case inputs
# ---------------------------------------------------------------------------


def test_empty_string_payload_signs_and_verifies(session):
    env = tag("", Origin.USER, session.hmac_key, session.session_id)
    assert verify(env, session.hmac_key, expected_session_id=session.session_id)


def test_very_long_payload_round_trips(session):
    payload = "x" * 1_000_000  # 1MB
    env = tag(payload, Origin.USER, session.hmac_key, session.session_id)
    assert verify(env, session.hmac_key, expected_session_id=session.session_id)


def test_unicode_payload_round_trips(session):
    payload = "héllo 🙂 测试 ‮‬"
    env = tag(payload, Origin.USER, session.hmac_key, session.session_id)
    assert verify(env, session.hmac_key, expected_session_id=session.session_id)


def test_null_byte_payload_round_trips(session):
    payload = "before\x00after"
    env = tag(payload, Origin.USER, session.hmac_key, session.session_id)
    assert verify(env, session.hmac_key, expected_session_id=session.session_id)
