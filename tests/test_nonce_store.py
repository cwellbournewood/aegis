"""Tests for the pluggable NonceStore."""

from __future__ import annotations

import threading
import time

import pytest

from aegis.capability import CapabilityMinter, ProposedCall
from aegis.nonce_store import MemoryNonceStore, make_nonce_store_from_config


def test_memory_first_mark_returns_true():
    store = MemoryNonceStore()
    assert store.mark_used("n1", ttl_seconds=10) is True


def test_memory_second_mark_returns_false():
    store = MemoryNonceStore()
    store.mark_used("n1", 10)
    assert store.mark_used("n1", 10) is False


def test_memory_expired_nonce_can_be_remarked():
    store = MemoryNonceStore()
    store.mark_used("n1", ttl_seconds=0)
    time.sleep(0.05)
    # Past TTL → mark_used returns True again.
    assert store.mark_used("n1", ttl_seconds=10) is True


def test_memory_is_used_lifecycle():
    store = MemoryNonceStore()
    assert not store.is_used("n1")
    store.mark_used("n1", 10)
    assert store.is_used("n1")


def test_memory_concurrent_mark_used_only_one_winner():
    """Even under concurrent threads, only one mark_used returns True."""
    store = MemoryNonceStore()
    winners: list[bool] = []
    barrier = threading.Barrier(50)

    def worker():
        barrier.wait()
        winners.append(store.mark_used("hot", ttl_seconds=60))

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert winners.count(True) == 1
    assert winners.count(False) == 49


def test_memory_sweep_evicts_expired():
    store = MemoryNonceStore(sweep_every=4)
    for i in range(4):
        store.mark_used(f"e{i}", ttl_seconds=0)
    time.sleep(0.05)
    # Trigger sweep with a fresh write.
    store.mark_used("fresh", ttl_seconds=60)
    # Expired ones are gone after sweep.
    for i in range(4):
        assert not store.is_used(f"e{i}")


def test_make_nonce_store_memory_default():
    store = make_nonce_store_from_config({})
    assert isinstance(store, MemoryNonceStore)


def test_make_nonce_store_unknown_kind_raises():
    with pytest.raises(ValueError):
        make_nonce_store_from_config({"kind": "evil"})


def test_make_nonce_store_redis_raises_without_lib(monkeypatch):
    """Without redis installed, requesting a redis nonce store raises a
    descriptive ImportError."""
    import sys
    monkeypatch.setitem(sys.modules, "redis", None)
    with pytest.raises((ImportError, AttributeError)):
        make_nonce_store_from_config({"kind": "redis", "url": "redis://localhost"})


# ---------------------------------------------------------------------------
# CapabilityMinter integration with NonceStore
# ---------------------------------------------------------------------------


def test_verify_and_consume_atomically_rejects_replay(session):
    minter = CapabilityMinter()
    tok = minter.mint(tool="x", session_id=session.session_id, session_key=session.hmac_key)

    # First verify_and_consume succeeds.
    v1 = minter.verify_and_consume(
        tok.raw, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id
    )
    assert v1.valid

    # Second call with the same token MUST fail, atomic mark_used returned False.
    v2 = minter.verify_and_consume(
        tok.raw, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id
    )
    assert not v2.valid
    assert "single-use" in v2.reason


def test_verify_and_consume_concurrent_only_one_winner(session):
    """The whole point of the atomic path: under concurrency, only one caller
    consumes a single-use token."""
    minter = CapabilityMinter()
    tok = minter.mint(tool="x", session_id=session.session_id, session_key=session.hmac_key)

    results: list[bool] = []
    barrier = threading.Barrier(20)

    def worker():
        barrier.wait()
        v = minter.verify_and_consume(
            tok.raw, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id
        )
        results.append(v.valid)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(True) == 1


def test_custom_nonce_store_used(session):
    """Pass in a custom store; minter uses it instead of the in-memory default."""
    custom_store = MemoryNonceStore()
    minter = CapabilityMinter(nonce_store=custom_store)
    tok = minter.mint(tool="x", session_id=session.session_id, session_key=session.hmac_key)

    v = minter.verify_and_consume(
        tok.raw, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id
    )
    assert v.valid
    assert custom_store.is_used(tok.claims.nonce)


def test_multi_use_token_does_not_mark_nonce(session):
    """`single_use=False` tokens should not consume the nonce store."""
    custom_store = MemoryNonceStore()
    minter = CapabilityMinter(nonce_store=custom_store)
    tok = minter.mint(
        tool="x", session_id=session.session_id, session_key=session.hmac_key, single_use=False
    )
    minter.verify_and_consume(
        tok.raw, session.hmac_key, ProposedCall("x", {}), expected_session_id=session.session_id
    )
    assert not custom_store.is_used(tok.claims.nonce)
