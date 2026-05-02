"""Shared pytest fixtures."""

from __future__ import annotations

import secrets

import pytest

from aegis.session import SessionStore, reset_master_key_for_tests


@pytest.fixture(autouse=True)
def _isolate_master_key():
    """Each test starts with a fresh, deterministic master key."""
    reset_master_key_for_tests(secrets.token_bytes(32))
    yield
    reset_master_key_for_tests(None)


@pytest.fixture
def session_store():
    return SessionStore(default_ttl_seconds=300)


@pytest.fixture
def session(session_store):
    return session_store.create(user_intent="summarize my latest invoice email")
