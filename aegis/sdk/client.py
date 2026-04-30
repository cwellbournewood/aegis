"""Synchronous AEGIS Python SDK client.

Usage:
    from aegis.sdk import AegisClient

    aegis = AegisClient(base_url="http://localhost:8080")

    session = aegis.session.create(user_intent="summarize my latest invoice email")
    session.capabilities.mint("read_email", constraints={"limit": {"kind": "max_len", "value": 5}})

    # Forward LLM calls through AEGIS — point your existing client at session.proxy_url
    import anthropic
    client = anthropic.Anthropic(base_url=session.proxy_url, api_key="...")
    resp = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        messages=[{"role": "user", "content": "summarize my latest invoice email"}],
        extra_body={"aegis": {"session_id": session.session_id, "capability_tokens": session.capability_tokens()}}
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class CapabilityHandle:
    token: str
    tool: str
    expires_at: float
    nonce: str


@dataclass
class SessionHandle:
    session_id: str
    upstream: str
    base_url: str
    user_intent: str | None = None
    canary_count: int = 0
    expires_at: float | None = None
    _client: AegisClient | None = field(default=None, repr=False)
    _capabilities: list[CapabilityHandle] = field(default_factory=list)

    @property
    def proxy_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/v1/{self.upstream}"

    @property
    def capabilities(self) -> CapabilityNamespace:
        return CapabilityNamespace(self)

    def capability_tokens(self) -> list[str]:
        return [c.token for c in self._capabilities]


class CapabilityNamespace:
    def __init__(self, session: SessionHandle) -> None:
        self._session = session
        if session._client is None:
            raise RuntimeError("SessionHandle has no attached client")
        self._client: AegisClient = session._client

    def mint(
        self,
        tool: str,
        constraints: dict[str, dict[str, Any]] | None = None,
        ttl_seconds: int | None = None,
        single_use: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> CapabilityHandle:
        body = {
            "session_id": self._session.session_id,
            "tool": tool,
            "constraints": constraints or {},
            "single_use": single_use,
            "metadata": metadata or {},
        }
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        resp = self._client._post("/aegis/capability", body)
        h = CapabilityHandle(
            token=resp["token"],
            tool=resp["tool"],
            expires_at=resp["expires_at"],
            nonce=resp["nonce"],
        )
        self._session._capabilities.append(h)
        return h


class SessionNamespace:
    def __init__(self, client: AegisClient) -> None:
        self._client = client

    def create(
        self,
        user_intent: str | None = None,
        upstream: str = "anthropic",
        ttl_seconds: int | None = None,
    ) -> SessionHandle:
        body: dict[str, Any] = {"upstream": upstream}
        if user_intent is not None:
            body["user_intent"] = user_intent
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        resp = self._client._post("/aegis/session", body)
        h = SessionHandle(
            session_id=resp["session_id"],
            upstream=resp["upstream"],
            base_url=self._client.base_url,
            user_intent=resp.get("user_intent"),
            canary_count=resp.get("canary_count", 0),
            expires_at=resp.get("expires_at"),
            _client=self._client,
        )
        return h

    def get(self, session_id: str) -> dict[str, Any]:
        return self._client._get(f"/aegis/session/{session_id}")


class DecisionNamespace:
    def __init__(self, client: AegisClient) -> None:
        self._client = client

    def get(self, request_id: str) -> dict[str, Any]:
        return self._client._get(f"/aegis/decisions/{request_id}")

    def list(self, limit: int = 50) -> dict[str, Any]:
        return self._client._get(f"/aegis/decisions?limit={limit}")


class AegisClient:
    """Synchronous AEGIS proxy client."""

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._http = httpx.Client(timeout=timeout)
        self.session = SessionNamespace(self)
        self.decisions = DecisionNamespace(self)

    def _headers(self) -> dict[str, str]:
        h = {"content-type": "application/json"}
        if self.api_key:
            h["authorization"] = f"Bearer {self.api_key}"
        return h

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = self._http.post(self.base_url + path, json=body, headers=self._headers())
        resp.raise_for_status()
        return resp.json()

    def _get(self, path: str) -> dict[str, Any]:
        resp = self._http.get(self.base_url + path, headers=self._headers())
        resp.raise_for_status()
        return resp.json()

    def health(self) -> dict[str, Any]:
        return self._get("/aegis/health")

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> AegisClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
