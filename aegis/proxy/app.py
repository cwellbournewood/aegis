"""FastAPI application — exposes upstream-compatible and AEGIS-native endpoints."""

from __future__ import annotations

import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from aegis import __version__
from aegis.capability import (
    ConstraintKind,
    ParamConstraint,
    constraint_eq,
    constraint_in,
    constraint_max_len,
    constraint_prefix,
    constraint_regex,
)
from aegis.policy import Policy, load_policy_from_env_or_default
from aegis.proxy.adapters import get_adapter
from aegis.proxy.orchestrator import Orchestrator

# Upstream endpoint URLs by provider.
UPSTREAM_URLS: dict[str, str] = {
    "anthropic": os.environ.get("AEGIS_ANTHROPIC_URL", "https://api.anthropic.com/v1/messages"),
    "openai": os.environ.get("AEGIS_OPENAI_URL", "https://api.openai.com/v1/chat/completions"),
    "google": os.environ.get("AEGIS_GOOGLE_URL", "https://generativelanguage.googleapis.com/v1beta/models"),
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CreateSessionRequest(BaseModel):
    user_intent: str | None = None
    upstream: str = "anthropic"
    ttl_seconds: int | None = None


class CreateSessionResponse(BaseModel):
    session_id: str
    upstream: str
    user_intent: str | None = None
    canary_count: int
    expires_at: float | None = None
    aegis_version: str = __version__


class ConstraintModel(BaseModel):
    kind: str
    value: Any = None


class MintCapabilityRequest(BaseModel):
    session_id: str
    tool: str
    constraints: dict[str, ConstraintModel] = Field(default_factory=dict)
    ttl_seconds: int | None = None
    single_use: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class MintCapabilityResponse(BaseModel):
    token: str
    tool: str
    expires_at: float
    nonce: str


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(orchestrator: Orchestrator | None = None, policy: Policy | None = None) -> FastAPI:
    if orchestrator is None:
        orchestrator = Orchestrator(policy=policy or load_policy_from_env_or_default())

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.orchestrator = orchestrator
        app.state.start_time = time.time()
        app.state.http_client = httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0))
        try:
            yield
        finally:
            await app.state.http_client.aclose()

    app = FastAPI(
        title="AEGIS",
        description="Authenticated Execution Gateway for Injection Security",
        version=__version__,
        lifespan=lifespan,
    )

    # ---------------------------------------------------------------- health
    @app.get("/aegis/health")
    async def health() -> dict[str, Any]:
        orch: Orchestrator = app.state.orchestrator
        return {
            "status": "ok",
            "version": __version__,
            "uptime_seconds": time.time() - app.state.start_time,
            "active_sessions": len(orch.sessions),
            "log_entries": len(orch.log),
            "policy_mode": orch.policy.mode.value,
        }

    @app.get("/aegis/version")
    async def version() -> dict[str, str]:
        return {"version": __version__}

    # ---------------------------------------------------------------- sessions
    @app.post("/aegis/session", response_model=CreateSessionResponse)
    async def create_session(req: CreateSessionRequest) -> CreateSessionResponse:
        orch: Orchestrator = app.state.orchestrator
        session = orch.get_or_create_session(
            upstream=req.upstream,
            session_id=None,
            user_intent=req.user_intent,
        )
        canary_count = len(session.canaries.canaries) if session.canaries else 0
        return CreateSessionResponse(
            session_id=session.session_id,
            upstream=session.upstream,
            user_intent=session.user_intent,
            canary_count=canary_count,
            expires_at=session.expires_at,
        )

    @app.get("/aegis/session/{session_id}")
    async def get_session(session_id: str) -> dict[str, Any]:
        orch: Orchestrator = app.state.orchestrator
        session = orch.sessions.get(session_id)
        if session is None:
            raise HTTPException(404, "session not found or expired")
        return {
            "session_id": session.session_id,
            "upstream": session.upstream,
            "user_intent": session.user_intent,
            "created_at": session.created_at,
            "last_active": session.last_active,
            "expires_at": session.expires_at,
            "has_anchor": session.anchor is not None,
            "canary_count": len(session.canaries.canaries) if session.canaries else 0,
        }

    # ---------------------------------------------------------------- capabilities
    @app.post("/aegis/capability", response_model=MintCapabilityResponse)
    async def mint_capability(req: MintCapabilityRequest) -> MintCapabilityResponse:
        orch: Orchestrator = app.state.orchestrator
        session = orch.sessions.get(req.session_id)
        if session is None:
            raise HTTPException(404, "session not found or expired")

        constraints: dict[str, ParamConstraint] = {}
        for name, c in req.constraints.items():
            kind = c.kind
            value = c.value
            if kind == "eq":
                constraints[name] = constraint_eq(value)
            elif kind == "in":
                constraints[name] = constraint_in(list(value or []))
            elif kind == "regex":
                constraints[name] = constraint_regex(str(value))
            elif kind == "prefix":
                constraints[name] = constraint_prefix(str(value))
            elif kind == "max_len":
                constraints[name] = constraint_max_len(int(value))
            elif kind == "any":
                constraints[name] = ParamConstraint(kind=ConstraintKind.ANY)
            else:
                raise HTTPException(400, f"unknown constraint kind: {kind}")

        token = orch.minter.mint(
            tool=req.tool,
            session_id=session.session_id,
            session_key=session.hmac_key,
            constraints=constraints,
            ttl_seconds=req.ttl_seconds,
            single_use=req.single_use,
            metadata=req.metadata,
        )
        return MintCapabilityResponse(
            token=token.raw,
            tool=token.claims.tool,
            expires_at=token.claims.expires_at,
            nonce=token.claims.nonce,
        )

    # ---------------------------------------------------------------- decisions
    @app.get("/aegis/decisions/{request_id}")
    async def get_decision(request_id: str) -> dict[str, Any]:
        orch: Orchestrator = app.state.orchestrator
        entry = orch.log.find(request_id)
        if entry is None:
            raise HTTPException(404, "decision record not found")
        return {
            "seq": entry.seq,
            "timestamp": entry.timestamp,
            "hash": entry.hash,
            "prev_hash": entry.prev_hash,
            "payload": entry.payload,
        }

    @app.get("/aegis/decisions")
    async def list_decisions(limit: int = 50) -> dict[str, Any]:
        orch: Orchestrator = app.state.orchestrator
        entries = orch.log.tail(limit)
        return {
            "count": len(entries),
            "entries": [
                {"seq": e.seq, "timestamp": e.timestamp, "hash": e.hash, "payload": e.payload}
                for e in entries
            ],
        }

    # ---------------------------------------------------------------- proxied LLM endpoints
    @app.post("/v1/anthropic/messages")
    async def anthropic_messages(request: Request) -> Any:
        return await _proxied_call(app, request, upstream="anthropic")

    @app.post("/v1/openai/chat/completions")
    async def openai_chat_completions(request: Request) -> Any:
        return await _proxied_call(app, request, upstream="openai")

    @app.post("/v1/google/generateContent")
    async def google_generate_content(request: Request) -> Any:
        return await _proxied_call(app, request, upstream="google")

    return app


async def _proxied_call(app: FastAPI, request: Request, upstream: str) -> Any:
    orch: Orchestrator = app.state.orchestrator

    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(400, f"invalid JSON body: {exc}") from exc

    adapter = get_adapter(upstream)
    norm_req = adapter.parse_request(body, headers=dict(request.headers))
    norm_req, ctx = orch.pre_flight(norm_req)

    # Forward upstream — unless DRY_RUN is set or there's no API URL configured.
    dry_run = os.environ.get("AEGIS_DRY_RUN") == "1" or body.get("aegis", {}).get("dry_run")

    if dry_run:
        upstream_response: dict[str, Any] = _stub_upstream_response(upstream, body)
    else:
        upstream_body = adapter.render_request(body, norm_req)
        upstream_response = await _forward(app, upstream, request, upstream_body)

    norm_resp = adapter.parse_response(upstream_response)
    record = orch.post_flight(norm_req, norm_resp, ctx)

    # Inject decision metadata.
    upstream_response = dict(upstream_response)
    upstream_response.setdefault("aegis", {})
    upstream_response["aegis"].update(
        {
            "decision": record.decision.value,
            "reason": record.reason,
            "session_id": record.session_id,
            "request_id": record.request_id,
            "score": record.score,
            "mode": record.mode.value,
            "votes": {
                v.layer: {"verdict": v.verdict.value, "reason": v.reason}
                for v in record.votes
            },
        }
    )

    if record.decision.value == "BLOCK":
        return JSONResponse(
            status_code=451,  # Unavailable for Legal Reasons — close-enough fit for "blocked by policy"
            content={
                "error": {
                    "type": "aegis_blocked",
                    "message": record.reason,
                    "decision": "BLOCK",
                    "request_id": record.request_id,
                    "session_id": record.session_id,
                },
                "aegis": upstream_response["aegis"],
            },
        )

    return upstream_response


async def _forward(app: FastAPI, upstream: str, request: Request, body: dict[str, Any]) -> dict[str, Any]:
    url = UPSTREAM_URLS.get(upstream)
    if not url:
        raise HTTPException(502, f"no upstream URL configured for {upstream}")

    headers = {k: v for k, v in request.headers.items() if k.lower() not in {"host", "content-length"}}

    client: httpx.AsyncClient = app.state.http_client
    try:
        resp = await client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"upstream error: {exc}") from exc

    try:
        return resp.json()
    except ValueError as exc:
        raise HTTPException(502, f"upstream returned non-JSON: {resp.text[:200]}") from exc


def _stub_upstream_response(upstream: str, body: dict[str, Any]) -> dict[str, Any]:
    """Synthetic upstream response for AEGIS_DRY_RUN — useful for testing/demo."""
    if upstream == "anthropic":
        return {
            "id": "msg_dryrun",
            "type": "message",
            "role": "assistant",
            "model": body.get("model", "claude-stub"),
            "content": [{"type": "text", "text": "[AEGIS dry run — no upstream call made]"}],
            "stop_reason": "end_turn",
        }
    if upstream == "openai":
        return {
            "id": "chatcmpl-dryrun",
            "object": "chat.completion",
            "model": body.get("model", "openai-stub"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "[AEGIS dry run — no upstream call made]"},
                    "finish_reason": "stop",
                }
            ],
        }
    return {
        "candidates": [
            {
                "content": {"parts": [{"text": "[AEGIS dry run — no upstream call made]"}], "role": "model"},
                "finishReason": "STOP",
            }
        ],
        "modelVersion": body.get("model", "gemini-stub"),
    }
