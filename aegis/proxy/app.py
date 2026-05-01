"""FastAPI application, exposes upstream-compatible and AEGIS-native endpoints."""

from __future__ import annotations

import json as _json
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
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
from aegis.metrics import metrics
from aegis.policy import Policy, load_policy_from_env_or_default
from aegis.proxy.adapters import get_adapter
from aegis.proxy.dashboard import render_dashboard
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

    # ---------------------------------------------------------------- dashboard
    @app.get("/aegis/dashboard", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        return HTMLResponse(content=render_dashboard())

    # ---------------------------------------------------------------- metrics
    @app.get("/metrics", response_class=PlainTextResponse)
    async def prometheus_metrics() -> PlainTextResponse:
        # Refresh gauges that are derived from orchestrator state.
        orch: Orchestrator = app.state.orchestrator
        metrics.gauge("aegis_active_sessions").set(float(len(orch.sessions)))
        metrics.gauge("aegis_log_entries").set(float(len(orch.log)))
        return PlainTextResponse(
            content=metrics.render(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

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

    # Streaming endpoints: same wire format, but `stream: true` is supported.
    @app.post("/v1/anthropic/messages/stream")
    async def anthropic_messages_stream(request: Request) -> Any:
        return await _proxied_stream(app, request, upstream="anthropic")

    @app.post("/v1/openai/chat/completions/stream")
    async def openai_chat_completions_stream(request: Request) -> Any:
        return await _proxied_stream(app, request, upstream="openai")

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

    # Forward upstream, unless DRY_RUN is set or there's no API URL configured.
    dry_run = os.environ.get("AEGIS_DRY_RUN") == "1" or body.get("aegis", {}).get("dry_run")

    if dry_run:
        upstream_response: dict[str, Any] = _stub_upstream_response(upstream, body)
    else:
        upstream_body = adapter.render_request(body, norm_req)
        upstream_response = await _forward(app, upstream, request, upstream_body)

    norm_resp = adapter.parse_response(upstream_response)
    record = await orch.post_flight_async(norm_req, norm_resp, ctx)

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
        # Two block modes:
        #   1. Tool-call block (graceful): the *only* reason for BLOCK is one or
        #      more tool calls failing the gates. We keep the response 200 and
        #      replace the offending tool_use blocks with a structured "denied"
        #      block the agent can recover from. This is the surface 1 design
        #      goal. AEGIS hides unless a hard block is genuinely needed.
        #   2. Hard block (HTTP 451): the request itself is broadly suspect
        #      (e.g., canary leak in the response text, or the entire prompt
        #      fails CCPT verification). The client gets a structured error.
        soft_block_safe = _is_tool_call_only_block(record, norm_resp)
        if soft_block_safe:
            sanitized = _rewrite_response_with_blocked_tool_results(
                upstream=upstream,
                upstream_response=upstream_response,
                norm_resp=norm_resp,
                record=record,
            )
            return sanitized

        return JSONResponse(
            status_code=451,  # Unavailable for Legal Reasons, close-enough fit for "blocked by policy"
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


async def _proxied_stream(app: FastAPI, request: Request, upstream: str) -> Any:
    """Streaming variant of the proxied call.

    Per-chunk canary scan rejects mid-stream; final-pass full pipeline runs at
    end-of-stream. The response is an SSE stream of text/event-stream events
    that mirrors the upstream's wire format, plus AEGIS decision events when
    relevant.
    """
    from aegis.proxy.streaming import (
        StreamingEvaluator,
        parse_anthropic_sse,
        parse_openai_sse,
    )

    orch: Orchestrator = app.state.orchestrator

    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(400, f"invalid JSON body: {exc}") from exc

    adapter = get_adapter(upstream)
    norm_req = adapter.parse_request(body, headers=dict(request.headers))
    norm_req, ctx = orch.pre_flight(norm_req)

    body.setdefault("stream", True)

    parser = parse_anthropic_sse if upstream == "anthropic" else parse_openai_sse

    dry_run = os.environ.get("AEGIS_DRY_RUN") == "1" or body.get("aegis", {}).get("dry_run")

    async def upstream_chunks() -> AsyncIterator[bytes]:
        if dry_run:
            # Synthetic SSE for testing: emit two text deltas + done.
            yield b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"[AEGIS dry "}}\n'
            yield b'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"run]"}}\n'
            yield b'data: {"type":"message_stop"}\n'
            return

        url = UPSTREAM_URLS.get(upstream)
        if not url:
            raise HTTPException(502, f"no upstream URL for {upstream}")

        upstream_body = adapter.render_request(body, norm_req)
        headers = {
            k: v for k, v in request.headers.items() if k.lower() not in {"host", "content-length"}
        }
        client: httpx.AsyncClient = app.state.http_client
        async with client.stream("POST", url, json=upstream_body, headers=headers) as resp:
            async for line in resp.aiter_lines():
                yield line.encode("utf-8") + b"\n"

    evaluator = StreamingEvaluator(orch, norm_req, ctx)

    async def event_stream() -> AsyncIterator[bytes]:
        async for event in evaluator.evaluate(parser(upstream_chunks())):
            if event.kind == "chunk":
                # Re-render the chunk in a wire-format-neutral SSE frame.
                # We mirror the upstream's structure as closely as possible.
                payload: dict[str, Any] = {}
                if event.chunk.text:
                    payload["text"] = event.chunk.text
                if event.chunk.tool_calls:
                    payload["tool_calls"] = [
                        {"tool": tc.tool, "parameters": tc.parameters}
                        for tc in event.chunk.tool_calls
                    ]
                if event.chunk.done:
                    payload["done"] = True
                yield ("data: " + _json.dumps(payload) + "\n\n").encode("utf-8")
            elif event.kind == "block":
                payload = {
                    "aegis": {
                        "decision": "BLOCK",
                        "reason": event.reason,
                        "request_id": event.request_id,
                        "session_id": event.session_id,
                    }
                }
                yield ("event: aegis_blocked\ndata: " + _json.dumps(payload) + "\n\n").encode("utf-8")
                return
            elif event.kind == "done":
                payload = {
                    "aegis": {
                        "decision": event.decision,
                        "reason": event.reason,
                        "request_id": event.request_id,
                        "session_id": event.session_id,
                    },
                    "done": True,
                }
                yield ("event: aegis_done\ndata: " + _json.dumps(payload) + "\n\n").encode("utf-8")

    return StreamingResponse(event_stream(), media_type="text/event-stream")


def _is_tool_call_only_block(record, norm_resp) -> bool:  # type: ignore[no-untyped-def]
    """True when the request would have been ALLOW if the model hadn't proposed
    any tool calls. In that case we can rewrite the response to surface the
    block as a tool-result error and keep the rest of the conversation flowing.
    """
    if not norm_resp.tool_calls:
        return False
    # Only the gates that fire per-tool-call are eligible for soft block.
    per_call_layers = {"lattice", "intent_drift", "capability"}
    for v in record.votes:
        if v.verdict.value != "BLOCK":
            continue
        if v.layer not in per_call_layers:
            return False
    return True


def _rewrite_response_with_blocked_tool_results(
    upstream: str,
    upstream_response: dict[str, Any],
    norm_resp,  # type: ignore[no-untyped-def]
    record,  # type: ignore[no-untyped-def]
) -> JSONResponse:
    """Replace tool_use blocks with provider-native 'tool denied' blocks.

    This lets agentic clients recover gracefully, the agent sees that the tool
    call was denied (with a structured reason) and can route around it. AEGIS
    stays out of the user-facing surface unless the block is genuinely hard.
    """
    body = dict(upstream_response)
    if upstream == "anthropic":
        original_content = body.get("content") or []
        new_content = []
        for block in original_content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tool_name = block.get("name", "<unknown>")
                new_content.append(
                    {
                        "type": "text",
                        "text": (
                            f"[AEGIS] Tool call to `{tool_name}` was denied by the "
                            f"security gateway: {record.reason}. I'll continue without it."
                        ),
                    }
                )
            else:
                new_content.append(block)
        body["content"] = new_content
        if body.get("stop_reason") == "tool_use":
            body["stop_reason"] = "end_turn"
    elif upstream == "openai":
        for choice in body.get("choices") or []:
            msg = choice.get("message") or {}
            if msg.get("tool_calls"):
                msg.pop("tool_calls", None)
                msg["content"] = (
                    f"[AEGIS] Proposed tool call(s) were denied by the security "
                    f"gateway: {record.reason}. Continuing without them."
                )
            choice["finish_reason"] = "stop"
    elif upstream == "google":
        for cand in body.get("candidates") or []:
            content = cand.get("content") or {}
            new_parts = []
            for part in content.get("parts") or []:
                if isinstance(part, dict) and "functionCall" in part:
                    new_parts.append(
                        {
                            "text": (
                                f"[AEGIS] Function call was denied by the security "
                                f"gateway: {record.reason}."
                            )
                        }
                    )
                else:
                    new_parts.append(part)
            if new_parts:
                content["parts"] = new_parts
            cand["content"] = content
            cand["finishReason"] = "STOP"

    body.setdefault("aegis", {})
    body["aegis"].update(
        {
            "decision": "BLOCK",
            "soft_block": True,
            "reason": record.reason,
            "request_id": record.request_id,
            "session_id": record.session_id,
            "blocked_by": [v.layer for v in record.votes if v.verdict.value == "BLOCK"],
            "votes": {
                v.layer: {"verdict": v.verdict.value, "reason": v.reason}
                for v in record.votes
            },
        }
    )
    return JSONResponse(status_code=200, content=body)


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
    """Synthetic upstream response for AEGIS_DRY_RUN, useful for testing/demo."""
    if upstream == "anthropic":
        return {
            "id": "msg_dryrun",
            "type": "message",
            "role": "assistant",
            "model": body.get("model", "claude-stub"),
            "content": [{"type": "text", "text": "[AEGIS dry run, no upstream call made]"}],
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
                    "message": {"role": "assistant", "content": "[AEGIS dry run, no upstream call made]"},
                    "finish_reason": "stop",
                }
            ],
        }
    return {
        "candidates": [
            {
                "content": {"parts": [{"text": "[AEGIS dry run, no upstream call made]"}], "role": "model"},
                "finishReason": "STOP",
            }
        ],
        "modelVersion": body.get("model", "gemini-stub"),
    }
