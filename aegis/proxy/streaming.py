"""Streaming response evaluation.

Modern LLM applications stream responses token-by-token via SSE. AEGIS supports
streaming with these guarantees:

    1. **Per-chunk canary scan.** Each text chunk is normalized and scanned for
       canary tokens as it arrives. A leak triggers an immediate BLOCK event;
       the upstream stream is closed and the client receives an `aegis_blocked`
       SSE event before any further content reaches them.

    2. **Final-pass full evaluation.** When the upstream stream completes, the
       full assembled response (text + tool calls) runs through the standard
       five-layer pipeline. This catches drift / lattice / capability issues
       that depend on knowing the whole response.

    3. **Bounded buffer.** The streaming evaluator never holds more than the
       configured buffer size in memory. Past content is hashed and discarded
       once scanned, preserves session memory for long-running streams.

The streaming evaluator wraps an async iterator and yields a stream of decision
events to the caller. The caller decides how to render those events in their
target wire format (Anthropic SSE, OpenAI SSE, Google SSE, etc).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from aegis.canary import CanaryHit
from aegis.proxy.orchestrator import (
    NormalizedRequest,
    NormalizedResponse,
    NormalizedToolCall,
    Orchestrator,
    ProxyContext,
)


@dataclass
class StreamChunk:
    """A unit of streamed model output.

    `text` is appended to the running text; `tool_calls` are deltas to be
    accumulated. Either may be present in any chunk.
    """

    text: str = ""
    tool_calls: list[NormalizedToolCall] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    done: bool = False


@dataclass
class StreamEvent:
    """Decision event emitted by the streaming evaluator."""

    kind: str  # "chunk" | "block" | "done"
    chunk: StreamChunk | None = None
    decision: str | None = None  # ALLOW / WARN / BLOCK
    reason: str | None = None
    request_id: str | None = None
    session_id: str | None = None
    canary_hit: CanaryHit | None = None
    final_record: Any = None


class StreamingEvaluator:
    """Wraps an async chunk iterator with per-chunk canary scanning.

    Usage:
        evaluator = StreamingEvaluator(orch, req, ctx)
        async for event in evaluator.evaluate(upstream_chunk_iter):
            if event.kind == "block":
                # serialize a 'blocked' SSE frame and close the connection
                break
            elif event.kind == "chunk":
                # forward to the client
                ...
            elif event.kind == "done":
                # final decision is event.final_record
                ...
    """

    def __init__(
        self,
        orch: Orchestrator,
        req: NormalizedRequest,
        ctx: ProxyContext,
        max_buffer_chars: int = 256_000,
    ) -> None:
        self.orch = orch
        self.req = req
        self.ctx = ctx
        self.max_buffer_chars = max_buffer_chars
        self._text_buffer: list[str] = []
        self._buffered_chars = 0
        self._tool_calls: list[NormalizedToolCall] = []

    async def evaluate(
        self,
        chunks: AsyncIterator[StreamChunk],
    ) -> AsyncIterator[StreamEvent]:
        """Drive the upstream chunk stream through per-chunk canary scan.

        Yields the chunk events to the caller. On a canary leak, yields a
        BLOCK event and stops consuming the upstream, the caller is
        responsible for closing the upstream connection.
        """
        garden = self.ctx.session.canaries
        async for chunk in chunks:
            # Per-chunk canary scan over text and any tool-call deltas.
            if garden is not None and garden.canaries:
                if chunk.text:
                    hits = garden.scan(chunk.text)
                    if hits:
                        yield self._block_event(
                            reason="canary leak detected mid-stream at chunk text",
                            canary_hit=hits[0],
                        )
                        return
                for tc in chunk.tool_calls:
                    hits = garden.scan_structured(
                        tc.parameters, location=f"tool:{tc.tool}"
                    )
                    if hits:
                        yield self._block_event(
                            reason=f"canary leak detected mid-stream at {hits[0].location}",
                            canary_hit=hits[0],
                        )
                        return

            # Accumulate; bound the buffer to protect memory.
            if chunk.text:
                self._text_buffer.append(chunk.text)
                self._buffered_chars += len(chunk.text)
                if self._buffered_chars > self.max_buffer_chars:
                    # Drop the oldest text chunks; we keep only what fits.
                    while self._buffered_chars > self.max_buffer_chars and self._text_buffer:
                        dropped = self._text_buffer.pop(0)
                        self._buffered_chars -= len(dropped)
            if chunk.tool_calls:
                self._tool_calls.extend(chunk.tool_calls)

            yield StreamEvent(kind="chunk", chunk=chunk)

            if chunk.done:
                break

        # Final evaluation: run the full five-layer pipeline on the assembled response.
        full_text = "".join(self._text_buffer)
        norm_resp = NormalizedResponse(text=full_text, tool_calls=self._tool_calls)
        record = await self.orch.post_flight_async(self.req, norm_resp, self.ctx)

        if record.decision.value == "BLOCK":
            yield self._block_event(reason=record.reason, final_record=record)
            return

        yield StreamEvent(
            kind="done",
            decision=record.decision.value,
            reason=record.reason,
            request_id=record.request_id,
            session_id=record.session_id,
            final_record=record,
        )

    def _block_event(
        self,
        reason: str,
        canary_hit: CanaryHit | None = None,
        final_record: Any = None,
    ) -> StreamEvent:
        return StreamEvent(
            kind="block",
            decision="BLOCK",
            reason=reason,
            request_id=self.ctx.request_id,
            session_id=self.ctx.session.session_id,
            canary_hit=canary_hit,
            final_record=final_record,
        )


# ---------------------------------------------------------------------------
# Provider-specific SSE parsers
# ---------------------------------------------------------------------------


async def parse_anthropic_sse(line_iter: AsyncIterator[bytes]) -> AsyncIterator[StreamChunk]:
    """Parse Anthropic Messages API SSE stream into normalized StreamChunks.

    Anthropic emits events: message_start, content_block_start, content_block_delta,
    content_block_stop, message_delta, message_stop. We only care about deltas
    and the terminal stop.
    """
    current_tool_call: dict[str, Any] | None = None
    pending_tool_args: list[str] = []

    async for raw in line_iter:
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            yield StreamChunk(done=True)
            return
        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            continue

        etype = event.get("type", "")
        if etype == "content_block_delta":
            delta = event.get("delta", {})
            if delta.get("type") == "text_delta":
                yield StreamChunk(text=delta.get("text", ""))
            elif delta.get("type") == "input_json_delta":
                pending_tool_args.append(delta.get("partial_json", ""))
        elif etype == "content_block_start":
            block = event.get("content_block", {})
            if block.get("type") == "tool_use":
                current_tool_call = {"name": block.get("name", ""), "input": block.get("input", {})}
                pending_tool_args = []
        elif etype == "content_block_stop":
            if current_tool_call is not None:
                # Reassemble full tool call.
                args_str = "".join(pending_tool_args)
                params = current_tool_call.get("input") or {}
                if args_str:
                    try:
                        params = json.loads(args_str)
                    except json.JSONDecodeError:
                        params = {"_raw_arguments": args_str}
                yield StreamChunk(
                    tool_calls=[
                        NormalizedToolCall(
                            tool=current_tool_call["name"],
                            parameters=params,
                            raw=event,
                        )
                    ]
                )
                current_tool_call = None
                pending_tool_args = []
        elif etype == "message_stop":
            yield StreamChunk(done=True)
            return


async def parse_openai_sse(line_iter: AsyncIterator[bytes]) -> AsyncIterator[StreamChunk]:
    """Parse OpenAI Chat Completions SSE stream into normalized StreamChunks."""
    pending_tool_args: dict[int, dict[str, Any]] = {}

    async for raw in line_iter:
        line = raw.decode("utf-8", errors="replace").strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            # Flush any pending tool calls.
            for tc in pending_tool_args.values():
                args = tc.get("args", "")
                try:
                    params = json.loads(args) if args else {}
                except json.JSONDecodeError:
                    params = {"_raw_arguments": args}
                yield StreamChunk(
                    tool_calls=[
                        NormalizedToolCall(tool=tc.get("name", ""), parameters=params)
                    ]
                )
            yield StreamChunk(done=True)
            return
        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            continue

        for choice in event.get("choices", []) or []:
            delta = choice.get("delta", {}) or {}
            if "content" in delta and isinstance(delta["content"], str):
                yield StreamChunk(text=delta["content"])
            for tc_delta in delta.get("tool_calls", []) or []:
                idx = tc_delta.get("index", 0)
                slot = pending_tool_args.setdefault(idx, {"name": "", "args": ""})
                fn = tc_delta.get("function", {}) or {}
                if fn.get("name"):
                    slot["name"] = fn["name"]
                if fn.get("arguments"):
                    slot["args"] += fn["arguments"]


@dataclass
class StreamSettings:
    enabled: bool = True
    max_buffer_chars: int = 256_000
