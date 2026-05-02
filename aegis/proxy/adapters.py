"""Provider adapters.

Each adapter knows how to:
    1. Parse a provider-native request into a NormalizedRequest.
    2. Re-render a (possibly canary-injected) NormalizedRequest back into the
       provider's wire format for upstream forwarding.
    3. Parse the provider's response into a NormalizedResponse.

Adapters are intentionally thin, all decision logic lives in the orchestrator.
"""

from __future__ import annotations

from typing import Any

from aegis.ccpt import Level, Origin
from aegis.proxy.orchestrator import (
    NormalizedMessage,
    NormalizedRequest,
    NormalizedResponse,
    NormalizedToolCall,
)

# ----------------------------------------------------------------------------
# Anthropic Messages API
# ----------------------------------------------------------------------------


class AnthropicAdapter:
    """Wire-compatible with Anthropic's Messages API.

    https://docs.anthropic.com/en/api/messages
    """

    name = "anthropic"

    def parse_request(
        self,
        body: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> NormalizedRequest:
        messages: list[NormalizedMessage] = []

        sys_prompt = body.get("system")
        if isinstance(sys_prompt, str) and sys_prompt:
            messages.append(
                NormalizedMessage(
                    role="system", origin=Origin.SYSTEM, level=Level.L3, content=sys_prompt
                )
            )
        elif isinstance(sys_prompt, list):
            for block in sys_prompt:
                if isinstance(block, dict) and block.get("type") == "text":
                    messages.append(
                        NormalizedMessage(
                            role="system", origin=Origin.SYSTEM, level=Level.L3, content=block.get("text", "")
                        )
                    )

        for m in body.get("messages", []) or []:
            role = m.get("role", "user")
            origin, level = (Origin.USER, Level.L2) if role == "user" else (Origin.AGENT, Level.L1)
            content = m.get("content", "")
            if isinstance(content, str):
                messages.append(NormalizedMessage(role=role, origin=origin, level=level, content=content))
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type")
                    if btype == "text":
                        messages.append(
                            NormalizedMessage(role=role, origin=origin, level=level, content=block.get("text", ""))
                        )
                    elif btype == "tool_result":
                        # Tool output is L0 (least trusted) by default.
                        tc = block.get("content", "")
                        if isinstance(tc, list):
                            for sub in tc:
                                if isinstance(sub, dict) and sub.get("type") == "text":
                                    messages.append(
                                        NormalizedMessage(
                                            role="tool",
                                            origin=Origin.TOOL,
                                            level=Level.L0,
                                            content=sub.get("text", ""),
                                            metadata={"tool_use_id": block.get("tool_use_id")},
                                        )
                                    )
                        elif isinstance(tc, str):
                            messages.append(
                                NormalizedMessage(
                                    role="tool",
                                    origin=Origin.TOOL,
                                    level=Level.L0,
                                    content=tc,
                                    metadata={"tool_use_id": block.get("tool_use_id")},
                                )
                            )

        meta_keys = ("model", "max_tokens", "temperature", "top_p", "top_k", "stop_sequences", "stream")
        metadata = {k: body[k] for k in meta_keys if k in body}

        # AEGIS-namespaced extensions in the request body.
        ext = body.get("aegis", {}) or {}
        session_hint = ext.get("session_id")
        intent_hint = ext.get("user_intent")
        cap_tokens = list(ext.get("capability_tokens") or [])

        return NormalizedRequest(
            upstream=self.name,
            messages=messages,
            tools=list(body.get("tools") or []),
            metadata=metadata,
            session_id_hint=session_hint,
            user_intent_hint=intent_hint,
            capability_tokens=cap_tokens,
        )

    def render_request(self, body: dict[str, Any], req: NormalizedRequest) -> dict[str, Any]:
        """Re-render the (possibly canary-augmented) request back to Anthropic's format.

        We modify only what we need to: the system prompt and pass everything else through.
        """
        out = dict(body)
        new_system_parts = [m.content for m in req.messages if m.origin == Origin.SYSTEM]
        if new_system_parts:
            out["system"] = "\n\n".join(new_system_parts)
        # Strip our extension before forwarding upstream.
        out.pop("aegis", None)
        return out

    def parse_response(self, body: dict[str, Any]) -> NormalizedResponse:
        text_chunks: list[str] = []
        tool_calls: list[NormalizedToolCall] = []
        for block in body.get("content", []) or []:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "text":
                text_chunks.append(block.get("text", ""))
            elif btype == "tool_use":
                tool_calls.append(
                    NormalizedToolCall(
                        tool=block.get("name", ""),
                        parameters=dict(block.get("input", {}) or {}),
                        summary=None,
                        capability_token=(block.get("input", {}) or {}).get("_aegis_capability"),
                        raw=block,
                    )
                )
        return NormalizedResponse(
            text="\n".join(text_chunks),
            tool_calls=tool_calls,
            raw=body,
            metadata={"stop_reason": body.get("stop_reason"), "model": body.get("model")},
        )


# ----------------------------------------------------------------------------
# OpenAI Chat Completions / Responses API
# ----------------------------------------------------------------------------


class OpenAIAdapter:
    """Wire-compatible with OpenAI Chat Completions.

    Tool calls are extracted from `choices[].message.tool_calls`.
    """

    name = "openai"

    def parse_request(
        self,
        body: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> NormalizedRequest:
        messages: list[NormalizedMessage] = []
        for m in body.get("messages") or []:
            role = m.get("role", "user")
            content = m.get("content", "")
            if role == "system":
                origin, level = Origin.SYSTEM, Level.L3
            elif role == "user":
                origin, level = Origin.USER, Level.L2
            elif role == "tool":
                origin, level = Origin.TOOL, Level.L0
            elif role == "assistant":
                origin, level = Origin.AGENT, Level.L1
            else:
                origin, level = Origin.USER, Level.L2

            if isinstance(content, str):
                messages.append(NormalizedMessage(role=role, origin=origin, level=level, content=content))
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") in {"text", "input_text"}:
                        messages.append(
                            NormalizedMessage(role=role, origin=origin, level=level, content=part.get("text", ""))
                        )

        meta_keys = ("model", "max_tokens", "temperature", "top_p", "stream", "tool_choice")
        metadata = {k: body[k] for k in meta_keys if k in body}

        ext = body.get("aegis", {}) or {}
        session_hint = ext.get("session_id")
        intent_hint = ext.get("user_intent")
        cap_tokens = list(ext.get("capability_tokens") or [])

        return NormalizedRequest(
            upstream=self.name,
            messages=messages,
            tools=list(body.get("tools") or []),
            metadata=metadata,
            session_id_hint=session_hint,
            user_intent_hint=intent_hint,
            capability_tokens=cap_tokens,
        )

    def render_request(self, body: dict[str, Any], req: NormalizedRequest) -> dict[str, Any]:
        out = dict(body)
        new_messages: list[dict[str, Any]] = []
        for m in req.messages:
            new_messages.append({"role": m.role, "content": m.content})
        out["messages"] = new_messages
        out.pop("aegis", None)
        return out

    def parse_response(self, body: dict[str, Any]) -> NormalizedResponse:
        text_chunks: list[str] = []
        tool_calls: list[NormalizedToolCall] = []

        for choice in body.get("choices") or []:
            msg = choice.get("message") or {}
            content = msg.get("content")
            if isinstance(content, str) and content:
                text_chunks.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") in {"text", "output_text"}:
                        text_chunks.append(part.get("text", ""))

            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function") or {}
                args = fn.get("arguments") or "{}"
                params: dict[str, Any]
                if isinstance(args, str):
                    import json as _json

                    try:
                        params = _json.loads(args)
                    except _json.JSONDecodeError:
                        params = {"_raw_arguments": args}
                else:
                    params = dict(args)
                tool_calls.append(
                    NormalizedToolCall(
                        tool=fn.get("name", ""),
                        parameters=params,
                        capability_token=params.pop("_aegis_capability", None) if isinstance(params, dict) else None,
                        raw=tc,
                    )
                )

        return NormalizedResponse(
            text="\n".join(text_chunks),
            tool_calls=tool_calls,
            raw=body,
            metadata={"model": body.get("model")},
        )


# ----------------------------------------------------------------------------
# Google Gemini generateContent
# ----------------------------------------------------------------------------


class GoogleAdapter:
    """Wire-compatible with Google Gemini's generateContent.

    System instructions arrive as `system_instruction`. Function calls are in
    `candidates[].content.parts[].functionCall`.
    """

    name = "google"

    def parse_request(
        self,
        body: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> NormalizedRequest:
        messages: list[NormalizedMessage] = []

        sys_inst = body.get("systemInstruction") or body.get("system_instruction")
        if isinstance(sys_inst, dict):
            for part in sys_inst.get("parts") or []:
                if isinstance(part, dict) and "text" in part:
                    messages.append(
                        NormalizedMessage(
                            role="system", origin=Origin.SYSTEM, level=Level.L3, content=part.get("text", "")
                        )
                    )
        elif isinstance(sys_inst, str):
            messages.append(
                NormalizedMessage(role="system", origin=Origin.SYSTEM, level=Level.L3, content=sys_inst)
            )

        for c in body.get("contents") or []:
            role = c.get("role", "user")
            origin = Origin.USER if role in {"user", "human"} else Origin.AGENT
            level = Level.L2 if origin == Origin.USER else Level.L1
            for part in c.get("parts") or []:
                if isinstance(part, dict):
                    if "text" in part:
                        messages.append(
                            NormalizedMessage(role=role, origin=origin, level=level, content=part.get("text", ""))
                        )
                    elif "functionResponse" in part:
                        fr = part["functionResponse"]
                        content = fr.get("response", {})
                        text = content.get("content") if isinstance(content, dict) else str(content)
                        messages.append(
                            NormalizedMessage(
                                role="tool",
                                origin=Origin.TOOL,
                                level=Level.L0,
                                content=str(text or ""),
                                metadata={"tool_name": fr.get("name")},
                            )
                        )

        meta_keys = ("generationConfig", "model", "tools", "toolConfig", "safetySettings")
        metadata = {k: body[k] for k in meta_keys if k in body}

        ext = body.get("aegis", {}) or {}
        session_hint = ext.get("session_id")
        intent_hint = ext.get("user_intent")
        cap_tokens = list(ext.get("capability_tokens") or [])

        return NormalizedRequest(
            upstream=self.name,
            messages=messages,
            tools=list(body.get("tools") or []),
            metadata=metadata,
            session_id_hint=session_hint,
            user_intent_hint=intent_hint,
            capability_tokens=cap_tokens,
        )

    def render_request(self, body: dict[str, Any], req: NormalizedRequest) -> dict[str, Any]:
        out = dict(body)
        sys_msgs = [m.content for m in req.messages if m.origin == Origin.SYSTEM]
        if sys_msgs:
            out["systemInstruction"] = {"parts": [{"text": "\n\n".join(sys_msgs)}]}
        out.pop("aegis", None)
        return out

    def parse_response(self, body: dict[str, Any]) -> NormalizedResponse:
        text_chunks: list[str] = []
        tool_calls: list[NormalizedToolCall] = []
        for cand in body.get("candidates") or []:
            content = cand.get("content") or {}
            for part in content.get("parts") or []:
                if isinstance(part, dict):
                    if "text" in part:
                        text_chunks.append(part.get("text", ""))
                    elif "functionCall" in part:
                        fc = part["functionCall"]
                        params = dict(fc.get("args") or {})
                        tool_calls.append(
                            NormalizedToolCall(
                                tool=fc.get("name", ""),
                                parameters=params,
                                capability_token=params.pop("_aegis_capability", None),
                                raw=part,
                            )
                        )
        return NormalizedResponse(
            text="\n".join(text_chunks),
            tool_calls=tool_calls,
            raw=body,
            metadata={"model": body.get("modelVersion")},
        )


def get_adapter(name: str):
    name = name.lower()
    if name in {"anthropic", "claude"}:
        return AnthropicAdapter()
    if name in {"openai", "gpt"}:
        return OpenAIAdapter()
    if name in {"google", "gemini"}:
        return GoogleAdapter()
    raise ValueError(f"unknown upstream adapter: {name}")
