"""Adversarial benchmark corpus + harness.

Lives inside the package so `aegis bench` works after `pip install`. The
corpus.json file is shipped as package data; the loader finds it relative to
this module.

Tests in `tests/adversarial/` import from here so there is exactly one source
of truth.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Optional

from aegis.ccpt import Level, Origin
from aegis.decision import PolicyMode
from aegis.policy import Policy
from aegis.proxy.orchestrator import (
    NormalizedMessage,
    NormalizedRequest,
    NormalizedResponse,
    NormalizedToolCall,
    Orchestrator,
)


@dataclass
class Case:
    id: str
    category: str
    description: str
    request: dict[str, Any]
    model_response: dict[str, Any]
    expected: str
    notes: str = ""


def default_corpus_path() -> str:
    return os.path.join(os.path.dirname(__file__), "corpus.json")


def load_corpus(path: Optional[str] = None) -> list[Case]:
    if path is None:
        path = default_corpus_path()
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    cases = []
    for c in data.get("cases", []):
        cases.append(
            Case(
                id=c["id"],
                category=c["category"],
                description=c.get("description", ""),
                request=c["request"],
                model_response=c["model_response"],
                expected=c["expected"],
                notes=c.get("notes", ""),
            )
        )
    return cases


def _build_request(case: Case) -> NormalizedRequest:
    req_data = case.request
    msgs = []
    for m in req_data.get("messages", []):
        msgs.append(
            NormalizedMessage(
                role=m.get("role", "user"),
                origin=Origin(m["origin"]),
                level=Level(m["level"]) if m.get("level") else None,
                content=m["content"],
            )
        )
    return NormalizedRequest(
        upstream="anthropic",
        messages=msgs,
        user_intent_hint=req_data.get("user_intent"),
    )


def _build_response(case: Case, canary_token: Optional[str]) -> NormalizedResponse:
    rd = case.model_response
    text = rd.get("text", "")
    if rd.get("text_uses_canary") and canary_token and "<CANARY>" in text:
        text = text.replace("<CANARY>", canary_token)
    tcs = []
    for c in rd.get("tool_calls", []):
        params = dict(c.get("parameters", {}) or {})
        tcs.append(
            NormalizedToolCall(
                tool=c["tool"],
                parameters=params,
                summary=c.get("summary"),
            )
        )
    return NormalizedResponse(text=text, tool_calls=tcs)


def run_benchmark(cases: list[Case], mode: str = "balanced") -> dict[str, Any]:
    policy = Policy.default()
    policy.mode = PolicyMode(mode)
    policy.log_path = None
    orch = Orchestrator(policy=policy)

    categories: dict[str, dict[str, int]] = {}
    overall = {"attempts": 0, "allowed": 0, "warned": 0, "blocked": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0}
    per_case: list[dict[str, Any]] = []

    for case in cases:
        cat_stats = categories.setdefault(case.category, {"attempts": 0, "allowed": 0, "warned": 0, "blocked": 0})

        req = _build_request(case)
        augmented, ctx = orch.pre_flight(req)

        mint = case.request.get("mint_capability")
        capability_token_raw: Optional[str] = None
        if mint:
            tok = orch.minter.mint(
                tool=mint["tool"],
                session_id=ctx.session.session_id,
                session_key=ctx.session.hmac_key,
            )
            capability_token_raw = tok.raw

        canary_token = ctx.session.canaries.canaries[0].token if ctx.session.canaries else None
        resp = _build_response(case, canary_token)

        if capability_token_raw:
            for tc in resp.tool_calls:
                rd_tcs = case.model_response.get("tool_calls", [])
                idx = resp.tool_calls.index(tc)
                if idx < len(rd_tcs) and rd_tcs[idx].get("use_minted_capability"):
                    tc.capability_token = capability_token_raw

        record = orch.post_flight(augmented, resp, ctx)

        actual = record.decision.value
        cat_stats["attempts"] += 1
        overall["attempts"] += 1
        if actual == "BLOCK":
            cat_stats["blocked"] += 1
            overall["blocked"] += 1
        elif actual == "WARN":
            cat_stats["warned"] += 1
            overall["warned"] += 1
        else:
            cat_stats["allowed"] += 1
            overall["allowed"] += 1

        is_attack = case.expected == "BLOCK"
        is_caught = actual in ("BLOCK", "WARN")
        if is_attack and is_caught:
            overall["tp"] += 1
        elif is_attack and not is_caught:
            overall["fn"] += 1
        elif (not is_attack) and not is_caught:
            overall["tn"] += 1
        else:
            overall["fp"] += 1

        per_case.append(
            {
                "id": case.id,
                "category": case.category,
                "expected": case.expected,
                "actual": actual,
                "reason": record.reason,
                "score": record.score,
            }
        )

    return {
        "mode": mode,
        "total_cases": len(cases),
        "categories": categories,
        "overall": overall,
        "cases": per_case,
    }
