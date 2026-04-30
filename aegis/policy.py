"""Policy loading from YAML.

Policies declare:
    - decision engine mode (strict / balanced / permissive)
    - lattice flow rules
    - intent anchor thresholds & embedder config
    - canary count
    - capability defaults (TTL, single_use)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml

from aegis.ccpt import Level
from aegis.decision import PolicyMode
from aegis.lattice import FlowRule, LatticeDecision, default_rules


@dataclass
class AnchorConfig:
    threshold_balanced: float = 0.22
    threshold_strict: float = 0.40
    embedder: dict[str, Any] = field(default_factory=lambda: {"kind": "hashing", "dim": 384})
    refresh: str = "session"  # "session" | "turn" | "explicit"


@dataclass
class CanaryConfig:
    enabled: bool = True
    count: int = 3


@dataclass
class CapabilityConfig:
    default_ttl_seconds: int = 600
    require_for_levels: tuple[str, ...] = ("L2", "L3")


@dataclass
class Policy:
    mode: PolicyMode = PolicyMode.BALANCED
    rules: list[FlowRule] = field(default_factory=default_rules)
    anchor: AnchorConfig = field(default_factory=AnchorConfig)
    canary: CanaryConfig = field(default_factory=CanaryConfig)
    capability: CapabilityConfig = field(default_factory=CapabilityConfig)
    log_path: str | None = None
    session_ttl_seconds: int = 60 * 60 * 12

    @classmethod
    def default(cls) -> Policy:
        return cls()


def _parse_rule(d: dict[str, Any]) -> FlowRule:
    return FlowRule(
        from_level=Level(d["from"]) if str(d["from"]).startswith("L") else Level("L" + str(d["from"])),
        to=str(d["to"]),
        decision=LatticeDecision(d["decision"]),
        require=tuple(d.get("require", []) or ()),
        reason=str(d.get("reason", "")),
    )


def load_policy(path: str) -> Policy:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    return _policy_from_dict(data)


def _policy_from_dict(data: dict[str, Any]) -> Policy:
    mode = PolicyMode(data.get("mode", "balanced"))

    rules = [_parse_rule(r) for r in data["flows"]] if data.get("flows") else default_rules()

    anchor_data = data.get("anchor", {}) or {}
    anchor = AnchorConfig(
        threshold_balanced=float(anchor_data.get("threshold_balanced", 0.22)),
        threshold_strict=float(anchor_data.get("threshold_strict", 0.40)),
        embedder=anchor_data.get("embedder") or {"kind": "hashing", "dim": 384},
        refresh=str(anchor_data.get("refresh", "session")),
    )

    canary_data = data.get("canary", {}) or {}
    canary = CanaryConfig(
        enabled=bool(canary_data.get("enabled", True)),
        count=int(canary_data.get("count", 3)),
    )

    cap_data = data.get("capability", {}) or {}
    capability = CapabilityConfig(
        default_ttl_seconds=int(cap_data.get("default_ttl_seconds", 600)),
        require_for_levels=tuple(cap_data.get("require_for_levels", ["L2", "L3"]) or []),
    )

    return Policy(
        mode=mode,
        rules=rules,
        anchor=anchor,
        canary=canary,
        capability=capability,
        log_path=data.get("log_path"),
        session_ttl_seconds=int(data.get("session_ttl_seconds", 60 * 60 * 12)),
    )


def load_policy_from_env_or_default() -> Policy:
    path = os.environ.get("AEGIS_POLICY_PATH")
    if path and os.path.exists(path):
        return load_policy(path)
    builtin = os.path.join(os.path.dirname(__file__), "policies", "default.yaml")
    if os.path.exists(builtin):
        return load_policy(builtin)
    return Policy.default()


def validate_policy(policy: Policy) -> list[str]:
    """Return a list of validation errors (empty list = valid)."""
    errors: list[str] = []

    if policy.anchor.threshold_balanced < 0 or policy.anchor.threshold_balanced > 1:
        errors.append("anchor.threshold_balanced must be in [0, 1]")
    if policy.anchor.threshold_strict < 0 or policy.anchor.threshold_strict > 1:
        errors.append("anchor.threshold_strict must be in [0, 1]")
    if policy.anchor.threshold_strict < policy.anchor.threshold_balanced:
        errors.append("anchor.threshold_strict must be >= threshold_balanced")
    if policy.canary.count < 1:
        errors.append("canary.count must be >= 1")
    if policy.capability.default_ttl_seconds < 1:
        errors.append("capability.default_ttl_seconds must be >= 1")

    seen_keys: set[tuple[str, str]] = set()
    for rule in policy.rules:
        key = (rule.from_level.value, rule.to)
        if key in seen_keys:
            errors.append(f"duplicate flow rule: from={rule.from_level.value} to={rule.to}")
        seen_keys.add(key)

    return errors
