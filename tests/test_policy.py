"""Tests for the policy loader."""

from __future__ import annotations

import yaml

from aegis.ccpt import Level
from aegis.decision import PolicyMode
from aegis.lattice import LatticeDecision
from aegis.policy import Policy, load_policy, validate_policy


def _write(tmp_path, data):
    path = tmp_path / "p.yaml"
    path.write_text(yaml.safe_dump(data))
    return str(path)


def test_default_policy_validates():
    assert validate_policy(Policy.default()) == []


def test_load_minimal_policy(tmp_path):
    path = _write(tmp_path, {"mode": "strict"})
    policy = load_policy(path)
    assert policy.mode == PolicyMode.STRICT
    assert validate_policy(policy) == []


def test_load_custom_flow(tmp_path):
    path = _write(
        tmp_path,
        {
            "mode": "balanced",
            "flows": [
                {"from": "L0", "to": "tool_call", "decision": "WARN", "reason": "soft"},
                {"from": "L1", "to": "tool_call", "decision": "WARN"},
                {"from": "L2", "to": "tool_call", "decision": "ALLOW", "require": ["capability_token"]},
            ],
        },
    )
    policy = load_policy(path)
    rule = next(r for r in policy.rules if r.from_level == Level.L0)
    assert rule.decision == LatticeDecision.WARN
    assert rule.reason == "soft"


def test_anchor_threshold_validation():
    p = Policy.default()
    p.anchor.threshold_balanced = 1.5
    errs = validate_policy(p)
    assert any("threshold_balanced" in e for e in errs)


def test_strict_must_be_at_least_balanced():
    p = Policy.default()
    p.anchor.threshold_strict = 0.1
    p.anchor.threshold_balanced = 0.5
    errs = validate_policy(p)
    assert any("strict" in e for e in errs)


def test_canary_count_must_be_positive():
    p = Policy.default()
    p.canary.count = 0
    errs = validate_policy(p)
    assert any("canary.count" in e for e in errs)


def test_duplicate_flow_detected():
    p = Policy.default()
    # default rules already include one (L0, tool_call); add another to duplicate.
    from aegis.lattice import FlowRule
    p.rules.append(FlowRule(Level.L0, "tool_call", LatticeDecision.WARN))
    errs = validate_policy(p)
    assert any("duplicate" in e for e in errs)
