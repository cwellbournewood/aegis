"""AEGIS — Authenticated Execution Gateway for Injection Security.

Open-source, model-agnostic prompt-injection defense gateway for LLM applications.

Five composed defense layers:
    1. CCPT  — Cryptographic Content Provenance Tags
    2. Lattice — Bell-LaPadula trust-level enforcement
    3. Anchor — Intent vector drift detection
    4. Canary — Decoy honeytoken tripwires
    5. Capability — Cryptographic tool-call authorization tokens
"""

from aegis.anchor import AnchorVector, IntentAnchor
from aegis.canary import CanaryGarden, CanaryHit
from aegis.capability import CapabilityMinter, CapabilityToken, ProposedCall
from aegis.ccpt import CCPTEnvelope, Level, Origin, strip, tag, verify
from aegis.decision import DecisionEngine, DecisionRecord, PolicyMode, Vote
from aegis.lattice import FlowRule, LatticeDecision, LatticeGate
from aegis.log import DecisionLog
from aegis.policy import Policy, load_policy
from aegis.session import Session, SessionStore

__version__ = "1.1.0"

__all__ = [
    "AnchorVector",
    "CCPTEnvelope",
    "CanaryGarden",
    "CanaryHit",
    "CapabilityMinter",
    "CapabilityToken",
    "DecisionEngine",
    "DecisionLog",
    "DecisionRecord",
    "FlowRule",
    "IntentAnchor",
    "LatticeDecision",
    "LatticeGate",
    "Level",
    "Origin",
    "Policy",
    "PolicyMode",
    "ProposedCall",
    "Session",
    "SessionStore",
    "Vote",
    "__version__",
    "load_policy",
    "strip",
    "tag",
    "verify",
]
