"""AEGIS Python SDK.

A thin client over the proxy's AEGIS-native endpoints — for minting capability
tokens, creating sessions, and consuming the typed decision objects attached
to LLM responses.
"""

from aegis.sdk.client import AegisClient, CapabilityHandle, SessionHandle
from aegis.sdk.decision import (
    AegisDecision,
    AegisDecisionBlocked,
    AegisVote,
    AegisWarning,
    attach_decision,
)

__all__ = [
    "AegisClient",
    "AegisDecision",
    "AegisDecisionBlocked",
    "AegisVote",
    "AegisWarning",
    "CapabilityHandle",
    "SessionHandle",
    "attach_decision",
]
