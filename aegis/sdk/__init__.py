"""AEGIS Python SDK.

A thin client over the proxy's AEGIS-native endpoints — for minting capability
tokens and creating sessions before issuing LLM calls.
"""

from aegis.sdk.client import AegisClient, CapabilityHandle, SessionHandle

__all__ = ["AegisClient", "CapabilityHandle", "SessionHandle"]
