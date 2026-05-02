"""AEGIS sidecar proxy.

The proxy speaks the native wire format of each upstream LLM provider, runs
every request through the five-layer decision pipeline, and forwards or
blocks based on the combined verdict.
"""

from aegis.proxy.app import create_app
from aegis.proxy.orchestrator import Orchestrator, ProxyContext

__all__ = ["Orchestrator", "ProxyContext", "create_app"]
