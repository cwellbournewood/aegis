"""AEGIS quickstart — full request lifecycle in one file.

Usage:
    # Terminal A:
    export AEGIS_MASTER_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
    export AEGIS_DRY_RUN=1
    aegis up

    # Terminal B:
    python examples/quickstart.py
"""

from __future__ import annotations

import os

from aegis.sdk import AegisClient


def main() -> None:
    aegis = AegisClient(base_url=os.environ.get("AEGIS_URL", "http://localhost:8080"))

    print("→ AEGIS health:", aegis.health()["status"])

    session = aegis.session.create(
        upstream="anthropic",
        user_intent="summarize my latest invoice email",
    )
    print(f"→ Created session {session.session_id}")
    print(f"  proxy URL: {session.proxy_url}")
    print(f"  canaries: {session.canary_count}")

    cap = session.capabilities.mint(
        "read_email",
        constraints={"folder": {"kind": "eq", "value": "inbox"}, "limit": {"kind": "max_len", "value": 5}},
    )
    print(f"→ Minted capability for read_email (nonce {cap.nonce[:8]}...)")

    print("→ Tokens to attach to your LLM request body's `aegis.capability_tokens`:")
    print(f"   {session.capability_tokens()}")

    print("\nNow point your Anthropic / OpenAI / Google client at:")
    print(f"   {session.proxy_url}")
    print("And include in the request body:")
    print(
        '   "aegis": {"session_id": "%s", "capability_tokens": [%d token(s)]}'
        % (session.session_id, len(session.capability_tokens()))
    )


if __name__ == "__main__":
    main()
