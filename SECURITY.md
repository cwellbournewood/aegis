# Security Policy

## Reporting a vulnerability

Please **do not** file public GitHub issues for security vulnerabilities.

Instead, open a **[private GitHub Security Advisory](https://github.com/cwellbournewood/aegis/security/advisories/new)** on this repository.

This is a community-maintained project. There is no SLA on triage or fix turnaround — reports are handled on a best-effort basis. If timely vendor support is critical for your use case, fork the repository and run your own audit/maintenance cadence.

## Scope

Issues in scope:

- Bypass of any of the five defense layers (CCPT, Lattice, Anchor, Canary, Capability)
- Cryptographic weaknesses in HMAC, HKDF, or token signing
- Tampering with the decision log without detection
- Privilege escalation via the proxy's own API
- Authentication / authorization issues on AEGIS-native endpoints

Issues out of scope (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for full list):

- Jailbreaks targeting model alignment (DAN-style)
- Vulnerabilities requiring `AEGIS_MASTER_KEY` compromise
- Denial-of-service at the network layer (handle via your reverse proxy)
- Issues in upstream LLM provider APIs

## Crypto and dependencies

AEGIS uses vetted libraries (`cryptography`, Python stdlib `hmac` / `secrets` / `hashlib`). No custom cryptographic primitives. Dependencies are pinned in `pyproject.toml`.

## Acknowledgements

Reporters who follow this policy in good faith may be credited (with permission) in the release notes for the fixing version.
