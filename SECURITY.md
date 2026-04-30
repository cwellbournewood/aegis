# Security Policy

## Reporting a vulnerability

Please **do not** file public GitHub issues for security vulnerabilities.

Instead, open a **[private GitHub Security Advisory](https://github.com/cwellbournewood/aegis/security/advisories/new)** on this repository.

We will acknowledge within **72 hours** and aim to ship a fix or coordinated mitigation within **14 days** for high-severity issues.

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

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0  | No |

We support the most recent minor release with security fixes for at least 6 months after a successor minor lands.

## Crypto and dependencies

AEGIS uses vetted libraries (`cryptography`, Python stdlib `hmac` / `secrets` / `hashlib`). No custom cryptographic primitives. Dependencies are pinned in `pyproject.toml` and reviewed before bumping.

## Acknowledgements

Reporters who follow this policy in good faith will be credited (with permission) in the release notes for the fixing version.
