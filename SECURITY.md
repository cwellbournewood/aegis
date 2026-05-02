# Security Policy

AEGIS is a security tool. Vulnerabilities in AEGIS itself can undermine the protections it provides to applications that depend on it. Please report them privately.

## Reporting a vulnerability

**Preferred:** open a private security advisory at
<https://github.com/cwellbournewood/aegis/security/advisories/new>.

**Backup:** email <cwellbournewood@gmail.com> with subject line `AEGIS security report`.

Please include:

- A description of the issue and the affected component (CCPT, lattice, anchor, canary, capability, decision engine, log, proxy, SDK).
- A minimal reproduction (proof-of-concept request, policy YAML, or test case).
- Versions affected (`aegis-guard` package version, container tag, or commit SHA).
- Your assessment of impact and severity.

## What to expect

This is a personal open-source project, not a commercial product. There is no SLA. As a rough good-faith target:

- Acknowledgement: within 7 days.
- Initial triage and severity assessment: within 14 days.
- Fix or mitigation timeline communicated once triage is complete.

If a report is accepted, you'll be credited in the release notes for the fixing version unless you prefer otherwise.

## Scope

In scope:

- Bypasses of any of the five layers (CCPT, lattice, anchor, canary, capability) on a default or recommended policy.
- Forgery, replay, or unauthorized minting of capability tokens or CCPT envelopes.
- Decision-log integrity failures (hash chain skips, tip-pointer races, log truncation undetected by `aegis verify`).
- Side-channel leaks of master key, per-session keys, or canary tokens through the proxy or SDK surfaces.
- Memory-safety or DoS issues in the proxy under documented load.

Out of scope:

- Issues that require already-compromised application code (e.g., the application minting a wildcard capability token defeats the capability layer; this is documented).
- Findings against custom policies that disable layers (`mode: permissive`, `canary.enabled: false`, etc.).
- Probabilistic-layer false positives or negatives within documented limits (drift detection, canary attrition).
- Findings against the `[embed]` extra's third-party model weights — please report those upstream.

## Supported versions

Only the latest released version on `main` receives security fixes. Pin a specific tag or commit in production; minor versions may include security-relevant changes.

## Disclosure

Coordinated disclosure preferred. Default embargo of 90 days from acknowledgement, negotiable. Public disclosure happens via a GitHub Security Advisory and a CHANGELOG entry on the fixing release.
