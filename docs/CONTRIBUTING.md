# Contributing to AEGIS

AEGIS welcomes contributions. This document covers what we look for, the evaluation criteria from the RFP, and how to land a change.

## Ground rules

- AEGIS is **defense-in-depth**. New features should not weaken the property that any single layer's failure is recoverable.
- AEGIS is **model-agnostic**. Anything provider-specific lives behind the adapter interface.
- AEGIS is **forkable**. No proprietary dependencies, vetted crypto, exhaustive tests.
- AEGIS is **honest about limits**. Document what your contribution does *and what it doesn't*.

## Evaluation criteria for PRs

Lifted directly from the RFP:

| Criterion | Weight |
|---|---|
| Demonstrably reduces attack success on the adversarial corpus | 30% |
| Stays within performance budget (<150 ms p50, <15% token overhead) | 20% |
| Code quality, test coverage, documentation | 20% |
| Composes cleanly with existing layers (no tight coupling) | 15% |
| Operator ergonomics (deployment, debuggability, observability) | 15% |

Bonus: contributions that *expand the adversarial corpus* with novel attacks are highly valued.

## Local development

```bash
git clone https://github.com/aegis-guard/aegis
cd aegis
python -m venv .venv && source .venv/bin/activate     # or .venv\Scripts\activate on Windows
pip install -e '.[test,dev]'
pytest
```

Run the proxy locally:

```bash
export AEGIS_MASTER_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export AEGIS_DRY_RUN=1   # don't forward upstream while you iterate
aegis up --reload
```

Run the adversarial benchmark:

```bash
aegis bench --mode balanced
```

## Code style

```bash
ruff check .
ruff format .
mypy aegis
```

We don't ship without `pytest -q` green and `ruff check .` clean.

## Tests

- Unit tests live in `tests/` mirroring the module layout.
- Adversarial corpus tests live in `tests/adversarial/`.
- Integration tests against live providers are gated by `pytest -m live`.

If you add a defense layer, you must also add:

1. Unit tests for the layer in isolation
2. Integration tests showing the layer composes with the orchestrator
3. At least one new corpus case demonstrating an attack the layer catches

## Adding a provider

1. Implement an adapter in `aegis/proxy/adapters.py` with `parse_request`, `render_request`, `parse_response`.
2. Add a route in `aegis/proxy/app.py`.
3. Add adapter tests in `tests/test_adapters.py`.
4. Update the supported-providers table in `README.md`.

## Adding a constraint kind

1. Add the new kind to `ConstraintKind` enum in `aegis/capability.py`.
2. Implement the check in `ParamConstraint.check`.
3. Wire it through `aegis/proxy/app.py` `mint_capability` endpoint.
4. Add a unit test in `tests/test_capability.py` covering match + no-match cases.

## RFC process (for breaking changes)

For changes that:

- Alter the CCPT envelope format
- Change the capability token format
- Modify the default policy
- Add or remove trust levels

…open a discussion as `[RFC] <title>` in GitHub Issues *before* opening a PR. Tag the maintainers. RFCs typically sit for 7–14 days for community review.

## Commit messages

Conventional Commits, lightly applied:

```
feat(capability): add prefix constraint kind

Adds ConstraintKind.PREFIX so capability tokens can require
parameter values to start with a specific prefix. Useful for
path-restriction on filesystem or HTTP tools.
```

## Reporting security issues

**Do not file public issues for security bugs.** See [THREAT_MODEL.md §9](THREAT_MODEL.md).

## Governance

Until v1.5, AEGIS is a single-maintainer project with public RFCs. Post-v1.5 we will move to a two-maintainer model with explicit committers. Contributors who land 3+ non-trivial PRs are invited to commit privileges.
