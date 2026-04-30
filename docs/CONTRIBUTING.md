# Contributing

## Ground rules

- **Defense in depth.** New features must not weaken the property that any single layer's failure is recoverable.
- **Model-agnostic.** Provider-specific code lives behind the adapter interface.
- **Forkable.** No proprietary dependencies, vetted crypto, exhaustive tests.

## PR evaluation

| Criterion | Weight |
|---|---|
| Demonstrably reduces attack success on the adversarial corpus | 30% |
| Stays within performance budget (<150 ms p50, <15% token overhead) | 20% |
| Code quality, test coverage, documentation | 20% |
| Composes cleanly with existing layers | 15% |
| Operator ergonomics | 15% |

Contributions that expand the adversarial corpus with novel attacks are especially valued.

## Local development

```bash
git clone https://github.com/cwellbournewood/aegis
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

`pytest -q` green and `ruff check .` clean are required to merge.

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

…open a discussion as `[RFC] <title>` in GitHub Issues *before* opening a PR. Allow time for community review before merging.

## Commit messages

Conventional Commits, lightly applied:

```
feat(capability): add prefix constraint kind

Adds ConstraintKind.PREFIX so capability tokens can require
parameter values to start with a specific prefix. Useful for
path-restriction on filesystem or HTTP tools.
```

## Security issues

Do not file public issues for security bugs. See [SECURITY.md](../SECURITY.md).

## Governance

Community-maintained with public RFCs for breaking changes. No SLA on PR review.
