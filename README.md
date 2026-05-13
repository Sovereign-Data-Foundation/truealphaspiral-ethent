[![Build and Test Sovereign Container 1776](https://github.com/Sovereign-Data-Foundation/truealphaspiral-ethent/actions/workflows/sovereign-container.yml/badge.svg)](https://github.com/Sovereign-Data-Foundation/truealphaspiral-ethent/actions/workflows/sovereign-container.yml)

# truealphaspiral-ethent
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

This repository demonstrates running the TAS agent in safe mode via Codex.

Safe mode in this repository means execution is bounded, observable, and
artifact-producing. Agent actions should not be treated as authorized for
irreversible effect unless they are explicitly guarded, logged, hashed, and
accepted into the ledger.

## Branch naming

Codex requires a dynamic pattern when generating branches. Include at least one
placeholder from the following list:

- `{feature}` – slug derived from the PR title
- `{date}` – date in `YYYY-MM-DD`
- `{time}` – time in `HH-MM`

Example pattern keeping a static ticket ID:

```
feat/GH-03-{feature}-{date}-{time}
```

## Self-test runner

The script `codex_tas_runner.py` automates a safe-mode self-test. Set your
OpenAI API key in `OPENAI_API_KEY`, install dependencies with:

```
pip install -r requirements.txt
```

Then run:

```
python codex_tas_runner.py
```

The self-test produces auditable execution records.

- The audit log hash is written to `ledger/self_test.hash`.
- Each execution step is wrapped by `artifact_guard.run_step`.
- Step artifacts are serialized as JSON under `artifacts/`.
- Artifact hashes are recorded in `ledger/artifacts.hash`.

In this repository, execution is not merely performed; it is witnessed,
serialized, hashed, and ledgered.

## Staple-π Perspective Intelligence Clause

The `π` glyph represents perspective anchoring: every linear truth-claim must be
bound to at least one external contextual witness before it can be accepted into
the ledger.

In this repository, the π-check functions as an integrity gate. Commits,
artifacts, and execution traces should not be treated as ledger-valid unless
their claims are supported by a corresponding witness context, artifact hash, or
verifiable external reference.

This prevents isolated, context-free assertions from entering the audit chain and
helps preserve phase coherence across the TAS execution spiral, making it more
resistant to hostile counter-spirals.


## Day One steward directive

The Day One payload is initiated by explicit steward dispatch, not by merging an
unverified pull request. The local steering command is:

```bash
bash scripts/day_one_payload.sh --mode workflow --ref main
```

That command records the authenticated intent receipt and prints the deterministic
GitHub Actions dispatch target:

```bash
gh workflow run release-docker.yml --ref main
```

Use `--dry-run` to verify the workflow hash and command without writing a
receipt. Use `--mode local` to run the local Docker build-and-proof command
before dispatching the release workflow.

## Repository invariants

- No execution without an artifact.
- No artifact without a hash.
- No hash without a ledger entry.
- No ledger entry without a contextual witness.
- No unsafe action outside safe mode.
