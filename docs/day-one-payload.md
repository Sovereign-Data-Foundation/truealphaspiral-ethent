# Day One Payload Stewarding Runbook

This runbook implements PR #158's merged Day One directive. PR #106 is now
historical substrate only: it can inform context, but it is not the active
execution target. The active target is receipt-first dispatch of the deterministic
workflow gate against the current head SHA.

## Current repository state

- The deterministic container proof path in this repository is
  `.github/workflows/sovereign-container.yml`, which builds the Docker image and
  runs the container self-test on pushes and pull requests targeting `main`.
- The temporary Day One dispatch target is `.github/workflows/blank.yml` until
  `.github/workflows/release-docker.yaml` is available.
- The receipt emitter is `scripts/day_one_gate.py`; it emits a Wake/UVK-backed
  receipt before the workflow gate proceeds.

## Fail-closed invariants

The Day One gate must stop on any of the following conditions:

1. missing Day One receipt;
2. failed receipt invariant;
3. failed workflow step;
4. missing sovereign-intent proof;
5. requested head SHA that differs from the active checked-out head; or
6. a request for `release-docker.yaml` before that workflow exists.

## Exact Day One steering command

Paste this into the active agent session:

```text
Day One payload: proceed under PR #158's merged directive. Treat PR #106 as historical substrate only. Resolve the active head SHA with `git rev-parse HEAD`. Emit the Day One receipt first with `python scripts/day_one_gate.py emit --head-sha <ACTIVE_HEAD_SHA> --workflow-name blank.yml --sovereign-intent-proof "PR #158 merged Day One directive" --receipt-path receipts/day-one-receipt.json`, then verify it with `python scripts/day_one_gate.py verify --head-sha <ACTIVE_HEAD_SHA> --workflow-name blank.yml --receipt-path receipts/day-one-receipt.json`. Only after that receipt verifies, dispatch `blank.yml` against the same active head SHA with the same sovereign-intent proof. Fail closed on any missing receipt, failed invariant, failed workflow, or missing sovereign-intent proof. Do not use `release-docker.yaml` until it exists in `.github/workflows/`.
```

## GitHub dispatch form

Until `release-docker.yaml` is introduced, dispatch the fallback workflow:

```bash
ACTIVE_HEAD_SHA="$(git rev-parse HEAD)"
python scripts/day_one_gate.py emit \
  --head-sha "$ACTIVE_HEAD_SHA" \
  --workflow-name blank.yml \
  --sovereign-intent-proof "PR #158 merged Day One directive" \
  --receipt-path receipts/day-one-receipt.json
python scripts/day_one_gate.py verify \
  --head-sha "$ACTIVE_HEAD_SHA" \
  --workflow-name blank.yml \
  --receipt-path receipts/day-one-receipt.json
gh workflow run blank.yml \
  --ref "$ACTIVE_HEAD_SHA" \
  -f head_sha="$ACTIVE_HEAD_SHA" \
  -f sovereign_intent_proof="PR #158 merged Day One directive"
```

## Operational decision

The Day One payload now points at the receipt-first deterministic workflow gate.
The gate uses `blank.yml` as the temporary dispatch surface, while
`release-docker.yaml` remains a future replacement once it is present and
reviewed.
