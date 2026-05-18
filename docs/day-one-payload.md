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
  `.github/workflows/release-docker.yaml` is available. It runs automatically on
  pull requests and can also be dispatched manually.
- The receipt emitter is `scripts/day_one_gate.py`; it emits a Wake/UVK-backed
  receipt before the workflow gate proceeds. That receipt now carries the five
  path-sensitive admissibility gates: novelty, acquisition trace, bounded
  efficiency, interface provenance, and constructive refusal.
- The same receipt also carries a maxims-of-law proof layer. Each maxim proof is
  hashed into the receipt so the workflow can demonstrate consent, clean hands,
  commercial truth, remedy, bounded non-recklessness, and refusal where proof is
  absent without storing raw sensitive proof text.

## Fail-closed invariants

The Day One gate must stop on any of the following conditions:

1. missing Day One receipt;
2. failed receipt invariant;
3. failed workflow step;
4. missing sovereign-intent proof;
5. requested head SHA that differs from the active checked-out head;
6. a request for `release-docker.yaml` before that workflow exists;
7. missing novelty assertion;
8. missing acquisition trace;
9. declared search steps outside the bounded efficiency limit;
10. missing interface provenance;
11. a constructive refusal basis that says execution is inadmissible; or
12. a missing maxims-of-law proof for any required legal-equity maxim.

## Exact Day One steering command

Paste this into the active agent session:

```text
Day One payload: proceed under PR #158's merged directive. Treat PR #106 as historical substrate only. Resolve the active head SHA with `git rev-parse HEAD`. Emit the Day One receipt first with `python scripts/day_one_gate.py emit --head-sha <ACTIVE_HEAD_SHA> --workflow-name blank.yml --sovereign-intent-proof "PR #158 merged Day One directive" --receipt-path receipts/day-one-receipt.json`, then verify it with `python scripts/day_one_gate.py verify --head-sha <ACTIVE_HEAD_SHA> --workflow-name blank.yml --receipt-path receipts/day-one-receipt.json`. Only after that receipt verifies, dispatch `blank.yml` against the same active head SHA with the same sovereign-intent proof. Fail closed on any missing receipt, failed invariant, failed workflow, missing sovereign-intent proof, failed path-sensitive gate, or failed maxims-of-law proof. Do not use `release-docker.yaml` until it exists in `.github/workflows/`.
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
ACTIVE_REF="$(git branch --show-current)"
gh workflow run blank.yml \
  --ref "$ACTIVE_REF" \
  -f head_sha="$ACTIVE_HEAD_SHA" \
  -f sovereign_intent_proof="PR #158 merged Day One directive"
```

## Maxims-of-law proof overrides

The emitter supplies deterministic default proof text for each required maxim.
If a steward needs to bind a stronger local proof, pass one or more overrides:

```bash
python scripts/day_one_gate.py emit \
  --head-sha "$ACTIVE_HEAD_SHA" \
  --workflow-name blank.yml \
  --sovereign-intent-proof "PR #158 merged Day One directive" \
  --maxim-proof clean_hands="receipt emitted before workflow relief" \
  --maxim-proof truth_sovereign="claims bound to receipt hash" \
  --receipt-path receipts/day-one-receipt.json
```

A blank maxim proof is a denial condition, not a warning.

## Operational decision

The Day One payload now points at the receipt-first deterministic workflow gate.
The gate uses `blank.yml` as the temporary dispatch surface, while
`release-docker.yaml` remains a future replacement once it is present and
reviewed. Pull requests run the same receipt-first gate automatically with the
PR head SHA as the active proof target.
