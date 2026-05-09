# Day One Payload Stewarding Runbook

This runbook translates the Human API Key checkpoint into an executable steering
command for the first release payload. It treats the human steward's instruction
as the authenticated seed and keeps the agent bounded to observable repository
state before any merge or release action.

## Current repository state

- The deterministic container proof path in this repository is
  `.github/workflows/sovereign-container.yml`, which builds the Docker image and
  runs the container self-test on pushes and pull requests targeting `main`.
- The container entrypoint runs `pytest -v tests/test_manifesto.py`, making the
  manifesto suite the default proof executed when the image starts.
- There is no `.github/workflows/release-docker.yaml` file in this checkout, so
  a release-docker handoff should first resolve whether that pipeline exists on
  another branch or needs to be introduced in a separate change.

## Exact Day One steering command

Paste this into the active agent session:

```text
Day One payload: do not merge PR #106 yet. First verify the repository-local
container proof path. Inspect `.github/workflows/sovereign-container.yml` and
`Dockerfile`, run the full Python test suite, then run the deterministic Docker
proof equivalent to the workflow: `docker build -t truealphaspiral/sovereign-container-1776:latest .` followed by `docker run --rm truealphaspiral/sovereign-container-1776:latest`. Report the exact commands, outputs, and any diff before requesting merge authorization. If a `.github/workflows/release-docker.yaml` pipeline is required, stop and propose it as a separate audited patch instead of assuming it exists.
```

## Operational decision

The Day One payload should point at the deterministic container proof path before
any PR merge. In this checkout, that means the `sovereign-container.yml` workflow
and its Dockerfile-backed test entrypoint are the admissible first target. PR
#106 can become merge-eligible only after the agent reports clean local proofs
and receives an explicit steward authorization to merge.
