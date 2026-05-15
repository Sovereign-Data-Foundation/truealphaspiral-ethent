# Press Release: TrueAlphaSpiral EthEnt Strengthens Replay Security and Deterministic Auditability

**Date:** May 15, 2026  
**Repository:** `Sovereign-Data-Foundation/truealphaspiral-ethent`  
**Release Type:** Security hardening / auditability update  
**Related Pull Request:** PR #30 — `Fix replay security vulnerabilities and address PR #24 review feedback`

## Summary

The Sovereign Data Foundation has merged PR #30 into the `truealphaspiral-ethent` codebase, strengthening the Human API Bridge replay path against receipt substitution, negative-index bypass behavior, and non-deterministic audit replay drift.

This update reinforces the project’s core operating principle: execution must remain receipt-bearing, bounded, reproducible, and traceable. The merged change converts review feedback from PR #24 into concrete replay-security corrections and deterministic lineage improvements.

## What Changed

PR #30 addresses two replay vulnerabilities and one determinism issue:

1. **Event-hash binding for replay receipts**  
   Replay validation now reconstructs the expected event from receipt fields and verifies that it matches the recorded provenance event hash. This prevents a forged receipt from substituting an unauthorized command while reusing an otherwise valid wake receipt hash.

2. **Negative wake-sequence rejection**  
   The replay path now rejects negative `wake_seq` values before indexing wake receipts, closing the Python negative-index bypass class.

3. **Narrower exception handling in decision flow**  
   Broad exception handling was narrowed so implementation bugs are not silently converted into refusal receipts. This preserves refusal integrity while avoiding accidental masking of defects.

4. **Deterministic Day One bridge construction**  
   `build_day_one_bridge()` now supports deterministic replay through an optional fixed `issued_at_utc` value, improving reproducibility across audit sessions.

5. **Test coverage added or updated**  
   New tests cover forged command-hash replay rejection, negative wake-sequence rejection, and deterministic Day One bridge construction.

## Why It Matters

Replay security is not only a conventional software hardening concern in this repository. It is part of the larger TAS/SDF design requirement that authenticated execution must be reconstructible after the fact.

A receipt is only meaningful if it remains bound to the event it claims to describe. PR #30 strengthens that binding by ensuring replay validation checks the event hash relationship rather than trusting isolated receipt fields.

This reinforces the operational doctrine:

> No valid lineage, no admissible replay.  
> No reproducible event path, no trustworthy execution.

## Traceability and ITL Lineage

This release is anchored to the post-merge checklist artifact committed after PR #30 merged.

- **PR:** #30
- **PR head SHA:** `64796705eb267e316704f1bbba0facc76a77099d`
- **Merge commit / child hash:** `64205c0cb4ca1cd8c6bcaa9eefe9f62f6372b5fe`
- **Parent hash:** `fc99db7e72aae673f53e5578085357d703652cc9`
- **Checklist artifact:** `artifacts/artifact-pr-30-checklist.json`
- **Checklist artifact commit:** `5c29a410590c9a1ea4122aa8b4889ff16a5e105f`
- **Checklist artifact SHA-256:** `3bd3495b3f95ad367da0216983974228b8e946abf157b50ed916af2f1c7f5415`

## Security Posture

This release improves replay-path integrity by closing two concrete replay bypass classes and by reducing the risk that implementation errors are misclassified as governed refusals.

The result is a stronger distinction between:

- valid refusal artifacts,
- invalid replay attempts,
- implementation defects, and
- deterministic audit evidence.

## Closing Statement

PR #30 is a practical step toward authenticated intelligence infrastructure: not merely producing outputs, but preserving the process by which outputs become verifiable, replayable, and accountable.

The product is the artifact.  
The process is the proof.
