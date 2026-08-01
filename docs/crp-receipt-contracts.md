# Canonical Readiness Protocol Receipt Contracts

## Status and order of operations

This document makes the payload shape normative for `tas.crp.receipt.v1` and
`tas.crp.migration.v1`. It intentionally precedes verifier implementation. The
schemas constrain representation; the semantic rules below constrain meaning.

Signature input is the UTF-8 encoding of the payload after JSON Canonicalization
Scheme (RFC 8785) serialization. A proof is detached because a signature cannot
be a member of the value that it signs. The OpenAPI component `DetachedProof`
defines the transport form. Implementations MUST reject duplicate JSON member
names, values not admitted by I-JSON/RFC 8785, unknown members, unresolved schema
references, and non-canonical payload bytes.

## Completion receipts

The normative schema is [`tas.crp.receipt.v1.schema.json`](../schemas/tas.crp.receipt.v1.schema.json).
A completion receipt commits to exactly one gate evaluation, its complete
evidence set, the evaluated scope, verifier implementation, authority snapshot,
and predecessor. Gate 1 has no predecessor. Gates 2 through 4 MUST identify the
digest of the immediately preceding, valid PASS receipt under the same
`protocol_id`, `protocol_version`, and `scope_digest`.

Receipt evaluation MUST apply this fail-closed order:

1. Require exact schema, protocol identity, and supported semantic version.
2. Recompute `sha256:` plus the lowercase SHA-256 hex digest of the canonical
   payload and compare it with `DetachedProof.payload_digest`, then verify the
   Ed25519 signature using the proof's `key_id`.
3. Establish historical validity at `evaluated_at`: the key MUST have been
   authorized for the evaluator and gate, `evaluated_at` MUST be on or after
   `key_valid_from` and before `key_valid_until` when an end exists, and the
   signed authority snapshot MUST agree with the authoritative snapshot digest.
4. Establish current effectiveness independently. Revocation does not rewrite a
   historically valid receipt, but policy MAY make that receipt ineffective for
   a new decision. An evaluator MUST report historical validity and current
   effectiveness separately.
5. Resolve the unique predecessor chain without gaps or forks to the current
   head for the exact protocol version and scope.
6. Derive state: a current FAIL head is `BLOCKED`; no Gate 1 head is
   `NOT_EVALUATED`; a PASS head at Gates 1–3 is `IN_PROGRESS`; only a PASS Gate 4
   head is `IOC_READY`.

`status_checked_at` records when the authority registry was consulted. It MUST
not be earlier than `evaluated_at`. A receipt producer MUST use a unique
`receipt_id`, include at least one evidence digest, and reject ambiguous evidence
names. These cross-field and registry rules are verifier obligations rather than
claims that JSON Schema alone can prove.

## Migration receipts and version isolation

The normative schema is [`tas.crp.migration.v1.schema.json`](../schemas/tas.crp.migration.v1.schema.json).
`source_version` and `target_version` MUST differ. A migration result is PASS if
and only if every required target-version invariant is present exactly once and
has a PASS attestation. The verifier MUST resolve `source_head_digest` to the
unique effective source head and MUST recompute `target_scope_digest` under the
target version's semantics.

A valid PASS migration receipt establishes the imported head from which target
version evaluation may proceed. A missing, invalid, untrusted, ambiguous, or
FAIL migration establishes no target head; the target version therefore derives
`NOT_EVALUATED`. Source receipts remain historical records and never become
target-version receipts by inheritance.

## Time-separated authority decisions

The embedded authority object is evidence about the evaluation-time
authorization snapshot, not a timeless declaration that a key is trusted.
Verification therefore returns two decisions:

- **Historical validity:** whether identity, signature, authorization at
  `evaluated_at`, schema semantics, and ancestry were valid for the receipt.
- **Current effectiveness:** whether current policy permits the historically
  valid chain to authorize the decision being made now.

Implementations MUST NOT erase historical validity after key rotation or later
revocation. They MUST NOT infer current effectiveness merely from a historically
valid signature. Compromise policy can deny current effectiveness immediately
while preserving the immutable audit fact.

## Protocol boundary

Schema revisions (`schema_id`) and CRP semantic versions (`protocol_version`) are
independent. A compatible representation correction may introduce a future
schema without changing protocol semantics. Any changed gate meaning, evidence
requirement, authority rule, ancestry rule, or state derivation requires a new
semantic `protocol_version` and the migration boundary above.

The schemas and semantic rules are the contract. A later verifier must implement
them; its runtime behavior cannot silently extend them.
