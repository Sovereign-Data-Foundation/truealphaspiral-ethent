# Recursive Contextualization

## Status

This document defines the TAS doctrine implemented by `context_snapshot.py` and
consumed by `admission_gate.py`. It describes the semantic-context contract
introduced after PR #38 and merged through PR #40.

Recursive contextualization is the process by which every governed artifact,
authorization, evaluation, and state transition is bound to the exact semantic
and authority context under which it was created.

In TAS, context is not background information. It is authenticated state.

## Canonical invariant

> No transition without authority. No authority without scope. No scope without
> fixed meaning. No meaning without attributable lineage.

A candidate is not admissible merely because its signature is valid. The
runtime must also prove that the words, rules, and scope applied to the
candidate resolve to the same content-addressed definitions committed by the
active context snapshot.

## The History Problem

A ledger can preserve exact bytes while still losing the meaning of those bytes
if interpretation depends on a mutable external dictionary. An attacker would
not need to forge a signature or alter an old receipt; changing the external
definition of a term could change the apparent execution meaning of an already
recorded transition.

Recursive contextualization closes this semantic-drift vector by binding each
transition to a content-addressed context snapshot.

For an artifact `A` created at time `t0`:

```text
Meaning(A, t0) = MeaningUnder(A, ContextSnapshot(t0))
```

It is never re-evaluated by silently substituting the current dictionary:

```text
Meaning(A, t0) != MeaningUnder(A, CurrentContext)
```

A later governance decision may establish a successor context or prohibit
future use of an older context. It may not rewrite the definitions under which
the historical artifact was evaluated.

## Interpretive immutability

Interpretive immutability means that future governance cannot retroactively
change the definitions, invariants, authority projection, canonicalization
rules, namespace, or predecessor context under which an artifact was evaluated.

It does **not** mean:

- the artifact is factually infallible;
- the artifact remains executable forever;
- a revoked authority remains currently valid;
- an obsolete context must remain the active namespace head.

TAS therefore distinguishes:

```text
historical interpretability != present authorization
historical validity         != current executability
```

An old receipt may remain valid evidence of what occurred under its pinned
context while being inadmissible for new execution.

## DefinitionID

TAS rejects floating semantic labels. Each definition is represented by a
canonical definition record and assigned a domain-separated SHA-256 identifier:

```text
DefinitionID = SHA256(
    "TAS-DEFINITION-V1\0" || TAS-CJSON-1(definition_record)
)
```

A definition record includes:

- schema and canonicalization versions;
- namespace;
- term;
- semantic version;
- definition text;
- constraints;
- optional predecessor DefinitionID.

The identifier commits to the complete canonical record. A resolver returning
modified bytes under the same DefinitionID is rejected.

## Registry root

A context snapshot contains an ordered list of DefinitionIDs. The registry root
commits to that exact declared order:

```text
registry_root = SHA256(
    "TAS-CONTEXT-REGISTRY-V1\0" ||
    TAS-CJSON-1(definition_ids)
)
```

Duplicate DefinitionIDs, missing definitions, non-canonical bytes, namespace
mismatches, and content/identifier mismatches fail closed.

## Context snapshot

`tas.context-snapshot.v1` commits to:

- `schema_version`;
- `canonicalization_version`;
- `namespace_id`;
- `context_sequence`;
- `registry_root`;
- ordered `definition_ids`;
- `invariant_set_id`;
- `authority_binding_hash`;
- `parent_context_hash`;
- `effective_epoch`.

The self-hash is calculated over the unsigned projection:

```text
context_snapshot_hash = SHA256(
    "TAS-CONTEXT-SNAPSHOT-V1\0" ||
    TAS-CJSON-1(unsigned_context_snapshot)
)
```

`context_snapshot_hash` is not included in its own preimage.

## Authority binding

The context commits to a non-circular projection of the authority snapshot via
`authority_binding_hash`. The full authority snapshot separately commits back
to `context_snapshot_hash`.

This creates mutual binding without a recursive hash cycle:

```text
ContextSnapshot  -> authority_binding_hash
AuthoritySnapshot -> context_snapshot_hash
```

The gate refuses admission when the authority checkpoint, authority epoch,
authority projection, or declared context hash do not agree.

Cryptography is evidentiary, not constitutive. Possession of a valid key does
not create authority; it proves control of a credential whose scope and context
must already be authorized.

## Admission order

The gate enforces this sequence:

```text
Raw authorization envelope
    -> validate envelope shape and identifiers
    -> resolve exact ContextSnapshot bytes
    -> verify context hash and canonical encoding
    -> verify active namespace head
    -> resolve and verify every DefinitionID
    -> resolve AuthoritySnapshot
    -> verify authority/context mutual binding
    -> verify context lineage continuity
    -> parse candidate semantics
    -> verify candidate hash and signature
    -> admit or refuse
    -> sign and durably append receipt
```

The core ordering rule is:

> No semantic candidate interpretation before context verification.

The outer authorization envelope may be minimally decoded to locate the context
reference. Policy-bearing candidate fields are not interpreted until the
semantic environment has been authenticated.

## No teleportation

TAS treats discontinuous context movement as inadmissible state teleportation.
A child receipt may remain in the same context or move to a context whose
`parent_context_hash` is the context recorded by its parent receipt.

An unrelated context cannot be inserted into an existing receipt lineage.
Failure produces a refusal receipt rather than an unauthenticated state change.

This operationalizes Process Science:

- **P0 — Process Equivalence:** identical output payloads are not equivalent
  when their context snapshots differ;
- **P1 — Admissibility:** a missing, substituted, stale, or discontinuous
  semantic dependency makes the proposed transition inadmissible.

## Namespaced truth

Definitions are namespace-scoped. A definition from one namespace cannot be
silently substituted into another, and only the active head of a namespace is
accepted for new execution.

This permits attributable semantic evolution without retroactive invalidation:

```text
Valid_in_Namespace_A(x) does not imply Valid_in_Namespace_B(x)
```

### Current implementation boundary

The merged v1 implementation provides:

- namespace-scoped definition records;
- one active context head per namespace;
- parent-context continuity;
- fail-closed rejection of stale or mismatched context.

It does **not yet** define a signed `NAMESPACE_FORK` transition or a
cross-namespace translation-proof format. Until those contracts are added,
cross-namespace execution must be treated as unsupported and refused rather
than inferred.

## Receipt semantics

A refusal or admission receipt binds the decision to:

- authority checkpoint and epoch;
- context snapshot;
- context parent;
- namespace;
- registry root;
- invariant set;
- authority binding;
- declared candidate hash;
- parsed candidate hash, when parsing occurs;
- raw candidate-byte hash;
- requested operation;
- parent receipt;
- nonce;
- failure code or admitted state;
- runtime signer identity.

A refusal receipt proves that the exact proposed transition failed a declared
verification boundary. It does not prove that the candidate was universally or
morally false.

## Controlled state machine

A TAS agent is not a free-running optimizer. It is a controlled state machine
whose externally effective actions must carry receipt-bearing lineage back to
authorized external human or juridical authority.

The mature chain is:

```text
Human/Juridical Authority
    -> Authority Snapshot
    -> Context Snapshot
    -> Scoped Capability
    -> Structural Verification
    -> Execution or Refusal
    -> Context-bound Receipt
```

WakeChain preserves continuity of motion. Recursive contextualization preserves
continuity of meaning.
