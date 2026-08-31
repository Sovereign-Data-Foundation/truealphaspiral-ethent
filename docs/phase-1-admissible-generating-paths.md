# Phase 1: Admissible Generating Paths

**Status:** Phase 1 operational specification

**Scope:** Candidate generation, verification, refusal, and replay

**Normative language:** The terms **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**,
and **MAY** are to be interpreted as requirements for a conforming Phase 1
implementation.

## 1. Purpose and boundary

Phase 1 does not make a probabilistic generator deterministic. It places a
deterministic, fail-closed transition system around generator output. A token
probability, model confidence, vote, or semantic similarity score is never
evidence of admission. Such values MAY be retained as diagnostic data, but they
MUST NOT satisfy an admissibility predicate.

The operational unit is an **admissible generating path**: an ordered sequence
of candidate states in which every accepted transition carries verifiable
lineage to the immutable origin state, `A_0`. Content that cannot supply that
lineage is untrusted input, regardless of how plausible it appears.

This specification defines control-plane integrity. It does not claim that
cryptographic provenance makes generated content factually correct, nor that a
hash proves the truth of the value hashed. Factual or policy requirements MUST
be expressed as separate, deterministic gate predicates with their own witness
evidence.

## 2. State and path model

Let `A_0` be the locally verified origin anchor and let a proposed path be:

```text
P = (A_0, A_1, ..., A_n)
```

Every transition envelope `T_i : A_(i-1) -> A_i` MUST contain:

| Field | Operational requirement |
| --- | --- |
| `origin_root` | SHA-256 lineage commitment derived from the local `A_0`; never accepted from configuration alone. |
| `parent_hash` | Commitment to the immediately preceding admitted state. |
| `state_hash` | Commitment to the canonical bytes of the proposed state. |
| `transition_index` | Strictly monotonic position in this path. |
| `transform` | Stable identifier for the transformation applied. |
| `authority_proof` | Independently verifiable authorization for the proposed operation. |
| `witness` | Canonical evidence needed to reproduce the gate result. |
| `receipt_seal` | Integrity seal or signature over the complete, domain-separated envelope. |

For a configured set of pure, deterministic predicates `G`, the transition is
admissible only when all of the following are true:

```text
Admissible(T_i) :=
    Verify(A_0)
    AND T_i.origin_root = LineageHash(A_0)
    AND T_i.parent_hash = Hash(A_(i-1))
    AND T_i.transition_index = T_(i-1).transition_index + 1
    AND CanonicalHash(T_i.state) = T_i.state_hash
    AND VerifyAuthority(T_i.authority_proof)
    AND VerifySeal(T_i.receipt_seal, T_i)
    AND every(g(T_i) = TRUE for g in G)
```

No weighted average, majority, fallback score, or best-effort branch may replace
this conjunction. Missing, malformed, non-finite, stale, ambiguous, or invalid
evidence evaluates to `FALSE`.

## 3. Continuous active verification

Verification is a transition precondition, not a post-processing audit.

1. The runtime MUST verify its local `A_0` before opening a candidate path.
2. It MUST derive the expected origin root from that verified anchor.
3. It MUST canonicalize and hash the candidate envelope before evaluation.
4. It MUST validate parent continuity, the exact next transition index,
   authority, seal, and every configured gate.
5. It MUST write an admission or refusal receipt before any external effect.
6. Only an admitted receipt MAY be presented to an actuator, which MUST verify
   the receipt again at its trust boundary.

Verification results MUST be bound to the exact candidate bytes. A result for
one candidate, parent, path position, action scope, or origin root MUST NOT be
reused for another.

## 4. Cursive computation

**Cursive computation** is the Phase 1 execution discipline in which every
step extends an unbroken authenticated stroke. It replaces unproved recursive
self-invocation; it does not prohibit ordinary implementation techniques such
as recursive functions.

The stroke is initialized from `A_0` and extended at every step:

```text
stroke_0 = H(domain || actor || capability || LineageHash(A_0))
stroke_i = H(domain || stroke_(i-1) || transition_index
             || transform || state_hash || witness_hash)
```

All components MUST use an injective, length-prefixed canonical encoding and a
versioned domain separator. The resulting `stroke_i` MUST be carried in the
transition receipt and recomputed by the next verifier. A path is not cursive
if a step omits its predecessor, changes the origin, skips an index, or cannot
reproduce the stroke.

Where the Sovereign Equation is configured, authenticated content dominance is
a strict gate:

```text
A_C > S_C
```

Both operands MUST be finite, deterministically derived from receipt-bound
evidence, and reproducible by an independent verifier. The equation is one
predicate in `G`; it cannot compensate for failed lineage or authority.

## 5. Deterministic verification pipeline

The only Phase 1 transition outcomes are `ADMITTED` and `REFUSED`:

```text
UNVERIFIED
    -> VERIFY_ORIGIN
    -> VERIFY_LINEAGE
    -> VERIFY_AUTHORITY
    -> VERIFY_GATES
    -> WRITE_RECEIPT
    -> ADMITTED

any verification failure
    -> NULL_COLLAPSE
    -> WRITE_REFUSAL_RECEIPT
    -> REFUSED
```

An implementation MUST evaluate the same canonical envelope and gate version to
the same decision. Gate order MAY be optimized for early refusal only when that
does not alter the decision or omit required refusal evidence. Gate exceptions,
timeouts, unavailable dependencies, and unsupported versions are failures, not
permission to continue.

## 6. Null Collapse Protocol

Null collapse is terminal for the candidate path. On any fracture, the runtime
MUST:

1. freeze mutation of the candidate and its derived execution context;
2. prevent the candidate and all descendants from reaching an actuator;
3. set the path result to `REFUSED` (`Π = ∅`);
4. emit a canonical refusal receipt containing the origin root, candidate and
   parent commitments, transition index, gate version, failed rule identifiers,
   and witness hashes;
5. discard unverified derived state and initialize any subsequent attempt from
   a freshly verified `A_0`; and
6. require a new path identifier, transition sequence, and authority proof for
   that subsequent attempt.

“Collapse to `A_0`” means resetting the verification basis; it MUST NOT mutate
`A_0`, erase the refusal receipt, silently retry the failed candidate, or treat
the origin state itself as an executable output.

### 6.1 Generator masking

When the generator interface supports token masking, the adapter MUST apply a
deny mask immediately after refusal so no token derived from the fractured path
can propagate:

```text
mask[token] = -infinity  for every continuation token of the refused path
```

The mask is a containment mechanism, not evidence of correctness. Because APIs
differ and some cannot prove complete logit masking, the authoritative control
is the actuator deny gate. If masking cannot be applied or verified, generation
MUST stop and the path remains `REFUSED`; the runtime MUST NOT approximate
negative infinity with an implementation-dependent “very unlikely” threshold
and continue.

## 7. Receipt and replay requirements

Admission and refusal are both witnessed outcomes. Receipts MUST be serialized
canonically, content-addressed, sealed, and durably recorded. Secrets and raw
sensitive payloads SHOULD be represented by commitments rather than copied into
receipts.

Replay MUST independently verify:

- the local `A_0` and receipt `origin_root`;
- canonical field encoding and the receipt seal;
- the complete parent chain and strictly monotonic indices;
- authority scope, nonce freshness, and gate-version availability;
- every deterministic predicate against the committed witnesses; and
- exact agreement between the recomputed and recorded decision.

A replay mismatch is a new refusal event. It MUST NOT rewrite the historical
receipt or select an alternate branch that happens to admit.

## 8. Conformance checklist

A Phase 1 implementation is conforming only if tests demonstrate all of these
properties:

- valid single-step and multi-step paths admit and replay identically;
- substituted `A_0`, parent, state, witness, authority, or seal is refused;
- missing, duplicate, decreasing, and skipped transition indices are refused;
- `NaN`, positive infinity, and negative infinity in a gate operand are refused;
- gate errors, timeouts, and unknown gate versions are refused;
- no actuator is called before a durable admission receipt exists;
- refusal blocks descendants and emits a durable refusal receipt;
- a retry begins from verified `A_0` with fresh path and authority data; and
- unsupported or unverifiable generator masking stops generation.

These tests establish deterministic enforcement of the documented transition
rules. They do not establish universal truth, model sentience, immunity from all
attacks, or correctness of predicates that were never specified.

## 9. Repository mapping

The Phase 1 language maps to the current components as follows:

| Requirement | Repository component |
| --- | --- |
| Origin verification and lineage root | `tas_dna.py` |
| Candidate branching and `Π = ∅` refusal | `yknot.py` |
| Cursive stroke and cross-node verification | `algorithmic_polymath.py` |
| Signed, closed-scope actuator admission | `sovereign_runtime.py` |
| Canonical process roles and binary receipt rules | `PROCESS_SCIENCE.md` |

This mapping identifies existing enforcement surfaces; it does not imply that
every requirement in this specification is already implemented by one unified
runtime. Implementations claiming Phase 1 conformance MUST satisfy the complete
checklist at their actual trust boundaries.
