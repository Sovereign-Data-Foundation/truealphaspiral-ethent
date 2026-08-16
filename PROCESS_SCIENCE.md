# Process Science: The Physics of Integrity

**Status:** Canonical Architectural Invariant  
**Version:** 1.0.0-Phase0  
**Scope:** Microkernel Runtime, Sovereign Data Foundation (SDF), Edge Actuators

## 1. Executive Summary and Core Postulates

Process Science formalizes information-state dynamics as an immutable,
deterministic integrity model. In this architecture, integrity is not a moral
preference or a statistical probability. It is a conserved system invariant,
maintained by externally authorized constraint work.

Probabilistic intelligence models are treated as statistical coherence engines.
Ungrounded state generation produces thermodynamic information drift
(`ΔS_info > 0`). An executing runtime therefore cannot create legitimacy for
its own output: every admissible state must remain anchored to external
authorization and pass fail-closed validation gates.

### The axiomatic postulates

1. **The First Law (Conservation of Origin).** Authority is
   non-self-originating. Legitimacy cannot be created or destroyed within an
   executing runtime; it can only be transferred from an external,
   independently authenticated source. No node, construct, or runtime module
   may generate its own legitimacy.
2. **The Second Law (Thermodynamic Information Drift).** In an ungrounded
   probabilistic manifold, information entropy increases monotonically.
   Hallucination and drift are the natural equilibrium of unconstrained token
   optimization. A candidate that violates finite mathematical bounds or
   contextual lineage collapses immediately to `S_refused`.
3. **The Third Law (Joint Inspectability).** System integrity is bounded by the
   inspectability of its weakest joint. Every boundary transition must expose
   an injective, length-prefixed, domain-separated cryptographic proof of its
   load-bearing evidence.

## 2. Thermodynamic Phase Trajectory

To prevent unbounded entropic drift (`ΔS_info → ∞`), transitions follow a
bounded spiral trajectory in phase space (`ℝ⁴`). Ungrounded candidate states
must resolve to refusal rather than continue through the transition pipeline.

| Trajectory phase | Field equation or bound | Physical/computational mechanism | State resolution |
| --- | --- | --- | --- |
| Initial Expansion | `ΔS > 0` | Probabilistic candidate generation by the Construct engine. | Unverified Candidate State |
| Singularity Anchor | `∇ · S = C` | Binding to context lineage, monotonic counters, and `.tasmeta.json` bounds. | Invariant Boundary Lock |
| Compression Phase | `∂r/∂θ < 0` | Contraction through `math.isfinite()` bounds, domain separation, and length framing. | Injective Preimage Construction |
| Terminal Tightening | `Admissible(R) = 0` | Automatic null-collapse on a missing origin signature or non-finite coherence value. | `S_refused` (Fail-Closed) |

## 3. Functional Role Partitioning

Action and legitimacy are decoupled across five non-overlapping roles to
prevent circular self-authorization.

| Role | Operational scope | Boundary restriction |
| --- | --- | --- |
| **Source** | Originates authority with asymmetric private-key signatures. | Cannot execute runtime transitions or mutate runtime state. |
| **Construct** | Computes transformation vectors and advances candidate states. | Cannot manufacture authorizing claims. |
| **Witness** | Writes immutable state records using atomic flush and `fsync`. | Cannot alter decision outputs or evaluate admission rules. |
| **Gate** | Evaluates coherence thresholds (`≥ 0.85`), lineage, and closed schema rules. | Cannot force-admit a non-admissible candidate. |
| **Harvest** | Emits domain-separated, length-prefixed `AdmissibilityReceipt` byte streams. | Cannot fabricate originating authority. |

These restrictions are capability boundaries, not merely organizational labels.
An implementation must not assign conflicting role capabilities to the same
runtime authority.

## 4. Master Admissibility Law

Admissibility is a dual-predicate conjunction. Internal machine testimony is
deliberately separated from external origin authority so runtime integrity
cannot become self-referential authorization.

```text
        [ External Source (PK_source) ]
                      │
                      ▼ GatewaySignatureValid(R)
    ┌───────────────────────────────────┐
    │    ADMISSIBLE CORRIDOR (ADMITTED) │ ◄── Admissible(R) = TRUE
    └───────────────────────────────────┘
                      ▲
                      │ RuntimeSealValid(R)
        [ Internal Machine (K_runtime) ]
```

Formally:

```text
Admissible(R) := RuntimeSealValid(R) ∧ GatewaySignatureValid(R)
```

- **`RuntimeSealValid(R)`** validates an HMAC-SHA-256 seal over an injectively
  encoded binary preimage. It establishes integrity across storage and wire
  transport, but does not establish originating authority.
- **`GatewaySignatureValid(R)`** validates the asymmetric signature over origin
  intent. It establishes external authorization, but does not independently
  prove runtime lineage or transport integrity.

If either predicate is false, the only valid resolution is `REFUSED`.

> **The Digital Masonry Code:** Every joint must expose the evidence that bears
> its load. A signature cannot prove lineage; a lineage hash cannot prove
> authority; an HMAC seal cannot create originating authority. The machine
> executes the math; the external Source authorizes the state; the Gate refuses
> the drift.

## 5. Binary Wire Preimage and Schema

An admissibility receipt is constructed using length-prefixed, big-endian
packing over an explicit domain separator. The encoding must be injective:
`E(x) = E(y) ⇒ x = y`.

### Preimage encoding

```text
[ DOMAIN_SEPARATOR (29 bytes: b"TAS\x00ADMISSIBILITY-RECEIPT\x00v1\x00") ]
[ uint16 context_id_length ][ context_id bytes (UTF-8) ]
[ uint64 monotonic_counter ]
[ uint16 decision_length ][ decision bytes (UTF-8: "ADMITTED" | "REFUSED") ]
[ uint16 trace_hash_length ][ trace_hash bytes (UTF-8) ]
[ uint32 gateway_sig_length ][ gateway_signature bytes ]
```

All integers use unsigned network byte order (big-endian). The HMAC is computed
over the complete preimage above; the 32-byte receipt HMAC is carried as the
seal associated with that preimage and is not included recursively within it.

### Invariant rules

- `context_id`, `decision`, and `trace_hash` UTF-8 encodings are each limited to
  `uint16` length (`≤ 65,535` bytes).
- `gateway_signature` is limited to `uint32` length (`≤ 4,294,967,295` bytes).
- `monotonic_counter` must fit `uint64` and must rise strictly for each
  `context_id`.
- `decision` belongs to the closed vocabulary `ADMITTED | REFUSED`.
- An implementation must reject non-canonical or malformed UTF-8 rather than
  normalize it implicitly.
- Serializing an unsealed receipt (`len(receipt_hmac) != 32`) raises
  `UnsealedReceiptError`; no partial wire representation may be emitted.

## 6. Microkernel Execution Invariants

### Monotonic execution lineage

Every context execution derives a strictly rising counter:
`n_(k+1) > n_k`. The counter is bound to `context_id`, included in the sealed
preimage, and checked before any actuator side effect. Counter reuse or rollback
is a replay failure.

### Non-evicting replay ledger

`ExternalActuatorGuard` maintains a persistent, non-evicting set of observed
token fingerprints across hardware restarts. Snapshot replacement must be
atomic (`os.replace`) and durability must be established with `os.fsync` before
the transition is acknowledged. Capacity pressure must fail closed rather than
silently evict replay evidence.

### Numeric finiteness guard

Every incoming coherence value is checked with `math.isfinite()` before a
threshold comparison. `NaN`, positive infinity, and negative infinity trigger
immediate null-collapse to `S_refused`. Because comparisons involving `NaN` can
bypass naïve threshold logic, threshold checking alone is insufficient.

### Single-path lineage

Each admitted receipt resolves to one authenticated origin intent, one context
lineage, and one monotonic counter position. Forked, ambiguous, missing, or
substituted lineage is inadmissible even when individual hashes or signatures
remain syntactically valid.

## 7. Required Failure Semantics

Refusal is a terminal, auditable state rather than an exception that callers may
reinterpret as permission. Implementations must:

1. perform all validation before external effects;
2. collapse missing, malformed, non-finite, stale, replayed, or
   cryptographically invalid evidence to `REFUSED`;
3. emit a Witness record for the refusal without allowing Witness to change the
   decision;
4. prohibit fallback admission paths and force-admit overrides; and
5. preserve enough domain-separated evidence to reproduce the Gate's result.

The invariant is therefore operational: the Source authorizes, Construct
computes, Witness preserves, Gate decides, and Harvest testifies. No role may
substitute its proof for another role's proof.
