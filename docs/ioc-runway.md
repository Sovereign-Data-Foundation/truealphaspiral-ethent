# Canonical Readiness Protocol and IOC Runway

This document defines the **Canonical Readiness Protocol (CRP)** and organizes the active Codex work threads and repository change metrics into its dated execution plan for the Initial Operating Capability (IOC) deployment target on **2026-08-21**.

As of **2026-07-29**, the IOC target is **23 calendar days away**.

## Governing Terms

- **Canonical Readiness Protocol (CRP):** The governing rules for proving readiness, including the required sequence, evidence, verification procedures, authorities, and receipts.
- **IOC runway:** The dated execution plan that implements the CRP for the 2026-08-21 target. It is an execution instance of the protocol, not the protocol itself.
- **Readiness gate:** A protocol-defined decision point with required inputs, authorized evaluators, verification procedures, and explicit pass/fail conditions.
- **Completion receipt:** The durable, cryptographically bound output proving that a readiness gate was evaluated against identified evidence and recording its result.
- **Readiness state:** A result derived from valid completion receipts. It is never a manually asserted label.

The IOC runway is an execution instance of the Canonical Readiness Protocol. The protocol defines the required sequence, evidence, verification procedures, authorities, and receipts by which readiness is established. No task, phase, or deployment state is complete merely because it is marked complete; completion exists only when the protocol admits the required evidence and produces a valid completion receipt.

## Runway Summary

| Phase | Focus | Additions | Deletions | Net Change | IOC Outcome |
| --- | --- | ---: | ---: | ---: | --- |
| Phase 1 | Core verification and kernel invariants | 1,431 | 0 | +1,431 | Cryptographic provenance and base policy enforcement are specified and testable. |
| Phase 2 | Interface, CLI, and guardrails | 2,010 | 84 | +1,926 | Operators receive auditable CLI workflows and bounded generation pathways. |
| Phase 3 | Correctness and stabilization | 206 | 55 | +151 | Blocking defects and review deltas are resolved before hardening. |
| Phase 4 | Milestone execution | 40 | 0 | +40 | Deployment objectives are consolidated into a final readiness checklist. |
| **Total** | **IOC runway** | **3,687** | **139** | **+3,548** | **A coherent path from invariant proof to deployment readiness.** |

## Phase 1: Core Verification and Kernel Invariants

Foundational mechanics that ensure cryptographic provenance and policy enforcement.

| Task | Metric | Purpose | Exit Criteria |
| --- | ---: | --- | --- |
| Define golden vectors for Merkle verification | +689 / -0 | Establish baseline test vectors that cryptographically anchor state lineage. | Golden-vector fixtures are deterministic, reproducible, and covered by verification tests. |
| Document Universal Verifier Kernel | +130 / -0 | Formalize the verification specification across execution nodes. | UVK requirements are documented with expected inputs, outputs, and failure modes. |
| Implement Layer 1 SMT policy validation | +612 / -0 | Enforce Satisfiability Modulo Theories constraints at the base protocol layer. | Policy checks reject invalid state transitions and surface auditable failure receipts. |

## Phase 2: Interface, CLI, and Guardrails

Operational controls for user interaction and behavioral boundaries.

| Task | Metric | Purpose | Exit Criteria |
| --- | ---: | --- | --- |
| Draft `tas_cli.py verify-identity` logic | +965 / -83 | Build the command-line interface for immutable identity checks. | CLI identity verification emits deterministic success and refusal receipts. |
| Implement logit bias and guardrails | +826 / -0 | Secure model output pathways against drift and unverified generation. | Guardrails are configurable, tested, and fail closed on unsafe output requests. |
| Implement proof of concept for verification modules | +219 / -1 | Validate end-to-end trace integrity. | Verification modules run together in a reproducible proof-of-concept path. |

## Phase 3: Correctness and Stabilization

Defect remediation and code-review hygiene.

| Task | Metric | Purpose | Exit Criteria |
| --- | ---: | --- | --- |
| Fix P1 correctness defects in pipeline | +200 / -49 | Remove critical blocking errors before deployment stabilization. | P1 defects have regression tests and no longer reproduce in the pipeline. |
| Review pull request 274 comments | +6 / -6 | Resolve pending architectural feedback. | Review comments are answered or incorporated into committed changes. |

## Phase 4: Milestone Execution

Final deployment vector lock-down.

| Task | Metric | Purpose | Exit Criteria |
| --- | ---: | --- | --- |
| Finalize IOC deployment objectives | +40 / -0 | Consolidate the readiness checklist for the August milestone. | IOC objectives are explicit, owned, and mapped to a go/no-go checklist. |

## Readiness Gates

IOC readiness requires all four protocol-defined gates to be evaluated and passed in order:

| Gate | Required inputs | Pass condition | Completion receipt |
| --- | --- | --- | --- |
| **1. Invariant proof** | Merkle vectors, UVK documentation, SMT policy validation, and their verification results | Every input is admitted, reproducible, and passes its specified verification procedure. | Binds the evidence hashes, verifier identity and version, evaluation time, authority, and pass/fail result. |
| **2. Operator path** | Gate 1 receipt, CLI identity-verification evidence, guardrail configuration, and deterministic receipt tests | The operator path produces deterministic success and refusal receipts and fails closed. | Binds the Gate 1 receipt and all operator-path evidence to the evaluation result. |
| **3. Stabilization** | Gate 2 receipt, P1 regression evidence, and dispositions for outstanding review feedback | P1 defects no longer reproduce and every review item has admitted test evidence or written rationale. | Binds the Gate 2 receipt, defect evidence, review dispositions, and evaluation result. |
| **4. Deployment authorization** | Gate 3 receipt, final IOC objectives, accountable owners, and the go/no-go checklist | Objectives are explicit, owned, verified, and authorized before the 2026-08-21 target. | Binds the complete receipt chain, deployment scope, authorizing identity, and final result. |

A gate cannot consume an unchecked task label as evidence. Each receipt must identify the gate and protocol version, commit to its inputs by cryptographic digest, record the verification procedure and outcome, and bind the authorized evaluator. Failed evaluations also produce durable receipts; they do not advance the readiness state.

## Derived Readiness State

Readiness is computed from the ordered receipt chain:

- **Not evaluated:** no valid Gate 1 receipt exists.
- **In progress:** the latest valid receipt passes a gate before Gate 4.
- **Blocked:** the latest valid receipt records a failed gate evaluation.
- **IOC ready:** valid, ordered, cryptographically linked pass receipts exist for Gates 1 through 4 under the applicable CRP version.

Editing a checklist, task, phase, or deployment label cannot change this state. Any missing, invalid, out-of-order, or evidence-mismatched receipt makes the claimed downstream state inadmissible.

## TAS Architectural Alignment

The IOC runway is aligned to the TAS mechanical-integrity model described in the repository:

- **Biconditional gate discipline:** State transitions must satisfy lineage, invariant, and density requirements before acceptance.
- **Sentient-lock fail closed behavior:** Integrity failures must produce durable non-compliance evidence instead of silent continuation.
- **Living Braid provenance:** Truth, context, and consequence streams must remain canonicalized and hashable across validating nodes.
- **Complexity dissipation:** Redundant process or interface layers should collapse into deterministic checks as the IOC target approaches.

## Immediate Execution Order

1. Complete Phase 1 verification primitives before expanding operator-facing behavior.
2. Land Phase 2 CLI and guardrail work only after invariant contracts are stable.
3. Run Phase 3 correction passes against the integrated path rather than isolated modules.
4. Use Phase 4 to freeze deployment scope, not to introduce new architectural surface area.

## Research Basis

The CRP framing follows evidence-gated assurance, signed software provenance, reproducible-build, and continuous-compliance research:

- Torres-Arias et al. (2019), [*in-toto: Providing farm-to-table guarantees for bits and bytes*](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias).
- Newman et al. (2022), [software-supply-chain security research](https://doi.org/10.1145/3548606.3560596).
- Okafor et al. (2022), [software provenance research](https://doi.org/10.1145/3560835.3564556).
- Butler et al. (2023), [continuous-compliance research](https://doi.org/10.1007/s11219-022-09607-z).
- Tran et al. (2024), [software assurance research](https://doi.org/10.1145/3661167.3661212).
- Zhang et al. (2026), [empirical software-engineering research](https://doi.org/10.1007/s10664-025-10795-y).
- Ozkan et al. (2024), [reproducible-build research](https://arxiv.org/abs/2412.05138).
- Huang et al. (2026), [continuous-compliance research](https://arxiv.org/abs/2607.14890).
