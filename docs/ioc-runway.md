# IOC Runway and Task Organization

This document organizes the active Codex work threads and repository change metrics into a staged execution path for the Initial Operating Capability (IOC) deployment target on **2026-08-21**.

As of **2026-07-29**, the IOC target is **23 calendar days away**.

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

## Readiness Gate

IOC readiness requires all four phase gates to be satisfied in order:

1. **Invariant proof:** Merkle vectors, UVK documentation, and SMT policy validation are complete.
2. **Operator path:** CLI identity verification and guardrails produce deterministic receipts.
3. **Stabilization:** P1 defects and outstanding review feedback are closed with tests or written rationale.
4. **Deployment checklist:** Final objectives are signed off before the 2026-08-21 target.

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
