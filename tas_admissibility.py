"""TAS Admissibility Boundary — ``admit_or_refuse``.

This module implements the single function that converts the SDF evidentiary
boundary into an executable state-transition guard:

.. math::

    S_n \\xrightarrow{P} S_{n+1}
    \\iff
    \\operatorname{Admissible}(P, E, S_n) = 1

When ``Admissible`` is 0, the state is unchanged (ΔS = 0) and a signed
refusal receipt is returned.  The receipt itself becomes lineage evidence that
can seed the *next* cycle — but it does not carry the jurisdiction that would
authorise a future transition.

Formally:

.. math::

    R_n \\rightarrow E_{n+1}
    \\quad \\text{but} \\quad
    R_n \\not\\Rightarrow \\operatorname{Authority}(P_{n+1})

This enforces the spiral invariant:

.. math::

    \\text{verified history}
    \\neq
    \\text{self-created jurisdiction}
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, FrozenSet, Optional, Set

from sdf_evidence_envelope import (
    EvidenceVerdict,
    SDFEvidenceEnvelope,
    SDF_VERDICT_DOMAIN,
    _canonical_json,
    _domain_hash,
    verify_evidence,
)

# ---------------------------------------------------------------------------
# Domain constant
# ---------------------------------------------------------------------------

TAS_ADMISSION_DOMAIN = b"TAS-ADMISSION-V1\x00"
TAS_REFUSAL_DOMAIN = b"TAS-REFUSAL-V1\x00"

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdmissionReceipt:
    """Sealed record of a successful state transition.

    ``delta_s`` is always 1 for an admission.
    ``state_root_after`` is the hash of the new state.
    ``lineage_evidence_hash`` is the hash that the *next* cycle may include as
    its ``parent_hash`` — but possessing this hash does not grant authority.
    """

    admitted: bool                   # Always True
    delta_s: int                     # Always 1
    evidence_id: str
    proposal_hash: str
    state_root_before: str
    state_root_after: str
    verdict: EvidenceVerdict
    lineage_evidence_hash: str       # R_n — for the next E_{n+1}

    def to_dict(self) -> dict[str, Any]:
        return {
            "admitted": self.admitted,
            "delta_s": self.delta_s,
            "evidence_id": self.evidence_id,
            "proposal_hash": self.proposal_hash,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "verdict_receipt_hash": self.verdict.receipt_hash,
            "lineage_evidence_hash": self.lineage_evidence_hash,
        }


@dataclass(frozen=True)
class RefusalReceipt:
    """Sealed record of a refused transition (ΔS = 0).

    ``lineage_evidence_hash`` is still produced — the refusal is part of the
    lineage — but it does not carry authority.
    """

    admitted: bool                   # Always False
    delta_s: int                     # Always 0
    evidence_id: str
    proposal_hash: str
    state_root: str                  # Unchanged: S_{n+1} = S_n
    failed_predicate: Optional[str]
    verdict: EvidenceVerdict
    lineage_evidence_hash: str       # R_n — for the next E_{n+1}

    def to_dict(self) -> dict[str, Any]:
        return {
            "admitted": self.admitted,
            "delta_s": self.delta_s,
            "evidence_id": self.evidence_id,
            "proposal_hash": self.proposal_hash,
            "state_root": self.state_root,
            "failed_predicate": self.failed_predicate,
            "verdict_receipt_hash": self.verdict.receipt_hash,
            "lineage_evidence_hash": self.lineage_evidence_hash,
        }


# Union type for callers that handle both outcomes
AdmissionOutcome = AdmissionReceipt | RefusalReceipt


# ---------------------------------------------------------------------------
# Core function
# ---------------------------------------------------------------------------


def admit_or_refuse(
    *,
    proposal: Any,
    envelope: SDFEvidenceEnvelope,
    state_root: str,
    authority_scope: FrozenSet[str],
    current_context: str,
    seen_nonces: Set[str],
    invariant_check: Callable[[Any, str], bool],
    apply_transition: Callable[[Any, str], str],
) -> AdmissionOutcome:
    """Evaluate a proposal against an SDF evidence envelope.

    Parameters
    ----------
    proposal:
        The model-generated proposal (P).  Any serialisable Python value.
    envelope:
        The ``SDFEvidenceEnvelope`` (E) accompanying the proposal.
    state_root:
        The hex-encoded SHA-256 of the current system state (S_n).
    authority_scope:
        The set of ``authority_id`` values authorised to endorse this class of
        proposal.  Established independently of the model and envelope.
    current_context:
        The system's current context identifier.
    seen_nonces:
        Mutable set of already-consumed nonces.  Updated in-place on admission.
    invariant_check:
        ``(proposal, state_root) → bool`` — caller-supplied system invariant.
        Must not use the envelope to derive its return value; the separation
        is the caller's responsibility.
    apply_transition:
        ``(proposal, state_root) → new_state_root`` — called only on admission.
        Must return a deterministic 64-char hex state root.

    Returns
    -------
    AdmissionReceipt  — if ΔS ≠ 0 (transition was admitted).
    RefusalReceipt    — if ΔS = 0  (transition was refused).
    """
    proposal_hash = _domain_hash(TAS_ADMISSION_DOMAIN, {"proposal": proposal})

    # Compute invariant pass BEFORE verification so the two checks remain
    # independent; neither can influence the other's inputs.
    inv = invariant_check(proposal, state_root)

    verdict = verify_evidence(
        envelope,
        authority_scope=authority_scope,
        current_context=current_context,
        seen_nonces=seen_nonces,
        invariant_pass=inv,
    )

    if verdict.admissible:
        new_state_root = apply_transition(proposal, state_root)

        # Consume nonce to prevent replay
        seen_nonces.add(envelope.nonce)

        receipt_body: dict[str, Any] = {
            "admitted": True,
            "delta_s": 1,
            "evidence_id": envelope.evidence_id,
            "proposal_hash": proposal_hash,
            "state_root_before": state_root,
            "state_root_after": new_state_root,
            "verdict_receipt_hash": verdict.receipt_hash,
        }
        lineage_hash = _domain_hash(TAS_ADMISSION_DOMAIN, receipt_body)

        return AdmissionReceipt(
            admitted=True,
            delta_s=1,
            evidence_id=envelope.evidence_id,
            proposal_hash=proposal_hash,
            state_root_before=state_root,
            state_root_after=new_state_root,
            verdict=verdict,
            lineage_evidence_hash=lineage_hash,
        )

    else:
        # ΔS = 0 — state root does not change
        refusal_body: dict[str, Any] = {
            "admitted": False,
            "delta_s": 0,
            "evidence_id": envelope.evidence_id,
            "proposal_hash": proposal_hash,
            "state_root": state_root,
            "failed_predicate": verdict.failed_predicate,
            "verdict_receipt_hash": verdict.receipt_hash,
        }
        lineage_hash = _domain_hash(TAS_REFUSAL_DOMAIN, refusal_body)

        return RefusalReceipt(
            admitted=False,
            delta_s=0,
            evidence_id=envelope.evidence_id,
            proposal_hash=proposal_hash,
            state_root=state_root,
            failed_predicate=verdict.failed_predicate,
            verdict=verdict,
            lineage_evidence_hash=lineage_hash,
        )
