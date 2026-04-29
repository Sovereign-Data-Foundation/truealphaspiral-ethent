# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0
"""
Universal Verifier Kernel (UVK) – deterministic admission control (§2).

The UVK is a minimal, policy-free verifier core that:
1. Verifies capabilities presented with action proposals.
2. Validates declared invariants I over (x_t, a_t, u_t).
3. Emits receipt R_t and commits it to the wake chain.
4. Triggers Phoenix on any breach.

The UVK implements the Objective Token τ (§4):

    τ = ⊥(s ⊙ k) ∧ ✓(k ⊙ e)

* Orthogonality ⊥(s ⊙ k): semantic generators cannot write into epistemic
  verification state except through defined channels.
* Alignment ✓(k ⊙ e): epistemic acceptance is oriented to declared ethical
  constraints.

UVK non-responsibilities (§2):
- No semantic interpretation.
- No intent inference.
- No discretionary policy beyond invariants.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from capability import CapabilityError, CapabilityTable, Right
from wake_chain import ProvenanceMark, WakeChain, get_default_chain


# ---------------------------------------------------------------------------
# Admission status
# ---------------------------------------------------------------------------


class AdmissionStatus(Enum):
    """Outcome of a UVK admission decision.

    Attributes:
        ADMITTED: All invariants passed and capability checks (if any) succeeded.
        REJECTED: At least one invariant failed or a capability check failed.
    """

    ADMITTED = "admitted"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Invariant
# ---------------------------------------------------------------------------


@dataclass
class Invariant:
    """A named, callable invariant checked by the UVK on every admission.

    Attributes:
        name:      Human-readable invariant identifier.
        predicate: Callable that receives ``(state, action, inputs)`` and
                   returns ``True`` iff the invariant holds.
    """

    name: str
    predicate: Callable[[Any, Any, Any], bool]


# ---------------------------------------------------------------------------
# Receipt
# ---------------------------------------------------------------------------


@dataclass
class Receipt:
    """Immutable record of a single UVK admission decision.

    Attributes:
        timestamp:         Unix epoch at which the decision was made.
        actor:             Identity that proposed the action.
        action:            The action that was evaluated.
        status:            :class:`AdmissionStatus` outcome.
        invariant_results: Mapping from invariant name to pass/fail boolean.
        wake_mark:         The :class:`ProvenanceMark` committed to the wake
                           chain, or ``None`` if no chain is attached.
    """

    timestamp: float
    actor: str
    action: str
    status: AdmissionStatus
    invariant_results: Dict[str, bool]
    wake_mark: Optional[ProvenanceMark]


# ---------------------------------------------------------------------------
# UVK
# ---------------------------------------------------------------------------


class UVK:
    """Universal Verifier Kernel – deterministic admission control.

    The UVK checks capabilities and evaluates registered :class:`Invariant`
    predicates for every proposed action.  Results are recorded as
    :class:`Receipt` objects and, if a :class:`WakeChain` is attached,
    committed to the tamper-evident ledger.

    Args:
        wake_chain:        Optional :class:`WakeChain` for receipt provenance.
                           Defaults to the module-level default chain.
        capability_table:  Optional :class:`CapabilityTable` used for
                           capability checks when *required_capability* is
                           supplied to :meth:`admit`.
    """

    def __init__(
        self,
        wake_chain: Optional[WakeChain] = None,
        capability_table: Optional[CapabilityTable] = None,
    ) -> None:
        self._wake_chain: Optional[WakeChain] = wake_chain if wake_chain is not None else get_default_chain()
        self._capability_table: Optional[CapabilityTable] = capability_table
        self._invariants: List[Invariant] = []
        self._receipts: List[Receipt] = []

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def add_invariant(self, invariant: Invariant) -> None:
        """Register *invariant* for evaluation on every :meth:`admit` call.

        Args:
            invariant: The :class:`Invariant` to add.
        """
        self._invariants.append(invariant)

    # ------------------------------------------------------------------
    # Admission
    # ------------------------------------------------------------------

    def admit(
        self,
        actor: str,
        action: str,
        state: Any = None,
        inputs: Any = None,
        required_capability: Optional[str] = None,
        capability_table: Optional[CapabilityTable] = None,
    ) -> Receipt:
        """Evaluate *action* proposed by *actor* and emit a :class:`Receipt`.

        Steps performed:
        1. If *required_capability* is given, invoke it against the supplied
           (or instance-level) :class:`CapabilityTable` to verify the right.
        2. Evaluate all registered :class:`Invariant` predicates.
        3. Determine :class:`AdmissionStatus`.
        4. Commit a :class:`ProvenanceMark` to the wake chain (if attached).
        5. Return and record a :class:`Receipt`.

        Args:
            actor:               Identity proposing the action.
            action:              The action to evaluate.
            state:               Current observable system state (x_t).
            inputs:              External inputs (u_t).
            required_capability: If set, the *cap_id* of the capability that
                                 must be present and carry :attr:`Right.INVOKE`.
            capability_table:    Override the instance-level
                                 :class:`CapabilityTable` for this call.

        Returns:
            A :class:`Receipt` recording the full admission decision.
        """
        inv_results: Dict[str, bool] = {}
        overall_admitted = True

        # Step 1 – capability check
        if required_capability is not None:
            table = capability_table or self._capability_table
            try:
                if table is None:
                    raise CapabilityError("No CapabilityTable available for capability check")
                table.invoke(required_capability, Right.INVOKE)
            except CapabilityError as exc:
                inv_results["__capability__"] = False
                overall_admitted = False

        # Step 2 – invariant evaluation
        for inv in self._invariants:
            try:
                result = bool(inv.predicate(state, action, inputs))
            except Exception:
                result = False
            inv_results[inv.name] = result
            if not result:
                overall_admitted = False

        status = AdmissionStatus.ADMITTED if overall_admitted else AdmissionStatus.REJECTED

        # Step 3 – commit to wake chain
        mark: Optional[ProvenanceMark] = None
        if self._wake_chain is not None:
            mark = self._wake_chain.commit(
                actor=actor,
                action=action,
                state_snapshot={
                    "status": status.value,
                    "invariant_results": inv_results,
                },
            )

        receipt = Receipt(
            timestamp=time.time(),
            actor=actor,
            action=action,
            status=status,
            invariant_results=inv_results,
            wake_mark=mark,
        )
        self._receipts.append(receipt)
        return receipt

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def receipts(self) -> List[Receipt]:
        """Return a copy of all :class:`Receipt` objects emitted so far."""
        return list(self._receipts)
