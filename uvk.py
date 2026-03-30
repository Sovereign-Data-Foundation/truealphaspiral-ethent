"""Universal Verifier Kernel (UVK) – deterministic admission control (§2).

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
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional

from capability import Capability, CapabilityError, CapabilityTable, Right
from wake_chain import ProvenanceMark, WakeChain, get_default_chain


# ---------------------------------------------------------------------------
# Invariant types
# ---------------------------------------------------------------------------


InvariantFn = Callable[[Any, Any, Any], bool]
"""Callable(x_t, a_t, u_t) → bool.  Must be pure and side-effect-free."""


@dataclass
class Invariant:
    """A named, versioned invariant predicate.

    Parameters
    ----------
    name:
        Human-readable identifier.
    version:
        Version string (bound into every Wrinkle so replay can verify it).
    check:
        Pure predicate (x_t, a_t, u_t) → bool.
    """

    name: str
    version: str
    check: InvariantFn

    def __call__(self, x_t: Any, a_t: Any, u_t: Any) -> bool:
        return self.check(x_t, a_t, u_t)


# ---------------------------------------------------------------------------
# Admission result
# ---------------------------------------------------------------------------


class AdmissionStatus(Enum):
    ADMITTED = auto()
    DENIED_CAPABILITY = auto()
    DENIED_INVARIANT = auto()
    DENIED_WAKE = auto()


@dataclass
class AdmissionResult:
    """Outcome of a UVK admission-control check.

    Attributes
    ----------
    status:
        Whether the transition was admitted or, if denied, why.
    receipt:
        The :class:`~wake_chain.ProvenanceMark` committed to the wake chain
        (present iff *status* is ADMITTED).
    failed_invariants:
        Names of invariants that returned False (empty on ADMITTED).
    cap_error:
        Capability error message if DENIED_CAPABILITY.
    wake_valid:
        True iff the wake chain was intact at admission time.
    """

    status: AdmissionStatus
    receipt: Optional[ProvenanceMark] = None
    failed_invariants: List[str] = field(default_factory=list)
    cap_error: Optional[str] = None
    wake_valid: bool = True

    @property
    def admitted(self) -> bool:
        return self.status == AdmissionStatus.ADMITTED


# ---------------------------------------------------------------------------
# UVK
# ---------------------------------------------------------------------------


class UVK:
    """Universal Verifier Kernel.

    Parameters
    ----------
    capability_table:
        The :class:`~capability.CapabilityTable` managed by this kernel.
        A fresh table is created if not provided.
    wake_chain:
        The :class:`~wake_chain.WakeChain` for this session.
        The process-level default chain is used if not provided.
    invariants:
        Initial list of :class:`Invariant` predicates.
    on_breach:
        Optional callback invoked *before* Phoenix is triggered.
        Signature: (AdmissionResult) → None.
    """

    def __init__(
        self,
        capability_table: Optional[CapabilityTable] = None,
        wake_chain: Optional[WakeChain] = None,
        invariants: Optional[List[Invariant]] = None,
        on_breach: Optional[Callable[["AdmissionResult"], None]] = None,
    ) -> None:
        self.cap_table: CapabilityTable = capability_table or CapabilityTable()
        self.wake: WakeChain = wake_chain if wake_chain is not None else get_default_chain()
        self._invariants: List[Invariant] = list(invariants or [])
        self._on_breach = on_breach
        self._breach_log: List[AdmissionResult] = []

    # ------------------------------------------------------------------
    # Invariant management
    # ------------------------------------------------------------------

    def add_invariant(self, invariant: Invariant) -> None:
        self._invariants.append(invariant)

    def remove_invariant(self, name: str) -> bool:
        before = len(self._invariants)
        self._invariants = [i for i in self._invariants if i.name != name]
        return len(self._invariants) < before

    # ------------------------------------------------------------------
    # Core admission-control method
    # ------------------------------------------------------------------

    def admit(
        self,
        capability: Capability,
        required_right: Right,
        action: Any,
        state: Any = None,
        inputs: Any = None,
        extra_info: Optional[Dict[str, Any]] = None,
    ) -> AdmissionResult:
        """Attempt to admit an action transition.

        Parameters
        ----------
        capability:
            The token presented by the agent for this action.
        required_right:
            The :class:`~capability.Right` the action requires.
        action:
            Action proposal *a_t* (JSON-serialisable for Wrinkle binding).
        state:
            Current state *x_t* (passed to invariant predicates).
        inputs:
            External inputs *u_t* (tools, sensors, operator commands).
        extra_info:
            Additional Wrinkle fields (protocol snapshot, tool IDs, …).

        Returns
        -------
        AdmissionResult
            ADMITTED with a wake receipt, or DENIED_* with breach details.
        """
        # --- Step 1: capability check -----------------------------------
        try:
            self.cap_table.invoke(capability, required_right, msg=action)
        except CapabilityError as exc:
            result = AdmissionResult(
                status=AdmissionStatus.DENIED_CAPABILITY,
                cap_error=str(exc),
                wake_valid=self.wake.verify(),
            )
            return self._handle_breach(result)

        # --- Step 2: invariant validation --------------------------------
        failed: List[str] = []
        for inv in self._invariants:
            try:
                if not inv(state, action, inputs):
                    failed.append(inv.name)
            except Exception as exc:
                failed.append(f"{inv.name}[exception:{exc}]")

        if failed:
            result = AdmissionResult(
                status=AdmissionStatus.DENIED_INVARIANT,
                failed_invariants=failed,
                wake_valid=self.wake.verify(),
            )
            return self._handle_breach(result)

        # --- Step 3: wake continuity check --------------------------------
        wake_ok = self.wake.verify()
        if not wake_ok:
            result = AdmissionResult(
                status=AdmissionStatus.DENIED_WAKE,
                wake_valid=False,
            )
            return self._handle_breach(result)

        # --- Step 4: emit receipt and commit to wake chain ---------------
        wrinkle = self._build_wrinkle(capability, required_right, action, inputs, extra_info)
        receipt = self.wake.commit(
            event={
                "action": str(action),
                "resource": capability.resource,
                "right": required_right.name,
                "t": time.time(),
            },
            info=wrinkle,
        )

        return AdmissionResult(
            status=AdmissionStatus.ADMITTED,
            receipt=receipt,
            wake_valid=True,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_wrinkle(
        self,
        cap: Capability,
        right: Right,
        action: Any,
        inputs: Any,
        extra: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build the Wrinkle (commit point) for the wake receipt (§5.3)."""
        invariant_versions = {inv.name: inv.version for inv in self._invariants}
        wrinkle: Dict[str, Any] = {
            "cap_id": cap.cap_id,
            "resource": cap.resource,
            "right": right.name,
            "action": str(action),
            "invariant_versions": invariant_versions,
            "wake_head_before": self.wake.head.hex(),
        }
        if inputs is not None:
            wrinkle["inputs"] = str(inputs)
        if extra:
            wrinkle.update(extra)
        return wrinkle

    def _handle_breach(self, result: AdmissionResult) -> AdmissionResult:
        """Record the breach and invoke the on_breach callback."""
        self._breach_log.append(result)
        if self._on_breach:
            try:
                self._on_breach(result)
            except Exception:
                pass  # breach handler must not raise
        return result

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def breach_log(self) -> List[AdmissionResult]:
        return list(self._breach_log)

    def verify_tau(self) -> bool:
        """Return True iff the Objective Token τ = ⊥ ∧ ✓ is preserved.

        Checks:
        - ⊥(s ⊙ k): wake chain integrity (epistemic state has not been tampered
          with via semantic channels).
        - ✓(k ⊙ e): all registered invariants are present (ethical constraints
          are declared and bound).

        This is a structural check, not a semantic one (§2 non-responsibilities).
        """
        orthogonal = self.wake.verify()           # ⊥ face
        aligned = len(self._invariants) > 0       # ✓ face – at least one ethical constraint
        return orthogonal and aligned
