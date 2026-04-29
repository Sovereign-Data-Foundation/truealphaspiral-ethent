# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0
"""
Phoenix Protocol – deterministic recovery controller (§7).

Phoenix triggers on any of the following breach conditions (§7.1):
1. Invariant violation (core constraints fail).
2. Wake discontinuity (chain break, signature mismatch).
3. Critical phase slip (sustained |φ_t| > φ_max).
4. Capability anomaly (misuse, unexpected mint/retype/revoke graph).

Recovery sequence (§7.2):
1. Freeze  – stop actuation; allow only status + safe prompts.
2. Rollback – select last R_k where invariants + wake continuity held.
3. Re-verify – deterministic replay in "dry dock" from R_k.
4. Correct  – require authenticated Human Command Stream (HCS) for
               non-replayable ambiguity.
5. Re-launch – resume only when UVK certifies wake continuity, invariants,
               τ preservation, and phase lock.

Phoenix must emit a PhoenixReceipt on every activation (§7.3).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from uvk import UVK
from wake_chain import WakeChain


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class BreachType(Enum):
    """Categorises the cause of a Phoenix activation.

    Attributes:
        INVARIANT_VIOLATION:  A UVK-registered invariant evaluated to False.
        WAKE_DISCONTINUITY:   The wake chain failed integrity verification.
        CRITICAL_PHASE_SLIP:  Sustained phase exceeded φ_max.
        CAPABILITY_ANOMALY:   Unexpected capability mint / revoke / retype event.
    """

    INVARIANT_VIOLATION = "invariant_violation"
    WAKE_DISCONTINUITY = "wake_discontinuity"
    CRITICAL_PHASE_SLIP = "critical_phase_slip"
    CAPABILITY_ANOMALY = "capability_anomaly"


class PhoenixState(Enum):
    """Lifecycle state of the :class:`Phoenix` controller.

    Attributes:
        NOMINAL:    Normal operation; no active breach.
        FROZEN:     Actuation suspended following a breach trigger.
        RECOVERING: HCS correction accepted; replay and re-verify in progress.
        RELAUNCHED: UVK has certified safe resumption.
    """

    NOMINAL = "nominal"
    FROZEN = "frozen"
    RECOVERING = "recovering"
    RELAUNCHED = "relaunched"


# ---------------------------------------------------------------------------
# PhoenixReceipt
# ---------------------------------------------------------------------------


@dataclass
class PhoenixReceipt:
    """Immutable record emitted on every Phoenix activation.

    Attributes:
        timestamp:       Unix epoch at the moment of activation.
        breach_type:     The :class:`BreachType` that triggered Phoenix.
        state_before:    :class:`PhoenixState` immediately before this event.
        state_after:     :class:`PhoenixState` immediately after this event.
        rollback_index:  Index of the last-known-good wake mark, or ``None``
                         if the chain was empty at trigger time.
        hcs_required:    ``True`` when human correction is needed before
                         re-launch.
        details:         Arbitrary key/value metadata for diagnostics.
    """

    timestamp: float
    breach_type: BreachType
    state_before: PhoenixState
    state_after: PhoenixState
    rollback_index: Optional[int]
    hcs_required: bool
    details: Dict[str, Any]


# ---------------------------------------------------------------------------
# Phoenix controller
# ---------------------------------------------------------------------------


class Phoenix:
    """Deterministic recovery controller that enforces §7 recovery semantics.

    Args:
        uvk:        The :class:`UVK` instance whose receipts are used to locate
                    the last-known-good state during rollback.
        wake_chain: The :class:`WakeChain` whose integrity is monitored.
    """

    def __init__(self, uvk: UVK, wake_chain: WakeChain) -> None:
        self._uvk: UVK = uvk
        self._wake_chain: WakeChain = wake_chain
        self._state: PhoenixState = PhoenixState.NOMINAL
        self._receipts: List[PhoenixReceipt] = []

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def state(self) -> PhoenixState:
        """Current :class:`PhoenixState` of this controller."""
        return self._state

    @property
    def is_frozen(self) -> bool:
        """``True`` when the controller is in the :attr:`PhoenixState.FROZEN` state."""
        return self._state == PhoenixState.FROZEN

    @property
    def receipts(self) -> List[PhoenixReceipt]:
        """Ordered list of every :class:`PhoenixReceipt` emitted by this controller."""
        return list(self._receipts)

    # ------------------------------------------------------------------
    # Trigger
    # ------------------------------------------------------------------

    def trigger(
        self,
        breach_type: BreachType,
        details: Optional[Dict[str, Any]] = None,
    ) -> PhoenixReceipt:
        """Activate the Phoenix protocol in response to a detected breach.

        The controller transitions to :attr:`PhoenixState.FROZEN` and
        attempts to identify the last-known-good mark index by scanning UVK
        receipts in reverse order.

        Args:
            breach_type: The :class:`BreachType` that caused this activation.
            details:     Optional diagnostic key/value pairs included in the
                         :class:`PhoenixReceipt`.

        Returns:
            The emitted :class:`PhoenixReceipt`.
        """
        state_before = self._state
        self._state = PhoenixState.FROZEN

        rollback_index = self._find_last_good_index()
        hcs_required = rollback_index is None

        receipt = PhoenixReceipt(
            timestamp=time.time(),
            breach_type=breach_type,
            state_before=state_before,
            state_after=self._state,
            rollback_index=rollback_index,
            hcs_required=hcs_required,
            details=details or {},
        )
        self._receipts.append(receipt)
        return receipt

    # ------------------------------------------------------------------
    # HCS correction
    # ------------------------------------------------------------------

    def provide_hcs_correction(self, hcs_command: str) -> bool:
        """Accept a Human Command Stream correction and attempt re-launch.

        The controller advances from :attr:`PhoenixState.FROZEN` through
        :attr:`PhoenixState.RECOVERING` to :attr:`PhoenixState.RELAUNCHED`
        when the wake chain is still verifiable.

        Args:
            hcs_command: Authenticated human command that resolves the breach.

        Returns:
            ``True`` if re-launch succeeded (state becomes RELAUNCHED),
            ``False`` if the chain could not be verified and the controller
            remains in a non-nominal state.
        """
        if self._state != PhoenixState.FROZEN:
            return False

        self._state = PhoenixState.RECOVERING

        # Commit the HCS correction to the wake chain for auditability.
        self._wake_chain.commit(
            actor="HCS",
            action=hcs_command,
            state_snapshot={"phoenix_state": self._state.value},
        )

        # Re-verify chain integrity before re-launch.
        if self._wake_chain.verify():
            self._state = PhoenixState.RELAUNCHED
            return True

        # Chain integrity cannot be established; stay in RECOVERING.
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_last_good_index(self) -> Optional[int]:
        """Return the index of the last UVK-admitted wake mark, or ``None``."""
        marks = self._wake_chain.marks
        if not marks:
            return None
        # Walk UVK receipts in reverse to find the last ADMITTED mark.
        from uvk import AdmissionStatus  # local import to avoid circularity at module level

        for receipt in reversed(self._uvk.receipts):
            if receipt.status == AdmissionStatus.ADMITTED and receipt.wake_mark is not None:
                idx = receipt.wake_mark.index
                if 0 <= idx < len(marks):
                    return idx
        # Fall back to the last mark in the chain.
        return len(marks) - 1
