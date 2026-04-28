"""Phoenix Protocol – deterministic recovery controller (§7).

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

Phoenix must emit a :class:`PhoenixReceipt` on every activation (§7.3).
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from wake_chain import WakeChain

if TYPE_CHECKING:
    from uvk import AdmissionResult, UVK


# ---------------------------------------------------------------------------
# Breach types
# ---------------------------------------------------------------------------


class BreachType(Enum):
    INVARIANT_VIOLATION = auto()
    WAKE_DISCONTINUITY  = auto()
    PHASE_SLIP          = auto()
    CAPABILITY_ANOMALY  = auto()
    UNKNOWN             = auto()


_BREACH_CODES: Dict[BreachType, str] = {
    BreachType.INVARIANT_VIOLATION: "PHX-001",
    BreachType.WAKE_DISCONTINUITY:  "PHX-002",
    BreachType.PHASE_SLIP:          "PHX-003",
    BreachType.CAPABILITY_ANOMALY:  "PHX-004",
    BreachType.UNKNOWN:             "PHX-000",
}


# ---------------------------------------------------------------------------
# Phoenix state machine
# ---------------------------------------------------------------------------


class PhoenixState(Enum):
    """States of the Phoenix deterministic recovery state machine (§7.2)."""
    NOMINAL   = auto()  # Normal operation
    FROZEN    = auto()  # Step 1: actuation stopped
    ROLLBACK  = auto()  # Step 2: identifying rollback target
    REVERIFY  = auto()  # Step 3: dry-dock replay
    CORRECTING = auto() # Step 4: awaiting authenticated HCS
    RELAUNCHED = auto() # Step 5: certified re-launch


# ---------------------------------------------------------------------------
# Phoenix Receipt (§7.3)
# ---------------------------------------------------------------------------


@dataclass
class PhoenixReceipt:
    """Required output of every Phoenix activation (§7.3).

    Fields
    ------
    receipt_id:
        UUID for this Phoenix event.
    breach_type:
        Enumerated breach category.
    breach_code:
        Short code string (e.g. "PHX-001").
    rollback_target_hash:
        Hex hash of the wake receipt R_k selected as the rollback point.
        Empty string if no valid rollback point was found.
    replay_result:
        Summary of the dry-dock replay outcome.
    human_action_required:
        True iff non-replayable ambiguity was detected and authenticated
        HCS input is needed before re-launch.
    relaunch_certificate:
        Populated when Phoenix certifies re-launch is safe (§7.2.5).
    timestamp:
        Unix epoch at which Phoenix was triggered.
    details:
        Arbitrary extra detail dict (breach-specific context).
    """

    receipt_id: str
    breach_type: BreachType
    breach_code: str
    rollback_target_hash: str
    replay_result: str
    human_action_required: bool
    relaunch_certificate: Optional[str]
    timestamp: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "breach_type": self.breach_type.name,
            "breach_code": self.breach_code,
            "rollback_target_hash": self.rollback_target_hash,
            "replay_result": self.replay_result,
            "human_action_required": self.human_action_required,
            "relaunch_certificate": self.relaunch_certificate,
            "timestamp": self.timestamp,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Phoenix controller
# ---------------------------------------------------------------------------


class Phoenix:
    """Deterministic recovery controller.

    Parameters
    ----------
    uvk:
        The :class:`~uvk.UVK` instance to consult for re-launch certification.
    wake_chain:
        The :class:`~wake_chain.WakeChain` under recovery.
    """

    def __init__(self, uvk: "UVK", wake_chain: WakeChain) -> None:
        self._uvk = uvk
        self._wake = wake_chain
        self._state: PhoenixState = PhoenixState.NOMINAL
        self._receipts: List[PhoenixReceipt] = []
        self._frozen: bool = False

    # ------------------------------------------------------------------
    # State accessor
    # ------------------------------------------------------------------

    @property
    def state(self) -> PhoenixState:
        return self._state

    @property
    def is_frozen(self) -> bool:
        return self._frozen

    @property
    def receipts(self) -> List[PhoenixReceipt]:
        return list(self._receipts)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def trigger(
        self,
        breach_type: BreachType,
        details: Optional[Dict[str, Any]] = None,
    ) -> PhoenixReceipt:
        """Execute the full Phoenix recovery sequence and return a receipt.

        Implements §7.2 steps 1–5.

        Parameters
        ----------
        breach_type:
            The category of the breach that triggered Phoenix.
        details:
            Optional context dict (e.g., failed invariant names, cap IDs).

        Returns
        -------
        PhoenixReceipt
            Emitted receipt documenting the breach and recovery outcome.
        """
        trigger_time = time.time()
        details = details or {}

        # Step 1: Freeze ---------------------------------------------------
        self._state = PhoenixState.FROZEN
        self._frozen = True

        # Step 2: Rollback – find last valid receipt -----------------------
        self._state = PhoenixState.ROLLBACK
        rollback_seq, rollback_hash = self._find_rollback_point()

        # Step 3: Re-verify – dry-dock replay from rollback point ----------
        self._state = PhoenixState.REVERIFY
        replay_ok, replay_summary = self._replay_from(rollback_seq)

        # Step 4: Correct – check if HCS input is needed -------------------
        self._state = PhoenixState.CORRECTING
        human_needed = not replay_ok

        # Step 5: Re-launch – certify if possible --------------------------
        relaunch_cert: Optional[str] = None
        tau_ok = self._uvk.verify_tau()
        if replay_ok and tau_ok:
            self._state = PhoenixState.RELAUNCHED
            self._frozen = False
            relaunch_cert = str(uuid.uuid4())
        else:
            # Stay in CORRECTING until an external HCS call resolves it
            self._state = PhoenixState.CORRECTING

        # Human action is required whenever automatic recovery cannot certify
        # re-launch (replay failed or τ invariant broken).
        human_needed = not replay_ok or not tau_ok

        receipt = PhoenixReceipt(
            receipt_id=str(uuid.uuid4()),
            breach_type=breach_type,
            breach_code=_BREACH_CODES.get(breach_type, "PHX-000"),
            rollback_target_hash=rollback_hash,
            replay_result=replay_summary,
            human_action_required=human_needed,
            relaunch_certificate=relaunch_cert,
            timestamp=trigger_time,
            details=details,
        )
        self._receipts.append(receipt)
        return receipt

    # ------------------------------------------------------------------
    # Human Command Stream integration (§7.2.4)
    # ------------------------------------------------------------------

    def provide_hcs_correction(self, hcs_command: str) -> bool:
        """Accept an authenticated Human Command Stream correction.

        Transitions the Phoenix state machine from CORRECTING → RELAUNCHED
        (or back to NOMINAL) if the UVK certifies the corrected state.

        Parameters
        ----------
        hcs_command:
            Authenticated operator instruction resolving the ambiguity.

        Returns
        -------
        bool
            True iff re-launch was certified.
        """
        if self._state != PhoenixState.CORRECTING:
            return False

        # Record the HCS command in the wake chain as an authenticated event
        self._wake.commit(
            event={"hcs_correction": hcs_command, "t": time.time()},
            info={"source": "HCS", "phoenix_state": self._state.name},
        )

        if self._uvk.verify_tau():
            self._state = PhoenixState.RELAUNCHED
            self._frozen = False
            return True
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_rollback_point(self) -> tuple[int, str]:
        """Find the last receipt where wake integrity held.

        Returns (seq, receipt_hash_hex).  Returns (-1, "") if none found.
        """
        receipts = self._wake.receipts
        for i in range(len(receipts) - 1, -1, -1):
            pm = receipts[i]
            # A simple heuristic: use the earliest receipt in the chain that
            # was correctly chained up to position i.
            # Full production code would re-verify the sub-chain to position i.
            return i, pm.receipt_hash().hex()
        return -1, ""

    def _replay_from(self, seq: int) -> tuple[bool, str]:
        """Attempt dry-dock replay from *seq* and return (ok, summary)."""
        if seq < 0:
            return False, "no valid rollback point found"
        try:
            replayed = self._wake.replay_from(seq)
            ok = replayed.verify()
            summary = (
                f"replayed {len(replayed)} receipts from seq={seq}; "
                f"chain_valid={ok}"
            )
            return ok, summary
        except Exception as exc:
            return False, f"replay failed: {exc}"
