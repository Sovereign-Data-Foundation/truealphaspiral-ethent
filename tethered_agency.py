"""Tethered Agency System (TAS) – Recursive Correction Layers.

Addresses the Orphan-Agent Problem by mandating a live authorial chain.
Agency without an identifiable, active human custodian is structurally void.

The four recursive correction layers enforce:

    1. No authorial custodian  → No agency.
    2. No authorial heartbeat  → No system privilege for execution.
    3. No provable receipts    → No authorized action.
    4. No system-wide feedback → No functional ecosystem.

These are not policies – they are *architectural invariants*.  Any action
that cannot satisfy all four layers collapses to Process Null (Π = ∅).

Math OS vs Mythos
-----------------
*Mythos*  relies on reputational trust and experiential narrative.
*Math OS* demands explicit proofs: custody chains, heartbeat tokens, and
          verifiable receipt paths traceable to A_0.

The Human API Key
-----------------
The *sponsor* is not an optional annotation.  The sponsor is the custodial
root from which system legitimacy flows.  Without a live, identified sponsor
the system cannot self-authorize – it is an orphan agent.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional

from uvk import Invariant
from wake_chain import WakeChain, get_default_chain


# ---------------------------------------------------------------------------
# Layer 1 – Authorial Custodian  (Human API Key)
# ---------------------------------------------------------------------------


@dataclass
class AuthorialCustodian:
    """The live human custodian who anchors system legitimacy.

    This is the *Human API Key* – the custodial root from which all
    authority in the system flows.  An absent or unidentified custodian
    makes every downstream action structurally void.

    Parameters
    ----------
    custodian_id:
        Opaque unique identifier for the custodian (e.g., a UUID or
        authenticated user token).
    name:
        Human-readable name (for audit trail readability).
    sponsor_hash:
        SHA-256 hex digest committing the custodian identity to a
        single verifiable string.  Computed via :meth:`compute_hash`
        when not supplied explicitly.
    """

    custodian_id: str
    name:         str
    sponsor_hash: str = field(default="")

    def __post_init__(self) -> None:
        if not self.sponsor_hash:
            object.__setattr__(self, "sponsor_hash", self.compute_hash())

    def compute_hash(self) -> str:
        """Compute the canonical sponsor commitment hash.

        Binds ``custodian_id`` and ``name`` into a single verifiable digest
        so that downstream receipts can prove custodian identity without
        exposing raw credentials.
        """
        payload = f"{self.custodian_id}|{self.name}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def is_valid(self) -> bool:
        """Return True iff the stored sponsor_hash matches the computed one."""
        return self.sponsor_hash == self.compute_hash()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "custodian_id": self.custodian_id,
            "name":         self.name,
            "sponsor_hash": self.sponsor_hash,
        }


def make_custodian_invariant(
    get_custodian: Callable[[Any, Any, Any], Optional[AuthorialCustodian]],
    version: str = "1.0.0",
) -> Invariant:
    """Return a UVK :class:`~uvk.Invariant` enforcing Layer 1.

    The invariant returns False (denying the action) if the custodian is
    absent, unidentified, or cryptographically invalid.

    Parameters
    ----------
    get_custodian:
        Pure function ``(state, action, inputs) → AuthorialCustodian | None``.
        Must be side-effect-free; called inside the UVK hot-path.
    version:
        Invariant version string bound into each wake receipt.
    """

    def _check(state: Any, action: Any, inputs: Any) -> bool:
        custodian = get_custodian(state, action, inputs)
        if custodian is None:
            return False
        return custodian.is_valid()

    return Invariant(
        name    = "tethered_agency:custodian_present",
        version = version,
        check   = _check,
    )


# ---------------------------------------------------------------------------
# Layer 2 – Authorial Heartbeat  (System Privilege Token)
# ---------------------------------------------------------------------------


class HeartbeatExpiredError(Exception):
    """Raised when a system privilege is exercised without a live heartbeat."""


@dataclass
class AuthorialHeartbeat:
    """Time-bounded proof that a human custodian is actively present.

    The heartbeat is the *authorial pulse* that grants system privilege.
    If the heartbeat has not been refreshed within ``max_interval`` seconds,
    the privilege expires and every execution request collapses to Π = ∅.

    Parameters
    ----------
    custodian_id:
        Identity of the custodian whose presence this heartbeat attests.
    max_interval:
        Maximum number of seconds between heartbeats before the token
        is considered expired (default: 300 s = 5 minutes).
    """

    custodian_id:  str
    max_interval:  float = 300.0
    _last_beat:    float = field(default_factory=time.time, init=False, repr=False)

    def beat(self) -> float:
        """Record a heartbeat from the custodian and return the timestamp."""
        self._last_beat = time.time()
        return self._last_beat

    def is_alive(self, at: Optional[float] = None) -> bool:
        """Return True iff the heartbeat is within the allowed interval.

        Parameters
        ----------
        at:
            Wall-clock time to evaluate against (defaults to ``time.time()``).
        """
        now = at if at is not None else time.time()
        return (now - self._last_beat) <= self.max_interval

    def assert_alive(self, at: Optional[float] = None) -> None:
        """Raise :class:`HeartbeatExpiredError` if the heartbeat has lapsed."""
        if not self.is_alive(at):
            elapsed = (at if at is not None else time.time()) - self._last_beat
            raise HeartbeatExpiredError(
                f"Authorial heartbeat for custodian {self.custodian_id!r} has expired "
                f"(elapsed={elapsed:.1f}s > max_interval={self.max_interval}s); "
                "system privilege revoked – action collapsed to Π = ∅"
            )

    def seconds_until_expiry(self, at: Optional[float] = None) -> float:
        """Return the number of seconds remaining before the heartbeat expires.

        Negative values indicate the heartbeat has already expired.
        """
        now = at if at is not None else time.time()
        return self.max_interval - (now - self._last_beat)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "custodian_id":  self.custodian_id,
            "max_interval":  self.max_interval,
            "last_beat":     self._last_beat,
        }


def make_heartbeat_invariant(
    get_heartbeat: Callable[[Any, Any, Any], Optional[AuthorialHeartbeat]],
    clock: Callable[[], float] = time.time,
    version: str = "1.0.0",
) -> Invariant:
    """Return a UVK :class:`~uvk.Invariant` enforcing Layer 2.

    The invariant returns False if no live heartbeat is available, or if
    the heartbeat has expired since the last custodian interaction.

    Parameters
    ----------
    get_heartbeat:
        Pure function ``(state, action, inputs) → AuthorialHeartbeat | None``.
    clock:
        Zero-argument callable returning the current Unix epoch.
    version:
        Invariant version string.
    """

    def _check(state: Any, action: Any, inputs: Any) -> bool:
        heartbeat = get_heartbeat(state, action, inputs)
        if heartbeat is None:
            return False
        return heartbeat.is_alive(at=clock())

    return Invariant(
        name    = "tethered_agency:heartbeat_alive",
        version = version,
        check   = _check,
    )


# ---------------------------------------------------------------------------
# Layer 3 – Provable Receipts  (No receipt → No authorized action)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProofReceipt:
    """An auditable proof-of-action bound to a custodian and wake receipt.

    Every authorized action MUST produce a :class:`ProofReceipt`.  If no
    receipt can be produced, the action is inadmissible.

    Parameters
    ----------
    receipt_id:
        UUID for this proof receipt.
    custodian_id:
        Identity of the sponsoring custodian.
    action_hash:
        SHA-256 hex digest of the canonical action payload.
    wake_receipt_hash:
        Hex digest of the :class:`~wake_chain.ProvenanceMark` committing
        this action to the wake chain.
    timestamp:
        Unix epoch at which the receipt was issued.
    """

    receipt_id:        str
    custodian_id:      str
    action_hash:       str
    wake_receipt_hash: str
    timestamp:         float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id":        self.receipt_id,
            "custodian_id":      self.custodian_id,
            "action_hash":       self.action_hash,
            "wake_receipt_hash": self.wake_receipt_hash,
            "timestamp":         self.timestamp,
        }


class ReceiptLedger:
    """Append-only ledger of :class:`ProofReceipt` entries.

    Fulfils the *provable receipts* requirement: every admitted action leaves
    a tamper-evident audit trail that can be presented on demand.
    """

    def __init__(self) -> None:
        self._receipts: List[ProofReceipt] = []

    def record(
        self,
        custodian_id: str,
        action: Any,
        wake_chain: Optional[WakeChain] = None,
    ) -> ProofReceipt:
        """Commit a new proof receipt for *action* and return it.

        Parameters
        ----------
        custodian_id:
            Identity of the acting custodian.
        action:
            The action payload (any JSON-serialisable object).
        wake_chain:
            Optional :class:`~wake_chain.WakeChain` to commit the receipt
            event to.  Defaults to the process-level chain.
        """
        chain = wake_chain if wake_chain is not None else get_default_chain()
        import json
        try:
            canonical = json.dumps(action, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            canonical = str(action)
        action_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        pm = chain.commit(
            event={"custodian_id": custodian_id, "action_hash": action_hash},
            info={"layer": "receipt_ledger"},
        )

        rec = ProofReceipt(
            receipt_id=str(uuid.uuid4()),
            custodian_id=custodian_id,
            action_hash=action_hash,
            wake_receipt_hash=pm.receipt_hash().hex(),
            timestamp=time.time(),
        )
        self._receipts.append(rec)
        return rec

    @property
    def receipts(self) -> List[ProofReceipt]:
        """All recorded proof receipts (immutable snapshot)."""
        return list(self._receipts)

    # Alias for consistency with the ConsentLedger API pattern
    @property
    def records(self) -> List[ProofReceipt]:
        """All recorded proof receipts (immutable snapshot). Alias for :attr:`receipts`."""
        return list(self._receipts)

    def __len__(self) -> int:
        return len(self._receipts)

    def has_receipt_for(self, action_hash: str) -> bool:
        """Return True iff at least one receipt exists for *action_hash*."""
        return any(r.action_hash == action_hash for r in self._receipts)


def make_receipt_invariant(
    ledger: ReceiptLedger,
    action_hasher: Callable[[Any, Any, Any], str],
    version: str = "1.0.0",
) -> Invariant:
    """Return a UVK :class:`~uvk.Invariant` enforcing Layer 3.

    The invariant returns False when the ledger contains no proof receipt
    for the current action, denying execution until a receipt is recorded.

    Parameters
    ----------
    ledger:
        The :class:`ReceiptLedger` that stores proof receipts.
    action_hasher:
        Pure function ``(state, action, inputs) → action_hash_hex``.
        Must be deterministic and side-effect-free.
    version:
        Invariant version string.
    """

    def _check(state: Any, action: Any, inputs: Any) -> bool:
        action_hash = action_hasher(state, action, inputs)
        return ledger.has_receipt_for(action_hash)

    return Invariant(
        name    = "tethered_agency:receipt_required",
        version = version,
        check   = _check,
    )


# ---------------------------------------------------------------------------
# Layer 4 – System-Wide Feedback  (No feedback → No functional ecosystem)
# ---------------------------------------------------------------------------


class FeedbackStatus(Enum):
    """Overall health status of the TAS ecosystem."""
    HEALTHY   = auto()  # All four layers are satisfied.
    DEGRADED  = auto()  # At least one layer is unsatisfied but recoverable.
    INOPERABLE = auto() # Critical layer failure; system must halt.


@dataclass
class LayerReport:
    """Diagnostic report for a single recursive correction layer.

    Attributes
    ----------
    layer_number:
        1–4 corresponding to the correction layer index.
    layer_name:
        Human-readable layer label.
    satisfied:
        True iff the layer's invariant is currently satisfied.
    detail:
        Optional diagnostic message.
    """

    layer_number: int
    layer_name:   str
    satisfied:    bool
    detail:       str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer": self.layer_number,
            "name":  self.layer_name,
            "satisfied": self.satisfied,
            "detail": self.detail,
        }


@dataclass
class EcosystemFeedback:
    """Aggregated system-wide feedback across all four correction layers.

    Attributes
    ----------
    status:
        Overall :class:`FeedbackStatus`.
    layer_reports:
        Per-layer diagnostic entries.
    timestamp:
        Unix epoch when the feedback snapshot was taken.
    """

    status:        FeedbackStatus
    layer_reports: List[LayerReport]
    timestamp:     float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status":        self.status.name,
            "layer_reports": [r.to_dict() for r in self.layer_reports],
            "timestamp":     self.timestamp,
        }

    @property
    def all_satisfied(self) -> bool:
        """Return True iff every layer report is satisfied."""
        return all(r.satisfied for r in self.layer_reports)

    @property
    def failed_layers(self) -> List[int]:
        """Return the layer numbers that are not satisfied."""
        return [r.layer_number for r in self.layer_reports if not r.satisfied]


class TetheredAgencySystem:
    """Orchestrator that evaluates all four recursive correction layers.

    The TAS evaluates each layer in sequence.  A failure at any layer
    produces a :class:`FeedbackStatus` of DEGRADED or INOPERABLE and
    exposes which layers require remediation.

    Parameters
    ----------
    custodian:
        The live :class:`AuthorialCustodian` sponsoring the session.
    heartbeat:
        The :class:`AuthorialHeartbeat` tracking custodian presence.
    receipt_ledger:
        The :class:`ReceiptLedger` holding proof receipts for admitted
        actions.
    wake_chain:
        The :class:`~wake_chain.WakeChain` providing receipt continuity.
        Defaults to the process-level chain.
    """

    # Layer numbers are the canonical correction layer index (1–4).
    _LAYER_NAMES: Dict[int, str] = {
        1: "authorial_custodian",
        2: "authorial_heartbeat",
        3: "provable_receipts",
        4: "system_feedback",
    }

    def __init__(
        self,
        custodian:      Optional[AuthorialCustodian] = None,
        heartbeat:      Optional[AuthorialHeartbeat] = None,
        receipt_ledger: Optional[ReceiptLedger] = None,
        wake_chain:     Optional[WakeChain] = None,
    ) -> None:
        self.custodian      = custodian
        self.heartbeat      = heartbeat
        self.receipt_ledger = receipt_ledger or ReceiptLedger()
        self.wake           = wake_chain if wake_chain is not None else get_default_chain()
        self._feedback_history: List[EcosystemFeedback] = []

    # ------------------------------------------------------------------
    # Layer evaluation
    # ------------------------------------------------------------------

    def evaluate(self, at: Optional[float] = None) -> EcosystemFeedback:
        """Run all four correction layers and return an :class:`EcosystemFeedback`.

        Parameters
        ----------
        at:
            Wall-clock evaluation timestamp (defaults to now).

        Returns
        -------
        EcosystemFeedback
            Aggregated feedback snapshot.
        """
        now = at if at is not None else time.time()
        reports: List[LayerReport] = []

        # Layer 1: Authorial Custodian
        l1_ok, l1_detail = self._check_custodian()
        reports.append(LayerReport(1, self._LAYER_NAMES[1], l1_ok, l1_detail))

        # Layer 2: Authorial Heartbeat
        l2_ok, l2_detail = self._check_heartbeat(at=now)
        reports.append(LayerReport(2, self._LAYER_NAMES[2], l2_ok, l2_detail))

        # Layer 3: Provable Receipts
        l3_ok, l3_detail = self._check_receipts()
        reports.append(LayerReport(3, self._LAYER_NAMES[3], l3_ok, l3_detail))

        # Layer 4: System Feedback (wake chain integrity)
        l4_ok, l4_detail = self._check_feedback()
        reports.append(LayerReport(4, self._LAYER_NAMES[4], l4_ok, l4_detail))

        # Determine overall status
        if all(r.satisfied for r in reports):
            status = FeedbackStatus.HEALTHY
        elif l1_ok and l2_ok:
            # Custodian and heartbeat present – system is degraded but recoverable
            status = FeedbackStatus.DEGRADED
        else:
            # Missing custodian or dead heartbeat is a critical failure
            status = FeedbackStatus.INOPERABLE

        feedback = EcosystemFeedback(
            status=status,
            layer_reports=reports,
            timestamp=now,
        )
        self._feedback_history.append(feedback)
        return feedback

    # ------------------------------------------------------------------
    # Convenience predicates
    # ------------------------------------------------------------------

    def is_operational(self, at: Optional[float] = None) -> bool:
        """Return True iff the system is fully operational (all 4 layers pass)."""
        return self.evaluate(at=at).status == FeedbackStatus.HEALTHY

    def assert_operational(self, at: Optional[float] = None) -> None:
        """Raise :class:`TASInoperableError` if any correction layer fails."""
        feedback = self.evaluate(at=at)
        if not feedback.all_satisfied:
            raise TASInoperableError(feedback)

    # ------------------------------------------------------------------
    # Internal layer checks
    # ------------------------------------------------------------------

    def _check_custodian(self) -> tuple[bool, str]:
        if self.custodian is None:
            return False, "No authorial custodian registered – system has no human anchor"
        if not self.custodian.is_valid():
            return False, (
                f"Custodian {self.custodian.custodian_id!r} failed integrity check "
                "(sponsor_hash mismatch)"
            )
        return True, f"Custodian {self.custodian.name!r} verified"

    def _check_heartbeat(self, at: Optional[float] = None) -> tuple[bool, str]:
        if self.heartbeat is None:
            return False, "No authorial heartbeat registered – system privilege absent"
        now = at if at is not None else time.time()
        if not self.heartbeat.is_alive(at=now):
            elapsed = now - self.heartbeat._last_beat
            return False, (
                f"Heartbeat for custodian {self.heartbeat.custodian_id!r} expired "
                f"(elapsed={elapsed:.1f}s > max={self.heartbeat.max_interval}s)"
            )
        remaining = self.heartbeat.seconds_until_expiry(at=now)
        return True, f"Heartbeat alive ({remaining:.1f}s until expiry)"

    def _check_receipts(self) -> tuple[bool, str]:
        count = len(self.receipt_ledger)
        if count == 0:
            return False, "Receipt ledger is empty – no provable action history exists"
        return True, f"Receipt ledger contains {count} provable receipt(s)"

    def _check_feedback(self) -> tuple[bool, str]:
        # Wake chain integrity provides the system-wide feedback signal
        if not self.wake.verify():
            return False, "Wake chain integrity check failed – system feedback loop broken"
        n = len(self.wake)
        return True, f"Wake chain intact ({n} receipt(s) committed)"

    # ------------------------------------------------------------------
    # Feedback history
    # ------------------------------------------------------------------

    @property
    def feedback_history(self) -> List[EcosystemFeedback]:
        """All recorded :class:`EcosystemFeedback` snapshots."""
        return list(self._feedback_history)


# ---------------------------------------------------------------------------
# TASInoperableError – raised on assert_operational failure
# ---------------------------------------------------------------------------


class TASInoperableError(Exception):
    """Raised when one or more TAS recursive correction layers fail.

    Attributes
    ----------
    feedback:
        The :class:`EcosystemFeedback` snapshot that triggered the error.
    """

    def __init__(self, feedback: EcosystemFeedback) -> None:
        self.feedback = feedback
        failed = feedback.failed_layers
        super().__init__(
            f"TAS inoperable: correction layer(s) {failed} unsatisfied "
            f"(status={feedback.status.name})"
        )


# ---------------------------------------------------------------------------
# Convenience factory – build a fully-wired TAS from a custodian identity
# ---------------------------------------------------------------------------


def create_tethered_session(
    custodian_id: str,
    name: str,
    heartbeat_interval: float = 300.0,
    wake_chain: Optional[WakeChain] = None,
) -> TetheredAgencySystem:
    """Create a :class:`TetheredAgencySystem` pre-wired with a live custodian.

    The returned system has Layer 1 and Layer 2 satisfied immediately.
    Layer 3 becomes satisfied once the first action is recorded via
    :meth:`TetheredAgencySystem.receipt_ledger.record`.
    Layer 4 is satisfied once the wake chain contains at least one receipt.

    Parameters
    ----------
    custodian_id:
        Unique identifier for the human custodian.
    name:
        Human-readable custodian name.
    heartbeat_interval:
        Maximum allowed silence before the heartbeat expires (seconds).
    wake_chain:
        Optional :class:`~wake_chain.WakeChain` to use.

    Returns
    -------
    TetheredAgencySystem
        A freshly initialised TAS instance.
    """
    custodian = AuthorialCustodian(custodian_id=custodian_id, name=name)
    heartbeat = AuthorialHeartbeat(
        custodian_id=custodian_id,
        max_interval=heartbeat_interval,
    )
    return TetheredAgencySystem(
        custodian=custodian,
        heartbeat=heartbeat,
        wake_chain=wake_chain,
    )
