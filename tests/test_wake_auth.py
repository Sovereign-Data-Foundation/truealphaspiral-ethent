# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0
"""
Unit tests for the Wake-Based Authentication + Phoenix Protocol implementation.

Covers:
- WakeChain: commit, verify, replay, anti-replay (§5)
- Capability model: retype, mint, revoke, invoke, move (§3)
- UVK: admission control, invariant enforcement, τ verification (§2, §4)
- Stability metrics: SDI, PhaseMonitor (§6)
- Phoenix Protocol: breach triggers, recovery sequence, receipt emission (§7)
"""

from __future__ import annotations

import sys
import os
import time

# Ensure the parent directory is on sys.path so the source modules are importable
# regardless of how pytest is invoked.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from wake_chain import WakeChain, ProvenanceMark, reset_default_chain
from capability import Capability, CapabilityError, CapabilityTable, Right, ALL_RIGHTS
from uvk import AdmissionStatus, Invariant, Receipt, UVK
from stability import (
    DriftTracker,
    PhaseMonitor,
    PhaseSlip,
    cosine_similarity,
    semantic_drift_index,
)
from phoenix import BreachType, Phoenix, PhoenixReceipt, PhoenixState
from yknot import AdmissibilityRule, P1AdmissibilityError, YKnot
from digital_rights import (
    ConsentLedger,
    UnalienableRight,
    consent_holds,
    make_consent_invariant,
)


# ===========================================================================
# WakeChain tests
# ===========================================================================


class TestWakeChain:
    """Tests for tamper-evident provenance ledger (§5)."""

    def test_commit_and_verify(self) -> None:
        """Commit three marks and confirm the chain verifies cleanly."""
        chain = WakeChain()
        chain.commit("alice", "login")
        chain.commit("alice", "read_file", state_snapshot={"file": "secret.txt"})
        chain.commit("bob", "write_file")
        assert chain.verify() is True
        assert len(chain.marks) == 3

    def test_anti_replay(self) -> None:
        """Committing the same nonce twice must raise ValueError."""
        chain = WakeChain()
        chain.commit("alice", "action", nonce="unique-nonce-1")
        with pytest.raises(ValueError, match="replay"):
            chain.commit("alice", "action", nonce="unique-nonce-1")

    def test_verify_tampered(self) -> None:
        """Mutating a mark's digest must cause verify() to return False."""
        chain = WakeChain()
        chain.commit("alice", "action-a")
        chain.commit("alice", "action-b")
        # Directly corrupt the stored digest of the first mark.
        chain._marks[0].digest = "deadbeef" * 8  # type: ignore[attr-defined]
        assert chain.verify() is False

    def test_replay(self) -> None:
        """Replaying a subset of a chain produces a valid, shorter chain."""
        chain = WakeChain()
        chain.commit("alice", "step-0", nonce="n0")
        chain.commit("alice", "step-1", nonce="n1")
        chain.commit("alice", "step-2", nonce="n2")

        replayed = chain.replay(up_to_index=1)
        assert len(replayed.marks) == 2
        assert replayed.verify() is True
        assert replayed.marks[0].action == "step-0"
        assert replayed.marks[1].action == "step-1"


# ===========================================================================
# Capability tests
# ===========================================================================


class TestCapability:
    """Tests for capability-based access control (§3)."""

    def test_mint_and_invoke(self) -> None:
        """Mint a capability then successfully invoke it with the correct right."""
        table = CapabilityTable()
        cap = table.mint("resource://data", Right.READ | Right.INVOKE, "alice")
        result = table.invoke(cap.cap_id, Right.READ)
        assert result.cap_id == cap.cap_id

    def test_invoke_missing_right(self) -> None:
        """Invoking with a right not present in the capability raises CapabilityError."""
        table = CapabilityTable()
        cap = table.mint("resource://data", Right.READ, "alice")
        with pytest.raises(CapabilityError):
            table.invoke(cap.cap_id, Right.WRITE)

    def test_revoke(self) -> None:
        """Invoking a revoked capability raises CapabilityError."""
        table = CapabilityTable()
        cap = table.mint("resource://data", Right.READ, "alice")
        table.revoke(cap.cap_id)
        with pytest.raises(CapabilityError):
            table.invoke(cap.cap_id, Right.READ)

    def test_retype(self) -> None:
        """Retyping a capability changes its rights."""
        table = CapabilityTable()
        cap = table.mint("resource://data", Right.READ, "alice")
        updated = table.retype(cap.cap_id, Right.WRITE)
        assert updated.rights == Right.WRITE
        assert not updated.has_right(Right.READ)

    def test_move(self) -> None:
        """Moving a capability transfers ownership to the new owner."""
        table = CapabilityTable()
        cap = table.mint("resource://data", Right.READ, "alice")
        moved = table.move(cap.cap_id, "bob")
        assert moved.owner == "bob"
        assert table.list_for("alice") == []
        assert table.list_for("bob") == [moved]


# ===========================================================================
# UVK tests
# ===========================================================================


class TestUVK:
    """Tests for Universal Verifier Kernel admission control (§2, §4)."""

    def test_uvk_admit(self) -> None:
        """An always-true invariant results in ADMITTED status."""
        chain = WakeChain()
        uvk = UVK(wake_chain=chain)
        uvk.add_invariant(Invariant("always_true", lambda s, a, u: True))
        receipt = uvk.admit("alice", "do_thing")
        assert receipt.status == AdmissionStatus.ADMITTED
        assert receipt.invariant_results["always_true"] is True

    def test_uvk_reject(self) -> None:
        """An always-false invariant results in REJECTED status."""
        chain = WakeChain()
        uvk = UVK(wake_chain=chain)
        uvk.add_invariant(Invariant("always_false", lambda s, a, u: False))
        receipt = uvk.admit("alice", "do_thing")
        assert receipt.status == AdmissionStatus.REJECTED
        assert receipt.invariant_results["always_false"] is False

    def test_uvk_with_capability(self) -> None:
        """Providing a valid INVOKE capability results in ADMITTED."""
        chain = WakeChain()
        table = CapabilityTable()
        cap = table.mint("resource://x", Right.INVOKE, "alice")
        uvk = UVK(wake_chain=chain, capability_table=table)
        receipt = uvk.admit(
            "alice",
            "invoke_x",
            required_capability=cap.cap_id,
        )
        assert receipt.status == AdmissionStatus.ADMITTED


# ===========================================================================
# Stability tests
# ===========================================================================


class TestStability:
    """Tests for stability metrics (§6)."""

    def test_cosine_similarity_identical(self) -> None:
        """Cosine similarity of a vector with itself is 1.0."""
        v = [1.0, 2.0, 3.0]
        assert abs(cosine_similarity(v, v) - 1.0) < 1e-9

    def test_cosine_similarity_orthogonal(self) -> None:
        """Cosine similarity of orthogonal vectors is 0.0."""
        a = [1.0, 0.0]
        b = [0.0, 1.0]
        assert abs(cosine_similarity(a, b)) < 1e-9

    def test_semantic_drift_index_zero(self) -> None:
        """SDI between identical vectors is 0.0."""
        v = [1.0, 1.0, 1.0]
        assert abs(semantic_drift_index(v, v)) < 1e-9

    def test_drift_tracker(self) -> None:
        """DriftTracker computes correct rolling mean."""
        tracker = DriftTracker(window=5)
        tracker.update(0.2)
        tracker.update(0.4)
        tracker.update(0.6)
        assert abs(tracker.mean - 0.4) < 1e-9
        assert len(tracker.samples) == 3

    def test_phase_monitor_ok(self) -> None:
        """Phase within threshold does not raise PhaseSlip."""
        monitor = PhaseMonitor(phi_max=1.0)
        monitor.check(0.5)   # should not raise

    def test_phase_monitor_slip(self) -> None:
        """Phase exceeding threshold raises PhaseSlip."""
        monitor = PhaseMonitor(phi_max=0.5)
        with pytest.raises(PhaseSlip):
            monitor.check(0.9)


# ===========================================================================
# Phoenix tests
# ===========================================================================


class TestPhoenix:
    """Tests for Phoenix Protocol breach handling (§7)."""

    def _make_phoenix(self) -> Phoenix:
        chain = WakeChain()
        uvk = UVK(wake_chain=chain)
        uvk.add_invariant(Invariant("always_true", lambda s, a, u: True))
        uvk.admit("system", "startup")
        return Phoenix(uvk=uvk, wake_chain=chain)

    def test_phoenix_trigger_freezes(self) -> None:
        """Triggering a breach transitions state to FROZEN."""
        phoenix = self._make_phoenix()
        phoenix.trigger(BreachType.INVARIANT_VIOLATION)
        assert phoenix.state == PhoenixState.FROZEN

    def test_phoenix_receipt_emitted(self) -> None:
        """trigger() returns a PhoenixReceipt with the correct breach_type."""
        phoenix = self._make_phoenix()
        receipt = phoenix.trigger(BreachType.WAKE_DISCONTINUITY, details={"info": "test"})
        assert isinstance(receipt, PhoenixReceipt)
        assert receipt.breach_type == BreachType.WAKE_DISCONTINUITY
        assert len(phoenix.receipts) == 1

    def test_phoenix_hcs_recovery(self) -> None:
        """After a breach, providing an HCS correction leads to RELAUNCHED state."""
        phoenix = self._make_phoenix()
        phoenix.trigger(BreachType.CRITICAL_PHASE_SLIP)
        assert phoenix.is_frozen is True
        success = phoenix.provide_hcs_correction("operator: reset phase lock")
        assert success is True
        assert phoenix.state == PhoenixState.RELAUNCHED

    def test_phoenix_is_frozen(self) -> None:
        """is_frozen property returns True immediately after a trigger."""
        phoenix = self._make_phoenix()
        assert phoenix.is_frozen is False
        phoenix.trigger(BreachType.CAPABILITY_ANOMALY)
        assert phoenix.is_frozen is True


# ===========================================================================
# YKnot tests
# ===========================================================================


class TestYKnot:
    """Tests for the Y-Knot Boundary Operator (§IV)."""

    def test_yknot_tie_admitted(self) -> None:
        """A passing rule results in an admitted receipt."""
        knot = YKnot([AdmissibilityRule("non_empty", lambda ctx: bool(ctx))])
        bid = knot.branch()
        receipt = knot.tie("valid action", branch_id=bid)
        assert receipt["admitted"] is True
        assert "non_empty" in receipt["rules_passed"]

    def test_yknot_tie_rejected(self) -> None:
        """A failing rule raises P1AdmissibilityError."""
        knot = YKnot([AdmissibilityRule("always_fail", lambda ctx: False)])
        bid = knot.branch()
        with pytest.raises(P1AdmissibilityError):
            knot.tie("any action", branch_id=bid)

    def test_yknot_refusal_integrity(self) -> None:
        """refusal_integrity reflects the fraction of rejected tie calls."""
        knot = YKnot()
        knot.add_rule(AdmissibilityRule("length_ok", lambda ctx: len(ctx) > 3))

        bid1 = knot.branch()
        knot.tie("long action", branch_id=bid1)  # passes

        bid2 = knot.branch()
        with pytest.raises(P1AdmissibilityError):
            knot.tie("no", branch_id=bid2)  # fails (len <= 3)

        assert knot.admitted == 1
        assert knot.rejected == 1
        assert abs(knot.refusal_integrity - 0.5) < 1e-9


# ===========================================================================
# Digital rights tests
# ===========================================================================


class TestDigitalRights:
    """Tests for the digital rights / consent framework."""

    def test_consent_grant_and_holds(self) -> None:
        """Granting consent makes consent_holds return True."""
        ledger = ConsentLedger()
        ledger.grant("user-1", UnalienableRight.PRIVACY | UnalienableRight.CONSENT)
        assert consent_holds(ledger, "user-1", UnalienableRight.PRIVACY) is True
        assert consent_holds(ledger, "user-1", UnalienableRight.CONSENT) is True

    def test_consent_revoke(self) -> None:
        """Revoking consent makes consent_holds return False."""
        ledger = ConsentLedger()
        ledger.grant("user-2", UnalienableRight.TRANSPARENCY)
        ledger.revoke("user-2", UnalienableRight.TRANSPARENCY)
        assert consent_holds(ledger, "user-2", UnalienableRight.TRANSPARENCY) is False

    def test_consent_expired(self) -> None:
        """An expired consent record makes consent_holds return False."""
        ledger = ConsentLedger()
        past = time.time() - 1.0  # already expired
        ledger.grant("user-3", UnalienableRight.PORTABILITY, expires_at=past)
        assert consent_holds(ledger, "user-3", UnalienableRight.PORTABILITY) is False

    def test_make_consent_invariant(self) -> None:
        """An invariant created by make_consent_invariant works inside the UVK."""
        ledger = ConsentLedger()
        ledger.grant("subject-a", UnalienableRight.AUTONOMY, governance_act="TAS-1")

        def _extractor(state: object, action: object, inputs: object) -> tuple:
            return ("subject-a", UnalienableRight.AUTONOMY, "TAS-1")

        inv = make_consent_invariant(ledger, _extractor, name="test_consent")

        chain = WakeChain()
        uvk = UVK(wake_chain=chain)
        uvk.add_invariant(inv)

        receipt = uvk.admit("subject-a", "autonomous_action")
        assert receipt.status == AdmissionStatus.ADMITTED
        assert receipt.invariant_results["test_consent"] is True

        # Revoke and re-check.
        ledger.revoke("subject-a", UnalienableRight.AUTONOMY)
        receipt2 = uvk.admit("subject-a", "autonomous_action")
        assert receipt2.status == AdmissionStatus.REJECTED
        assert receipt2.invariant_results["test_consent"] is False
