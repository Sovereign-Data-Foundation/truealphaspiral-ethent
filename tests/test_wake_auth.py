"""Unit tests for the Wake-Based Authentication + Phoenix Protocol implementation.

Covers:
- WakeChain: commit, verify, replay, anti-replay (§5)
- Capability model: retype, mint, revoke, invoke, move (§3)
- UVK: admission control, invariant enforcement, τ verification (§2, §4)
- Stability metrics: SDI, PhaseMonitor (§6)
- Phoenix Protocol: breach triggers, recovery sequence, receipt emission (§7)
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from wake_chain import WakeChain, ProvenanceMark, reset_default_chain, get_default_chain
from capability import Capability, CapabilityTable, CapabilityError, Right, ALL_RIGHTS
from uvk import UVK, Invariant, AdmissionStatus
from stability import (
    semantic_drift_index,
    cosine_similarity,
    DriftTracker,
    PhaseMonitor,
    PhaseSlip,
)
from phoenix import Phoenix, BreachType, PhoenixState


# ===========================================================================
# WakeChain tests (§5)
# ===========================================================================


class TestWakeChain:
    def test_empty_chain_is_valid(self):
        chain = WakeChain()
        assert chain.verify()
        assert len(chain) == 0

    def test_commit_single_receipt(self):
        chain = WakeChain()
        pm = chain.commit(event={"action": "test"})
        assert pm.seq == 0
        assert pm.prev == bytes(32)
        assert len(chain) == 1
        assert chain.verify()

    def test_chain_multi_commit(self):
        chain = WakeChain()
        for i in range(5):
            chain.commit(event={"step": i})
        assert len(chain) == 5
        assert chain.verify()

    def test_seq_is_monotone(self):
        chain = WakeChain()
        for i in range(3):
            pm = chain.commit(event={"n": i})
            assert pm.seq == i

    def test_prev_links_correctly(self):
        chain = WakeChain()
        pm0 = chain.commit(event={"a": 0})
        pm1 = chain.commit(event={"a": 1})
        assert pm1.prev == pm0.receipt_hash()

    def test_tamper_detection_sig(self):
        chain = WakeChain()
        chain.commit(event={"x": 1})
        # Tamper the signature of the first receipt
        original = chain._receipts[0]
        tampered = ProvenanceMark(
            id=original.id,
            seq=original.seq,
            prev=original.prev,
            key_commit=original.key_commit,
            event_hash=original.event_hash,
            info=original.info,
            sig=bytes(32),  # wrong sig
        )
        chain._receipts[0] = tampered
        assert not chain.verify()

    def test_tamper_detection_prev(self):
        chain = WakeChain()
        chain.commit(event={"x": 1})
        pm0 = chain._receipts[0]
        # Replace first receipt with correct sig but wrong prev
        wrong_prev = ProvenanceMark(
            id=pm0.id,
            seq=pm0.seq,
            prev=b"\xff" * 32,
            key_commit=pm0.key_commit,
            event_hash=pm0.event_hash,
            info=pm0.info,
        ).sign(chain._key)
        chain._receipts[0] = wrong_prev
        assert not chain.verify()

    def test_anti_replay_seq(self):
        chain = WakeChain()
        chain.commit(event={"x": 1})
        chain.commit(event={"x": 2})
        # Duplicate seq 0 at position 1
        dup = ProvenanceMark(
            id=chain._receipts[0].id,
            seq=0,  # wrong seq (should be 1)
            prev=chain._receipts[0].prev,
            key_commit=bytes(32),
            event_hash=chain._receipts[0].event_hash,
            info={},
        ).sign(chain._key)
        chain._receipts[1] = dup
        assert not chain.verify()

    def test_replay_from(self):
        chain = WakeChain()
        for i in range(4):
            chain.commit(event={"i": i})
        replayed = chain.replay_from(2)
        assert replayed.verify()
        assert len(replayed) == 4  # 2 retained + 2 re-committed

    def test_replay_from_invalid_seq_raises(self):
        chain = WakeChain()
        chain.commit(event={"x": 1})
        with pytest.raises(IndexError):
            chain.replay_from(5)

    def test_receipt_hash_deterministic(self):
        chain = WakeChain(session_id="fixed-id", uvk_key=b"k" * 32)
        pm = chain.commit(event={"x": 1})
        assert pm.receipt_hash() == pm.receipt_hash()

    def test_default_chain_singleton(self):
        chain1 = get_default_chain()
        chain2 = get_default_chain()
        assert chain1 is chain2

    def test_reset_default_chain(self):
        c1 = reset_default_chain()
        c2 = get_default_chain()
        assert c1 is c2


# ===========================================================================
# Capability model tests (§3)
# ===========================================================================


class TestCapabilityTable:
    def test_retype_creates_live_cap(self):
        ct = CapabilityTable()
        cap = ct.retype("resource_a")
        assert ct.is_live(cap)

    def test_retype_tag_valid(self):
        ct = CapabilityTable()
        cap = ct.retype("resource_a")
        assert cap.verify_tag(ct._key)

    def test_mint_subset_rights(self):
        ct = CapabilityTable()
        parent = ct.retype("res", ALL_RIGHTS)
        child = ct.mint(parent, Right.READ | Right.EXECUTE)
        assert ct.is_live(child)
        assert child.has_right(Right.READ)
        assert not child.has_right(Right.WRITE)

    def test_mint_requires_mint_right(self):
        ct = CapabilityTable()
        parent = ct.retype("res", Right.READ)  # no MINT right
        with pytest.raises(CapabilityError, match="MINT"):
            ct.mint(parent, Right.READ)

    def test_mint_cannot_exceed_parent_rights(self):
        ct = CapabilityTable()
        parent = ct.retype("res", Right.READ | Right.MINT)
        with pytest.raises(CapabilityError):
            ct.mint(parent, Right.WRITE)  # WRITE not in parent

    def test_revoke_removes_cap(self):
        ct = CapabilityTable()
        cap = ct.retype("res")
        ct.revoke(cap)
        assert not ct.is_live(cap)

    def test_revoke_cascades(self):
        ct = CapabilityTable()
        parent = ct.retype("res", ALL_RIGHTS)
        child = ct.mint(parent, Right.READ | Right.MINT)
        grandchild = ct.mint(child, Right.READ)
        ct.revoke(parent)
        assert not ct.is_live(child)
        assert not ct.is_live(grandchild)
        assert ct.live_count == 0

    def test_invoke_admitted(self):
        ct = CapabilityTable()
        cap = ct.retype("res", Right.READ)
        result = ct.invoke(cap, Right.READ, msg="hello")
        assert result["admitted"] is True

    def test_invoke_denied_missing_right(self):
        ct = CapabilityTable()
        cap = ct.retype("res", Right.READ)
        with pytest.raises(CapabilityError):
            ct.invoke(cap, Right.WRITE)

    def test_invoke_denied_revoked(self):
        ct = CapabilityTable()
        cap = ct.retype("res")
        ct.revoke(cap)
        with pytest.raises(CapabilityError):
            ct.invoke(cap, Right.READ)

    def test_move_transfers_resource(self):
        ct = CapabilityTable()
        cap = ct.retype("res_a", Right.READ | Right.MOVE | Right.MINT)
        new_cap = ct.move(cap, "res_b")
        assert new_cap.resource == "res_b"
        assert not ct.is_live(cap)
        assert ct.is_live(new_cap)

    def test_move_denied_without_move_right(self):
        ct = CapabilityTable()
        cap = ct.retype("res", Right.READ)
        with pytest.raises(CapabilityError, match="MOVE"):
            ct.move(cap, "res_b")

    def test_forgery_rejected(self):
        ct = CapabilityTable()
        ct.retype("res")
        # Construct a forged capability (wrong tag)
        forged = Capability(
            cap_id="forged-id",
            resource="res",
            rights=ALL_RIGHTS,
            tag=bytes(32),
        )
        # Manually inject into live table to bypass retype
        ct._live["forged-id"] = forged
        with pytest.raises(CapabilityError, match="tag"):
            ct.invoke(forged, Right.READ)


# ===========================================================================
# UVK tests (§2, §4)
# ===========================================================================


class TestUVK:
    def _make_uvk(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("test_resource", Right.EXECUTE | Right.MINT)
        inv = Invariant(
            name="always_true",
            version="1.0",
            check=lambda _s, _a, _u: True,
        )
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[inv])
        return uvk, ct, cap, chain

    def test_admit_success(self):
        uvk, ct, cap, chain = self._make_uvk()
        result = uvk.admit(cap, Right.EXECUTE, action="run_test")
        assert result.admitted
        assert result.receipt is not None
        assert result.status == AdmissionStatus.ADMITTED

    def test_admit_commits_receipt(self):
        uvk, ct, cap, chain = self._make_uvk()
        before = len(chain)
        uvk.admit(cap, Right.EXECUTE, action="run_test")
        assert len(chain) == before + 1

    def test_admit_denied_wrong_right(self):
        uvk, ct, cap, _ = self._make_uvk()
        # cap only has EXECUTE | MINT, not READ
        cap_read_only = ct.retype("res2", Right.READ)
        result = uvk.admit(cap_read_only, Right.WRITE, action="write")
        assert not result.admitted
        assert result.status == AdmissionStatus.DENIED_CAPABILITY

    def test_admit_denied_invariant_failure(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("res", Right.EXECUTE | Right.MINT)
        failing_inv = Invariant(
            name="always_false",
            version="1.0",
            check=lambda _s, _a, _u: False,
        )
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[failing_inv])
        result = uvk.admit(cap, Right.EXECUTE, action="anything")
        assert not result.admitted
        assert result.status == AdmissionStatus.DENIED_INVARIANT
        assert "always_false" in result.failed_invariants

    def test_admit_denied_revoked_cap(self):
        uvk, ct, cap, _ = self._make_uvk()
        ct.revoke(cap)
        result = uvk.admit(cap, Right.EXECUTE, action="run")
        assert not result.admitted
        assert result.status == AdmissionStatus.DENIED_CAPABILITY

    def test_breach_log_populated_on_denial(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("res", Right.EXECUTE | Right.MINT)
        failing_inv = Invariant(
            name="fail", version="1.0", check=lambda *_: False
        )
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[failing_inv])
        uvk.admit(cap, Right.EXECUTE, action="x")
        assert len(uvk.breach_log) == 1

    def test_verify_tau_true(self):
        uvk, _, cap, _ = self._make_uvk()
        uvk.admit(cap, Right.EXECUTE, action="ok")
        assert uvk.verify_tau()

    def test_verify_tau_false_no_invariants(self):
        chain = WakeChain()
        ct = CapabilityTable()
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[])
        assert not uvk.verify_tau()


# ===========================================================================
# Stability metric tests (§6)
# ===========================================================================


class TestSDI:
    def test_identical_vectors(self):
        v = [1.0, 0.0, 0.0]
        assert semantic_drift_index(v, v) == pytest.approx(0.0)

    def test_orthogonal_vectors(self):
        a = [1.0, 0.0]
        b = [0.0, 1.0]
        assert semantic_drift_index(a, b) == pytest.approx(1.0)

    def test_anti_aligned_vectors(self):
        a = [1.0, 0.0]
        b = [-1.0, 0.0]
        assert semantic_drift_index(a, b) == pytest.approx(2.0)

    def test_zero_vector_gives_sdi_one(self):
        # cosine_similarity returns 0 for zero vector → SDI = 1
        a = [0.0, 0.0]
        b = [1.0, 0.0]
        assert semantic_drift_index(a, b) == pytest.approx(1.0)

    def test_mismatched_lengths_raises(self):
        with pytest.raises(ValueError):
            semantic_drift_index([1.0], [1.0, 2.0])

    def test_drift_tracker_first_call_returns_none(self):
        dt = DriftTracker()
        result = dt.update([1.0, 0.0])
        assert result is None

    def test_drift_tracker_stable(self):
        dt = DriftTracker(threshold=0.1)
        dt.update([1.0, 0.0])
        sdi = dt.update([0.99, 0.14])  # small drift
        assert sdi is not None
        assert not dt.is_drifted()

    def test_drift_tracker_drifted(self):
        dt = DriftTracker(threshold=0.1)
        dt.update([1.0, 0.0])
        dt.update([0.0, 1.0])  # orthogonal = SDI 1.0
        assert dt.is_drifted()


class TestPhaseMonitor:
    def test_no_slip_below_threshold(self):
        pm = PhaseMonitor(phi_max=0.5, n_consecutive=3)
        for _ in range(10):
            pm.update(0.1)
        assert pm.total_slips == 0
        assert not pm.is_in_slip()

    def test_single_slip_below_consecutive(self):
        pm = PhaseMonitor(phi_max=0.5, n_consecutive=3)
        pm.update(0.6)  # slip
        pm.update(0.1)  # not slip
        assert pm.total_slips == 1
        assert pm.consecutive_slips == 0

    def test_critical_phase_slip_raises(self):
        pm = PhaseMonitor(phi_max=0.5, n_consecutive=3)
        with pytest.raises(PhaseSlip):
            pm.update(1.0)
            pm.update(1.0)
            pm.update(1.0)

    def test_consecutive_reset_on_recovery(self):
        pm = PhaseMonitor(phi_max=0.5, n_consecutive=3)
        pm.update(1.0)  # slip
        pm.update(1.0)  # slip (count=2)
        pm.update(0.1)  # no slip → count reset
        assert pm.consecutive_slips == 0


# ===========================================================================
# Phoenix Protocol tests (§7)
# ===========================================================================


class TestPhoenix:
    def _make_setup(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("phoenix_res", Right.EXECUTE | Right.MINT)
        inv = Invariant("ok_inv", "1.0", lambda *_: True)
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[inv])
        # Admit a few transitions to populate the chain
        for i in range(3):
            uvk.admit(cap, Right.EXECUTE, action=f"step_{i}")
        phoenix = Phoenix(uvk=uvk, wake_chain=chain)
        return phoenix, uvk, chain, cap

    def test_trigger_invariant_violation(self):
        phoenix, _, _, _ = self._make_setup()
        receipt = phoenix.trigger(BreachType.INVARIANT_VIOLATION, details={"inv": "test_inv"})
        assert receipt.breach_type == BreachType.INVARIANT_VIOLATION
        assert receipt.breach_code == "PHX-001"
        assert receipt.receipt_id is not None

    def test_trigger_wake_discontinuity(self):
        phoenix, _, _, _ = self._make_setup()
        receipt = phoenix.trigger(BreachType.WAKE_DISCONTINUITY)
        assert receipt.breach_code == "PHX-002"

    def test_trigger_phase_slip(self):
        phoenix, _, _, _ = self._make_setup()
        receipt = phoenix.trigger(BreachType.PHASE_SLIP)
        assert receipt.breach_code == "PHX-003"

    def test_trigger_capability_anomaly(self):
        phoenix, _, _, _ = self._make_setup()
        receipt = phoenix.trigger(BreachType.CAPABILITY_ANOMALY)
        assert receipt.breach_code == "PHX-004"

    def test_state_machine_transitions_on_success(self):
        phoenix, uvk, chain, _ = self._make_setup()
        # uvk.verify_tau() must return True for relaunched state
        assert uvk.verify_tau()
        receipt = phoenix.trigger(BreachType.INVARIANT_VIOLATION)
        # If tau is preserved and replay succeeds, should relaunch
        assert phoenix.state == PhoenixState.RELAUNCHED
        assert receipt.relaunch_certificate is not None
        assert not phoenix.is_frozen

    def test_receipt_emitted_and_stored(self):
        phoenix, _, _, _ = self._make_setup()
        phoenix.trigger(BreachType.INVARIANT_VIOLATION)
        assert len(phoenix.receipts) == 1

    def test_rollback_target_populated(self):
        phoenix, _, _, _ = self._make_setup()
        receipt = phoenix.trigger(BreachType.WAKE_DISCONTINUITY)
        assert receipt.rollback_target_hash != ""

    def test_hcs_correction_when_needed(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("res", Right.EXECUTE | Right.MINT)
        # UVK with NO invariants → verify_tau() returns False (no ethical constraints)
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[])
        uvk.admit(cap, Right.EXECUTE, action="step_0")
        phoenix = Phoenix(uvk=uvk, wake_chain=chain)
        receipt = phoenix.trigger(BreachType.INVARIANT_VIOLATION)
        # tau is False (no invariants), so human action is required
        assert receipt.human_action_required

    def test_receipt_to_dict(self):
        phoenix, _, _, _ = self._make_setup()
        receipt = phoenix.trigger(BreachType.INVARIANT_VIOLATION)
        d = receipt.to_dict()
        assert "breach_type" in d
        assert "breach_code" in d
        assert "rollback_target_hash" in d
        assert "replay_result" in d
        assert "relaunch_certificate" in d
        assert "timestamp" in d


# ===========================================================================
# Integration: UVK breach → Phoenix activation
# ===========================================================================


class TestUVKPhoenixIntegration:
    def test_breach_triggers_phoenix(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("res", Right.EXECUTE | Right.MINT)
        inv = Invariant("ok", "1.0", lambda *_: True)

        phoenix_receipts = []

        def on_breach(result):
            p = Phoenix(uvk=uvk, wake_chain=chain)
            pr = p.trigger(BreachType.CAPABILITY_ANOMALY, details={"result": str(result.status)})
            phoenix_receipts.append(pr)

        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[inv], on_breach=on_breach)
        # Revoke the cap then try to admit → triggers breach
        ct.revoke(cap)
        uvk.admit(cap, Right.EXECUTE, action="bad_action")

        assert len(phoenix_receipts) == 1
        assert phoenix_receipts[0].breach_type == BreachType.CAPABILITY_ANOMALY

    def test_admitted_actions_build_valid_wake(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("res", Right.EXECUTE | Right.MINT)
        inv = Invariant("ok", "1.0", lambda *_: True)
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[inv])

        for i in range(5):
            r = uvk.admit(cap, Right.EXECUTE, action=f"action_{i}")
            assert r.admitted

        assert chain.verify()
        assert len(chain) == 5
