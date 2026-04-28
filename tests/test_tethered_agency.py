"""Tests for the Tethered Agency System (TAS) recursive correction layers.

Covers:
- AuthorialCustodian: identity commitment, validation (Layer 1)
- AuthorialHeartbeat: liveness, expiry, beat refresh (Layer 2)
- ReceiptLedger / ProofReceipt: recording and querying provable receipts (Layer 3)
- TetheredAgencySystem: full evaluation of all four layers (Layer 4)
- EcosystemFeedback: status, failed_layers, all_satisfied
- UVK invariant factories: custodian, heartbeat, receipt
- create_tethered_session: convenience factory
- TASInoperableError: raised on assert_operational failure
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

import hashlib
import time
import pytest

from tethered_agency import (
    AuthorialCustodian,
    AuthorialHeartbeat,
    EcosystemFeedback,
    FeedbackStatus,
    HeartbeatExpiredError,
    LayerReport,
    ProofReceipt,
    ReceiptLedger,
    TASInoperableError,
    TetheredAgencySystem,
    create_tethered_session,
    make_custodian_invariant,
    make_heartbeat_invariant,
    make_receipt_invariant,
)
from wake_chain import WakeChain, reset_default_chain


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_custodian(cid: str = "user-001", name: str = "Russell Nordland") -> AuthorialCustodian:
    return AuthorialCustodian(custodian_id=cid, name=name)


def _make_heartbeat(cid: str = "user-001", interval: float = 300.0) -> AuthorialHeartbeat:
    return AuthorialHeartbeat(custodian_id=cid, max_interval=interval)


# ===========================================================================
# Layer 1 – AuthorialCustodian
# ===========================================================================


class TestAuthorialCustodian:
    def test_custodian_is_valid_by_default(self):
        c = _make_custodian()
        assert c.is_valid()

    def test_sponsor_hash_computed_from_id_and_name(self):
        c = _make_custodian()
        expected = hashlib.sha256(f"{c.custodian_id}|{c.name}".encode()).hexdigest()
        assert c.sponsor_hash == expected

    def test_explicit_sponsor_hash_preserved(self):
        c = AuthorialCustodian(custodian_id="u1", name="Alice", sponsor_hash="custom")
        assert c.sponsor_hash == "custom"

    def test_invalid_sponsor_hash_detected(self):
        c = AuthorialCustodian(custodian_id="u1", name="Alice", sponsor_hash="wrong")
        assert not c.is_valid()

    def test_to_dict_structure(self):
        c = _make_custodian()
        d = c.to_dict()
        assert d["custodian_id"] == c.custodian_id
        assert d["name"] == c.name
        assert d["sponsor_hash"] == c.sponsor_hash

    def test_different_identities_produce_different_hashes(self):
        c1 = _make_custodian("u1", "Alice")
        c2 = _make_custodian("u2", "Bob")
        assert c1.sponsor_hash != c2.sponsor_hash

    def test_compute_hash_deterministic(self):
        c = _make_custodian()
        assert c.compute_hash() == c.compute_hash()


# ===========================================================================
# Layer 2 – AuthorialHeartbeat
# ===========================================================================


class TestAuthorialHeartbeat:
    def test_freshly_created_heartbeat_is_alive(self):
        hb = _make_heartbeat()
        assert hb.is_alive()

    def test_heartbeat_expires_after_max_interval(self):
        hb = _make_heartbeat(interval=1.0)
        future = time.time() + 2.0
        assert not hb.is_alive(at=future)

    def test_beat_refreshes_liveness(self):
        hb = _make_heartbeat(interval=1.0)
        future = time.time() + 2.0
        assert not hb.is_alive(at=future)
        hb.beat()
        # Now the beat time is refreshed; re-check a short window after beat
        assert hb.is_alive(at=hb._last_beat + 0.5)

    def test_assert_alive_passes_when_alive(self):
        hb = _make_heartbeat(interval=300.0)
        hb.assert_alive()  # must not raise

    def test_assert_alive_raises_when_expired(self):
        hb = _make_heartbeat(interval=1.0)
        with pytest.raises(HeartbeatExpiredError):
            hb.assert_alive(at=time.time() + 2.0)

    def test_seconds_until_expiry_positive_when_alive(self):
        hb = _make_heartbeat(interval=300.0)
        remaining = hb.seconds_until_expiry()
        assert remaining > 0

    def test_seconds_until_expiry_negative_when_expired(self):
        hb = _make_heartbeat(interval=1.0)
        remaining = hb.seconds_until_expiry(at=time.time() + 2.0)
        assert remaining < 0

    def test_beat_returns_timestamp(self):
        hb = _make_heartbeat()
        before = time.time()
        ts = hb.beat()
        after = time.time()
        assert before <= ts <= after

    def test_to_dict_contains_expected_keys(self):
        hb = _make_heartbeat()
        d = hb.to_dict()
        assert "custodian_id" in d
        assert "max_interval" in d
        assert "last_beat" in d


# ===========================================================================
# Layer 3 – ReceiptLedger / ProofReceipt
# ===========================================================================


class TestReceiptLedger:
    def setup_method(self):
        reset_default_chain()

    def test_empty_ledger_has_zero_length(self):
        ledger = ReceiptLedger()
        assert len(ledger) == 0

    def test_record_creates_receipt(self):
        ledger = ReceiptLedger()
        rec = ledger.record("user-1", {"op": "write", "target": "file.txt"})
        assert isinstance(rec, ProofReceipt)
        assert rec.custodian_id == "user-1"

    def test_record_increments_length(self):
        ledger = ReceiptLedger()
        ledger.record("u1", "action-a")
        ledger.record("u1", "action-b")
        assert len(ledger) == 2

    def test_receipt_action_hash_is_sha256(self):
        ledger = ReceiptLedger()
        action = "deploy:staging"
        rec = ledger.record("u1", action)
        import json
        canonical = json.dumps(action, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert rec.action_hash == expected

    def test_has_receipt_for_returns_true_after_recording(self):
        ledger = ReceiptLedger()
        rec = ledger.record("u1", "my-action")
        assert ledger.has_receipt_for(rec.action_hash)

    def test_has_receipt_for_returns_false_for_unknown_hash(self):
        ledger = ReceiptLedger()
        assert not ledger.has_receipt_for("deadbeef")

    def test_records_property_returns_immutable_snapshot(self):
        ledger = ReceiptLedger()
        ledger.record("u1", "act")
        snap = ledger.records
        snap.clear()
        assert len(ledger) == 1  # original unaffected

    def test_proof_receipt_to_dict_keys(self):
        ledger = ReceiptLedger()
        rec = ledger.record("u1", "act")
        d = rec.to_dict()
        for key in ("receipt_id", "custodian_id", "action_hash", "wake_receipt_hash", "timestamp"):
            assert key in d

    def test_wake_receipt_hash_non_empty(self):
        ledger = ReceiptLedger()
        rec = ledger.record("u1", "act")
        assert len(rec.wake_receipt_hash) == 64  # 32 bytes hex-encoded

    def test_record_with_custom_wake_chain(self):
        chain = WakeChain()
        ledger = ReceiptLedger()
        rec = ledger.record("u1", "act", wake_chain=chain)
        assert len(chain) == 1
        assert rec.wake_receipt_hash != ""

    def test_non_serialisable_action_handled(self):
        ledger = ReceiptLedger()
        # object() is not JSON-serialisable; should fall back to str()
        rec = ledger.record("u1", object())
        assert rec.action_hash != ""


# ===========================================================================
# Layer 4 – TetheredAgencySystem  (full evaluation)
# ===========================================================================


class TestTetheredAgencySystem:
    def setup_method(self):
        reset_default_chain()

    def _make_tas(self) -> TetheredAgencySystem:
        return TetheredAgencySystem(
            custodian=_make_custodian(),
            heartbeat=_make_heartbeat(),
        )

    def test_healthy_when_all_layers_satisfied(self):
        chain = WakeChain()
        tas = TetheredAgencySystem(
            custodian=_make_custodian(),
            heartbeat=_make_heartbeat(),
            wake_chain=chain,
        )
        tas.receipt_ledger.record("user-001", "bootstrap", wake_chain=chain)
        chain.commit({"boot": True})
        fb = tas.evaluate()
        assert fb.status == FeedbackStatus.HEALTHY
        assert fb.all_satisfied

    def test_inoperable_when_no_custodian(self):
        tas = TetheredAgencySystem(custodian=None, heartbeat=_make_heartbeat())
        tas.receipt_ledger.record("anon", "act")
        fb = tas.evaluate()
        assert fb.status == FeedbackStatus.INOPERABLE
        assert 1 in fb.failed_layers

    def test_inoperable_when_heartbeat_expired(self):
        tas = TetheredAgencySystem(
            custodian=_make_custodian(),
            heartbeat=_make_heartbeat(interval=1.0),
        )
        tas.receipt_ledger.record("user-001", "act")
        # Evaluate far in the future
        future = time.time() + 60.0
        fb = tas.evaluate(at=future)
        assert fb.status == FeedbackStatus.INOPERABLE
        assert 2 in fb.failed_layers

    def test_degraded_when_only_receipt_layer_fails(self):
        chain = WakeChain()
        chain.commit({"seed": True})
        tas = TetheredAgencySystem(
            custodian=_make_custodian(),
            heartbeat=_make_heartbeat(),
            wake_chain=chain,
        )
        # receipt_ledger is empty → Layer 3 fails
        fb = tas.evaluate()
        assert fb.status == FeedbackStatus.DEGRADED
        assert 3 in fb.failed_layers

    def test_degraded_when_wake_chain_not_seeded(self):
        # Empty wake chain → Layer 4 detail reports 0 receipts but chain is still valid
        tas = TetheredAgencySystem(
            custodian=_make_custodian(),
            heartbeat=_make_heartbeat(),
        )
        tas.receipt_ledger.record("user-001", "act")
        # wake chain has 0 entries but is still technically valid (empty chain verifies)
        fb = tas.evaluate()
        # Layer 4 should be satisfied (empty valid chain), Layer 3 satisfied
        assert fb.status in (FeedbackStatus.HEALTHY, FeedbackStatus.DEGRADED)

    def test_is_operational_returns_true_when_healthy(self):
        chain = WakeChain()
        tas = TetheredAgencySystem(
            custodian=_make_custodian(),
            heartbeat=_make_heartbeat(),
            wake_chain=chain,
        )
        tas.receipt_ledger.record("user-001", "act", wake_chain=chain)
        assert tas.is_operational()

    def test_is_operational_returns_false_when_no_custodian(self):
        tas = TetheredAgencySystem(custodian=None, heartbeat=_make_heartbeat())
        assert not tas.is_operational()

    def test_assert_operational_raises_tas_inoperable_error(self):
        tas = TetheredAgencySystem(custodian=None, heartbeat=_make_heartbeat())
        with pytest.raises(TASInoperableError) as exc_info:
            tas.assert_operational()
        assert 1 in exc_info.value.feedback.failed_layers

    def test_assert_operational_passes_when_healthy(self):
        chain = WakeChain()
        tas = TetheredAgencySystem(
            custodian=_make_custodian(),
            heartbeat=_make_heartbeat(),
            wake_chain=chain,
        )
        tas.receipt_ledger.record("user-001", "act", wake_chain=chain)
        tas.assert_operational()  # must not raise

    def test_feedback_history_grows_with_each_evaluate(self):
        tas = self._make_tas()
        tas.evaluate()
        tas.evaluate()
        assert len(tas.feedback_history) == 2

    def test_all_four_layer_reports_present(self):
        tas = self._make_tas()
        fb = tas.evaluate()
        layer_nums = [r.layer_number for r in fb.layer_reports]
        assert sorted(layer_nums) == [1, 2, 3, 4]

    def test_custodian_invalid_hash_causes_layer1_failure(self):
        bad_custodian = AuthorialCustodian(
            custodian_id="u1", name="Eve", sponsor_hash="tampered"
        )
        tas = TetheredAgencySystem(custodian=bad_custodian, heartbeat=_make_heartbeat())
        fb = tas.evaluate()
        assert 1 in fb.failed_layers

    def test_no_heartbeat_causes_layer2_failure(self):
        tas = TetheredAgencySystem(custodian=_make_custodian(), heartbeat=None)
        fb = tas.evaluate()
        assert 2 in fb.failed_layers


# ===========================================================================
# EcosystemFeedback helpers
# ===========================================================================


class TestEcosystemFeedback:
    def _make_feedback(self, statuses: list[bool]) -> EcosystemFeedback:
        reports = [
            LayerReport(i + 1, f"layer_{i+1}", ok)
            for i, ok in enumerate(statuses)
        ]
        satisfied = all(statuses)
        status = FeedbackStatus.HEALTHY if satisfied else FeedbackStatus.DEGRADED
        return EcosystemFeedback(
            status=status,
            layer_reports=reports,
            timestamp=time.time(),
        )

    def test_all_satisfied_true_when_all_pass(self):
        fb = self._make_feedback([True, True, True, True])
        assert fb.all_satisfied

    def test_all_satisfied_false_when_any_fail(self):
        fb = self._make_feedback([True, True, False, True])
        assert not fb.all_satisfied

    def test_failed_layers_empty_when_all_pass(self):
        fb = self._make_feedback([True, True, True, True])
        assert fb.failed_layers == []

    def test_failed_layers_correct_indices(self):
        fb = self._make_feedback([True, False, True, False])
        assert fb.failed_layers == [2, 4]

    def test_to_dict_structure(self):
        fb = self._make_feedback([True, False, True, True])
        d = fb.to_dict()
        assert "status" in d
        assert "layer_reports" in d
        assert "timestamp" in d
        assert len(d["layer_reports"]) == 4


# ===========================================================================
# UVK Invariant factories
# ===========================================================================


class TestCustodianInvariant:
    def test_invariant_passes_with_valid_custodian(self):
        c = _make_custodian()
        inv = make_custodian_invariant(lambda s, a, i: c)
        assert inv(None, None, None)

    def test_invariant_fails_with_none_custodian(self):
        inv = make_custodian_invariant(lambda s, a, i: None)
        assert not inv(None, None, None)

    def test_invariant_fails_with_invalid_hash(self):
        bad = AuthorialCustodian(custodian_id="u1", name="Alice", sponsor_hash="bad")
        inv = make_custodian_invariant(lambda s, a, i: bad)
        assert not inv(None, None, None)

    def test_invariant_name(self):
        inv = make_custodian_invariant(lambda s, a, i: _make_custodian())
        assert inv.name == "tethered_agency:custodian_present"

    def test_invariant_version_default(self):
        inv = make_custodian_invariant(lambda s, a, i: _make_custodian())
        assert inv.version == "1.0.0"

    def test_invariant_version_custom(self):
        inv = make_custodian_invariant(lambda s, a, i: _make_custodian(), version="2.0.0")
        assert inv.version == "2.0.0"


class TestHeartbeatInvariant:
    def test_invariant_passes_with_live_heartbeat(self):
        hb = _make_heartbeat()
        inv = make_heartbeat_invariant(lambda s, a, i: hb)
        assert inv(None, None, None)

    def test_invariant_fails_with_none_heartbeat(self):
        inv = make_heartbeat_invariant(lambda s, a, i: None)
        assert not inv(None, None, None)

    def test_invariant_fails_with_expired_heartbeat(self):
        hb = _make_heartbeat(interval=0.0)
        inv = make_heartbeat_invariant(
            lambda s, a, i: hb,
            clock=lambda: time.time() + 1.0,
        )
        assert not inv(None, None, None)

    def test_invariant_name(self):
        inv = make_heartbeat_invariant(lambda s, a, i: _make_heartbeat())
        assert inv.name == "tethered_agency:heartbeat_alive"

    def test_deterministic_clock_override(self):
        hb = _make_heartbeat(interval=10.0)
        fixed_time = hb._last_beat + 5.0  # within interval
        inv = make_heartbeat_invariant(
            lambda s, a, i: hb,
            clock=lambda: fixed_time,
        )
        assert inv(None, None, None)


class TestReceiptInvariant:
    def setup_method(self):
        reset_default_chain()

    def test_invariant_fails_when_no_receipt(self):
        ledger = ReceiptLedger()
        inv = make_receipt_invariant(ledger, lambda s, a, i: a)
        assert not inv(None, "unknown-hash", None)

    def test_invariant_passes_after_recording(self):
        ledger = ReceiptLedger()
        action = "deploy:prod"
        rec = ledger.record("u1", action)
        inv = make_receipt_invariant(ledger, lambda s, a, i: a)
        assert inv(None, rec.action_hash, None)

    def test_invariant_name(self):
        ledger = ReceiptLedger()
        inv = make_receipt_invariant(ledger, lambda s, a, i: a)
        assert inv.name == "tethered_agency:receipt_required"


# ===========================================================================
# create_tethered_session factory
# ===========================================================================


class TestCreateTetheredSession:
    def setup_method(self):
        reset_default_chain()

    def test_session_has_custodian(self):
        tas = create_tethered_session("u1", "Alice")
        assert tas.custodian is not None
        assert tas.custodian.name == "Alice"

    def test_session_has_heartbeat(self):
        tas = create_tethered_session("u1", "Alice")
        assert tas.heartbeat is not None

    def test_session_heartbeat_is_alive(self):
        tas = create_tethered_session("u1", "Alice")
        assert tas.heartbeat.is_alive()

    def test_session_custodian_matches_heartbeat_id(self):
        tas = create_tethered_session("u1", "Alice")
        assert tas.custodian.custodian_id == tas.heartbeat.custodian_id

    def test_custom_heartbeat_interval_applied(self):
        tas = create_tethered_session("u1", "Alice", heartbeat_interval=60.0)
        assert tas.heartbeat.max_interval == 60.0

    def test_layer1_and_layer2_satisfied_immediately(self):
        tas = create_tethered_session("u1", "Alice")
        fb = tas.evaluate()
        layer_map = {r.layer_number: r.satisfied for r in fb.layer_reports}
        assert layer_map[1] is True
        assert layer_map[2] is True

    def test_custom_wake_chain_accepted(self):
        chain = WakeChain()
        tas = create_tethered_session("u1", "Alice", wake_chain=chain)
        assert tas.wake is chain


# ===========================================================================
# TASInoperableError
# ===========================================================================


class TestTASInoperableError:
    def test_error_contains_feedback(self):
        tas = TetheredAgencySystem(custodian=None, heartbeat=None)
        with pytest.raises(TASInoperableError) as exc_info:
            tas.assert_operational()
        assert isinstance(exc_info.value.feedback, EcosystemFeedback)

    def test_error_message_mentions_failed_layers(self):
        tas = TetheredAgencySystem(custodian=None, heartbeat=None)
        with pytest.raises(TASInoperableError) as exc_info:
            tas.assert_operational()
        assert "1" in str(exc_info.value)

    def test_error_status_inoperable(self):
        tas = TetheredAgencySystem(custodian=None, heartbeat=None)
        with pytest.raises(TASInoperableError) as exc_info:
            tas.assert_operational()
        assert exc_info.value.feedback.status == FeedbackStatus.INOPERABLE
