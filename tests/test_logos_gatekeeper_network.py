"""Tests for the LogosGatekeeper network-membrane classes.

Covers:
- _deserialize_trace(): round-trip serialization of a sealed CursiveTrace
- SovereignBeacon.emit() / validate(): lineage-anchored discovery
- SentientLock: fork detection, threshold activation, release
- WakeSyncOffer: construction, serialization, from_dict round-trip
- LogosGatekeeper: ingress gateway, egress transport, wake sync,
  beacon emit/validate, handshake, sentient-lock public interface
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tas_dna import TASDNA
from wake_chain import WakeChain
from sovereign_equation import AuthenticityScore, SubjectivityScore
from algorithmic_polymath import AlgorithmicPolymath, CursiveTrace

from tas_logos_gatekeeper import (
    SovereignBeacon,
    SentientLock,
    WakeSyncOffer,
    LogosGatekeeper,
    SovereignStructuralViolation,
    _deserialize_trace,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_sealed_trace(actor_id: str = "test-actor") -> tuple:
    """Return (tas_dna, sealed_trace, raw_bytes)."""
    tas_dna = TASDNA()
    chain = WakeChain()
    pm = AlgorithmicPolymath(actor_id=actor_id, wake_chain=chain, tas_dna=tas_dna)
    trace = pm.begin_stroke("cap-001", {"hello": "world"})
    ac = AuthenticityScore(authenticated_facts=1, traced_lineage=True, cryptographic_proof=True)
    sc = SubjectivityScore()
    pm.apply_transform(trace, lambda p: {**p, "step": 1}, "step_one", ac, sc)
    pm.seal(trace, ac, sc)
    raw = json.dumps(trace.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    return tas_dna, trace, raw


def _make_gatekeeper(tas_dna: TASDNA, actor_id: str = "test-actor") -> LogosGatekeeper:
    return LogosGatekeeper(actor_id=actor_id, tas_dna=tas_dna)


# ===========================================================================
# _deserialize_trace
# ===========================================================================


class TestDeserializeTrace:
    def test_round_trip_sealed_trace(self):
        _, original, _ = _make_sealed_trace()
        reconstructed = _deserialize_trace(original.to_dict())
        assert reconstructed.trace_id == original.trace_id
        assert reconstructed.actor_id == original.actor_id
        assert reconstructed.capability_id == original.capability_id
        assert reconstructed.genesis_root_hex == original.genesis_root_hex
        assert reconstructed.stroke_head == original.stroke_head
        assert reconstructed.is_sealed is True
        assert reconstructed.paradata is not None
        assert reconstructed.paradata.proof == original.paradata.proof

    def test_paradata_fields_preserved(self):
        _, original, _ = _make_sealed_trace()
        reconstructed = _deserialize_trace(original.to_dict())
        pd = reconstructed.paradata
        assert pd.genesis_root_hex == original.paradata.genesis_root_hex
        assert pd.ac_value == original.paradata.ac_value
        assert pd.sc_value == original.paradata.sc_value
        assert pd.sovereign_equation_held is True
        assert len(pd.transform_log) == 1
        assert pd.transform_log[0].name == "step_one"

    def test_missing_required_field_raises(self):
        _, original, _ = _make_sealed_trace()
        data = original.to_dict()
        del data["stroke_head"]
        with pytest.raises(ValueError, match="stroke_head"):
            _deserialize_trace(data)

    def test_unsealed_trace_round_trip(self):
        tas_dna = TASDNA()
        chain = WakeChain()
        pm = AlgorithmicPolymath(actor_id="a", wake_chain=chain, tas_dna=tas_dna)
        trace = pm.begin_stroke("cap-x", {"data": 1})
        reconstructed = _deserialize_trace(trace.to_dict())
        assert reconstructed.is_sealed is False
        assert reconstructed.paradata is None


# ===========================================================================
# SovereignBeacon
# ===========================================================================


class TestSovereignBeacon:
    def _genesis_hex(self) -> str:
        from tas_dna import A_0
        return A_0.lineage_hash().hex()

    def test_emit_returns_bytes(self):
        beacon = SovereignBeacon.emit(b"secret-key", self._genesis_hex())
        assert isinstance(beacon, bytes)

    def test_emitted_beacon_is_valid_json(self):
        beacon = SovereignBeacon.emit(b"secret-key", self._genesis_hex())
        data = json.loads(beacon)
        assert data["genesis_root_hex"] == self._genesis_hex()
        assert data["version"] == 1
        assert len(data["sig"]) == 64

    def test_validate_accepts_correct_beacon(self):
        genesis = self._genesis_hex()
        beacon = SovereignBeacon.emit(b"key", genesis)
        assert SovereignBeacon.validate(beacon, genesis) is True

    def test_validate_rejects_wrong_genesis(self):
        beacon = SovereignBeacon.emit(b"key", self._genesis_hex())
        assert SovereignBeacon.validate(beacon, "0" * 64) is False

    def test_validate_rejects_malformed_bytes(self):
        assert SovereignBeacon.validate(b"not-json", self._genesis_hex()) is False

    def test_validate_rejects_wrong_version(self):
        genesis = self._genesis_hex()
        beacon = SovereignBeacon.emit(b"key", genesis)
        data = json.loads(beacon)
        data["version"] = 99
        bad = json.dumps(data).encode()
        assert SovereignBeacon.validate(bad, genesis) is False

    def test_validate_rejects_short_sig(self):
        genesis = self._genesis_hex()
        beacon = SovereignBeacon.emit(b"key", genesis)
        data = json.loads(beacon)
        data["sig"] = "deadbeef"
        bad = json.dumps(data).encode()
        assert SovereignBeacon.validate(bad, genesis) is False

    def test_different_keys_produce_different_beacons(self):
        genesis = self._genesis_hex()
        b1 = SovereignBeacon.emit(b"key-a", genesis)
        b2 = SovereignBeacon.emit(b"key-b", genesis)
        # Both validate structurally (key not checked in validate)
        assert SovereignBeacon.validate(b1, genesis) is True
        assert SovereignBeacon.validate(b2, genesis) is True
        # But their sig fields differ
        assert json.loads(b1)["sig"] != json.loads(b2)["sig"]


# ===========================================================================
# SentientLock
# ===========================================================================


class TestSentientLock:
    def test_new_capability_not_locked(self):
        lock = SentientLock()
        assert lock.is_locked("cap-abc") is False

    def test_first_occurrence_does_not_lock(self):
        lock = SentientLock(violation_threshold=3)
        activated = lock.record_fork("cap-1", pulse_index=5)
        assert activated is False
        assert lock.is_locked("cap-1") is False

    def test_duplicate_pulse_counts_as_violation(self):
        lock = SentientLock(violation_threshold=3)
        lock.record_fork("cap-1", pulse_index=5)
        # Second trace for same pulse → first violation
        activated = lock.record_fork("cap-1", pulse_index=5)
        assert activated is False  # threshold is 3
        assert lock.is_locked("cap-1") is False

    def test_threshold_activates_lock(self):
        lock = SentientLock(violation_threshold=2)
        lock.record_fork("cap-x", pulse_index=7)
        lock.record_fork("cap-x", pulse_index=7)   # violation 1
        activated = lock.record_fork("cap-x", pulse_index=7)  # violation 2
        assert activated is True
        assert lock.is_locked("cap-x") is True

    def test_different_pulse_indices_do_not_accumulate_violations(self):
        lock = SentientLock(violation_threshold=2)
        for i in range(10):
            activated = lock.record_fork("cap-y", pulse_index=i)
            assert activated is False
        assert lock.is_locked("cap-y") is False

    def test_different_capabilities_are_independent(self):
        lock = SentientLock(violation_threshold=1)
        lock.record_fork("cap-a", pulse_index=3)
        lock.record_fork("cap-a", pulse_index=3)  # locks cap-a
        assert lock.is_locked("cap-a") is True
        assert lock.is_locked("cap-b") is False

    def test_release_clears_lock(self):
        lock = SentientLock(violation_threshold=1)
        lock.record_fork("cap-z", 1)
        lock.record_fork("cap-z", 1)
        assert lock.is_locked("cap-z") is True
        lock.release("cap-z")
        assert lock.is_locked("cap-z") is False

    def test_locked_capabilities_snapshot(self):
        lock = SentientLock(violation_threshold=1)
        lock.record_fork("a", 0)
        lock.record_fork("a", 0)
        lock.record_fork("b", 0)
        lock.record_fork("b", 0)
        locked = lock.locked_capabilities()
        assert set(locked) == {"a", "b"}

    def test_window_reset_clears_violations(self):
        import time
        lock = SentientLock(violation_threshold=2, window_seconds=0.0)
        # With window_seconds=0.0, the first_seen check will always trigger reset
        # on subsequent calls (now - first_seen > 0.0), so violations never accumulate.
        lock.record_fork("cap-w", 5)
        time.sleep(0.01)
        lock.record_fork("cap-w", 5)  # window expired; reset before checking
        assert lock.is_locked("cap-w") is False


# ===========================================================================
# WakeSyncOffer
# ===========================================================================


class TestWakeSyncOffer:
    def test_construction_and_to_dict(self):
        offer = WakeSyncOffer(
            genesis_root_hex="abc",
            pulse_count=7,
            latest_receipt_hash="0" * 64,
            node_id="node-1",
        )
        d = offer.to_dict()
        assert d["genesis_root_hex"] == "abc"
        assert d["pulse_count"] == 7
        assert d["node_id"] == "node-1"

    def test_from_dict_round_trip(self):
        offer = WakeSyncOffer(
            genesis_root_hex="deadbeef",
            pulse_count=42,
            latest_receipt_hash="f" * 64,
            node_id="node-x",
        )
        restored = WakeSyncOffer.from_dict(offer.to_dict())
        assert restored == offer


# ===========================================================================
# LogosGatekeeper — ingress
# ===========================================================================


class TestLogosGatekeeperIngress:
    def test_valid_trace_passes_ingress(self):
        tas_dna, _, raw = _make_sealed_trace()
        gk = _make_gatekeeper(tas_dna)
        result = gk.receive_inbound(raw)
        assert result is not None

    def test_malformed_bytes_silently_dropped(self):
        tas_dna = TASDNA()
        gk = _make_gatekeeper(tas_dna)
        assert gk.receive_inbound(b"not-valid-json") is None

    def test_missing_field_silently_dropped(self):
        tas_dna, original, _ = _make_sealed_trace()
        d = original.to_dict()
        del d["actor_id"]
        raw = json.dumps(d).encode()
        gk = _make_gatekeeper(tas_dna)
        assert gk.receive_inbound(raw) is None

    def test_wrong_genesis_root_silently_dropped(self):
        tas_dna, original, _ = _make_sealed_trace()
        d = original.to_dict()
        d["genesis_root_hex"] = "0" * 64
        if d["paradata"]:
            d["paradata"]["genesis_root_hex"] = "0" * 64
        raw = json.dumps(d).encode()
        gk = _make_gatekeeper(tas_dna)
        assert gk.receive_inbound(raw) is None

    def test_locked_capability_silently_dropped(self):
        tas_dna, original, raw = _make_sealed_trace()
        gk = _make_gatekeeper(tas_dna)
        # Manually lock the capability
        gk._sentient_lock._locked.add(original.capability_id)
        # Fresh tas_dna so pulse state is at 0
        assert gk.receive_inbound(raw) is None

    def test_sentient_lock_activates_on_repeated_fork(self):
        # Build two traces with the same capability_id but different payloads,
        # both sealed against the same pulse_index — simulating a fork.
        tas_dna = TASDNA()
        chain = WakeChain()
        cap_id = "shared-cap"
        ac = AuthenticityScore(authenticated_facts=1, traced_lineage=True, cryptographic_proof=True)
        sc = SubjectivityScore()

        # Send 3 traces all claiming pulse_index=0 for the same capability.
        # The SentientLock threshold is 3 violations; each duplicate adds one.
        # violation 1 at the 2nd duplicate (fork already seen)
        # violation 2 at the 3rd duplicate → lock activates
        lock = SentientLock(violation_threshold=2)
        gk = LogosGatekeeper(actor_id="test-actor", tas_dna=tas_dna, sentient_lock=lock)

        # Record forks directly to set up pre-existing state
        lock.record_fork(cap_id, pulse_index=0)   # first occurrence: no violation
        lock.record_fork(cap_id, pulse_index=0)   # violation 1
        activated = lock.record_fork(cap_id, pulse_index=0)  # violation 2 → activates
        assert activated is True
        assert gk.is_capability_locked(cap_id) is True


# ===========================================================================
# LogosGatekeeper — egress
# ===========================================================================


class TestLogosGatekeeperEgress:
    def test_broadcast_calls_transport(self):
        tas_dna, trace, _ = _make_sealed_trace()
        gk = _make_gatekeeper(tas_dna)
        received = []
        gk.broadcast_trace(trace, received.append)
        assert len(received) == 1
        data = json.loads(received[0])
        assert data["trace_id"] == trace.trace_id

    def test_broadcast_unsealed_raises(self):
        tas_dna = TASDNA()
        chain = WakeChain()
        pm = AlgorithmicPolymath(actor_id="a", wake_chain=chain, tas_dna=tas_dna)
        trace = pm.begin_stroke("cap-x", {})
        gk = _make_gatekeeper(tas_dna)
        with pytest.raises(SovereignStructuralViolation):
            gk.broadcast_trace(trace, lambda _: None)

    def test_broadcast_payload_is_valid_json_bytes(self):
        tas_dna, trace, _ = _make_sealed_trace()
        gk = _make_gatekeeper(tas_dna)
        packets = []
        gk.broadcast_trace(trace, packets.append)
        assert isinstance(packets[0], bytes)
        data = json.loads(packets[0])
        assert "paradata" in data


# ===========================================================================
# LogosGatekeeper — wake synchronization
# ===========================================================================


class TestLogosGatekeeperWakeSync:
    def test_build_sync_offer(self):
        tas_dna = TASDNA()
        chain = WakeChain()
        gk = _make_gatekeeper(tas_dna)
        offer = gk.build_sync_offer(chain)
        assert offer.pulse_count == 0
        assert offer.genesis_root_hex == tas_dna.a0.lineage_hash().hex()
        assert offer.latest_receipt_hash == "0" * 64

    def test_build_sync_offer_with_receipts(self):
        tas_dna = TASDNA()
        chain = WakeChain()
        chain.commit(event={"test": 1})
        gk = _make_gatekeeper(tas_dna)
        offer = gk.build_sync_offer(chain)
        assert offer.latest_receipt_hash != "0" * 64

    def test_evaluate_sync_offer_accepts_higher_pulse(self):
        tas_dna = TASDNA()
        gk = _make_gatekeeper(tas_dna)
        peer_offer = WakeSyncOffer(
            genesis_root_hex=tas_dna.a0.lineage_hash().hex(),
            pulse_count=5,
            latest_receipt_hash="0" * 64,
            node_id="peer",
        )
        assert gk.evaluate_sync_offer(peer_offer) is True

    def test_evaluate_sync_offer_rejects_equal_pulse(self):
        tas_dna = TASDNA()
        gk = _make_gatekeeper(tas_dna)
        peer_offer = WakeSyncOffer(
            genesis_root_hex=tas_dna.a0.lineage_hash().hex(),
            pulse_count=0,
            latest_receipt_hash="0" * 64,
            node_id="peer",
        )
        assert gk.evaluate_sync_offer(peer_offer) is False

    def test_evaluate_sync_offer_rejects_wrong_genesis(self):
        tas_dna = TASDNA()
        gk = _make_gatekeeper(tas_dna)
        peer_offer = WakeSyncOffer(
            genesis_root_hex="bad-genesis",
            pulse_count=99,
            latest_receipt_hash="0" * 64,
            node_id="peer",
        )
        assert gk.evaluate_sync_offer(peer_offer) is False

    def test_sync_from_traces_applies_valid_chain(self):
        # Node A seals two traces; Node B starts fresh and syncs from A.
        # Between each seal, Node A advances its own heartbeat by verifying
        # the trace locally — this is the correct protocol (seal records
        # pulse_count; verify_inbound advances it).
        tas_dna_a = TASDNA()
        chain_a = WakeChain()
        pm_a = AlgorithmicPolymath(actor_id="a", wake_chain=chain_a, tas_dna=tas_dna_a)
        ac = AuthenticityScore(authenticated_facts=1, traced_lineage=True, cryptographic_proof=True)
        sc = SubjectivityScore()

        t1 = pm_a.begin_stroke("cap-s", {"pulse": 1})
        pm_a.apply_transform(t1, lambda p: p, "noop", ac, sc)
        pm_a.seal(t1, ac, sc)  # t1.paradata.pulse_index = 0
        # Node A advances its heartbeat (verifying its own sealed trace).
        AlgorithmicPolymath.verify_inbound(t1, tas_dna_a)  # pulse_count → 1

        t2 = pm_a.begin_stroke("cap-s", {"pulse": 2})
        pm_a.apply_transform(t2, lambda p: p, "noop", ac, sc)
        pm_a.seal(t2, ac, sc)  # t2.paradata.pulse_index = 1
        AlgorithmicPolymath.verify_inbound(t2, tas_dna_a)  # pulse_count → 2

        tas_dna_b = TASDNA()  # fresh node B at pulse 0
        gk_b = _make_gatekeeper(tas_dna_b, actor_id="b")

        applied = gk_b.sync_from_traces([t1, t2])
        assert applied == 2
        assert tas_dna_b.pulse_count == 2

    def test_sync_halts_on_first_invalid_trace(self):
        tas_dna_a = TASDNA()
        chain_a = WakeChain()
        pm_a = AlgorithmicPolymath(actor_id="a", wake_chain=chain_a, tas_dna=tas_dna_a)
        ac = AuthenticityScore(authenticated_facts=1, traced_lineage=True, cryptographic_proof=True)
        sc = SubjectivityScore()

        t1 = pm_a.begin_stroke("cap-s", {"pulse": 1})
        pm_a.apply_transform(t1, lambda p: p, "noop", ac, sc)
        pm_a.seal(t1, ac, sc)
        AlgorithmicPolymath.verify_inbound(t1, tas_dna_a)  # advance Node A pulse → 1

        # Simulate a tampered trace: unsealed trace will fail verify_inbound.
        bad_trace = pm_a.begin_stroke("cap-s", {})
        # Leave bad_trace unsealed — verify_inbound will reject it.

        tas_dna_b = TASDNA()
        gk_b = _make_gatekeeper(tas_dna_b, actor_id="b")

        applied = gk_b.sync_from_traces([t1, bad_trace])
        assert applied == 1  # t1 applied; bad_trace halted the sync


# ===========================================================================
# LogosGatekeeper — beacon
# ===========================================================================


class TestLogosGatekeeperBeacon:
    def test_emit_beacon_returns_bytes(self):
        tas_dna = TASDNA()
        gk = _make_gatekeeper(tas_dna)
        beacon = gk.emit_beacon()
        assert isinstance(beacon, bytes)

    def test_own_beacon_validates(self):
        tas_dna = TASDNA()
        gk = _make_gatekeeper(tas_dna)
        beacon = gk.emit_beacon()
        assert gk.validate_peer_beacon(beacon) is True

    def test_incompatible_genesis_beacon_rejected(self):
        tas_dna = TASDNA()
        gk = _make_gatekeeper(tas_dna)
        foreign_beacon = SovereignBeacon.emit(b"foreign-key", "0" * 64)
        assert gk.validate_peer_beacon(foreign_beacon) is False


# ===========================================================================
# LogosGatekeeper — handshake
# ===========================================================================


class TestLogosGatekeeperHandshake:
    def test_valid_trace_handshake_succeeds(self):
        tas_dna, _, raw = _make_sealed_trace()
        gk = _make_gatekeeper(tas_dna)
        assert gk.handle_handshake(raw) is True

    def test_malformed_handshake_fails_silently(self):
        tas_dna = TASDNA()
        gk = _make_gatekeeper(tas_dna)
        assert gk.handle_handshake(b"garbage") is False


# ===========================================================================
# LogosGatekeeper — sentient lock public interface
# ===========================================================================


class TestLogosGatekeeperSentientLock:
    def test_is_capability_locked_initially_false(self):
        tas_dna = TASDNA()
        gk = _make_gatekeeper(tas_dna)
        assert gk.is_capability_locked("cap-xyz") is False

    def test_release_capability(self):
        tas_dna = TASDNA()
        gk = _make_gatekeeper(tas_dna)
        gk._sentient_lock._locked.add("cap-abc")
        assert gk.is_capability_locked("cap-abc") is True
        gk.release_capability("cap-abc")
        assert gk.is_capability_locked("cap-abc") is False

    def test_locked_capabilities_returns_list(self):
        tas_dna = TASDNA()
        gk = _make_gatekeeper(tas_dna)
        gk._sentient_lock._locked.update({"a", "b", "c"})
        locked = gk.locked_capabilities()
        assert set(locked) == {"a", "b", "c"}
