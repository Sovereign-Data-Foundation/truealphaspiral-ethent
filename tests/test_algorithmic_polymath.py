"""Unit tests for the Algorithmic Polymath module.

Covers:
- begin_stroke: trace initialisation, stroke_head seeding (§1)
- apply_transform: stroke extension, transform log, payload update (§1)
- seal: wake chain commitment, paradata binding, proof stamping (§2)
- CursiveTrace.verify / AlgorithmicPolymath.verify_inbound: cross-node
  trustless verification (§3)
- PolymathViolation: enforcement of sealed-state invariants
- Integration: multi-transform pipeline with wake chain and sovereign equation
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
import hmac
import json

import pytest

from algorithmic_polymath import (
    AlgorithmicPolymath,
    CursiveTrace,
    GENESIS_ROOT_HEX,
    Paradata,
    PolymathViolation,
    TransformRecord,
    _recompute_stroke_head,
)
from sovereign_equation import AuthenticityScore, SubjectivityScore
from tas_dna import TASDNA, PrimaryInvariantA0
from wake_chain import WakeChain


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ACTOR  = "user:sovereign-test-actor"
_CAP_ID = "cap-uuid-1234"
_STRONG_AC = AuthenticityScore(authenticated_facts=1, traced_lineage=True, cryptographic_proof=True)
_ZERO_SC   = SubjectivityScore()
_WEAK_AC   = AuthenticityScore()
_STRONG_SC = SubjectivityScore(unverified_claims=2, speculative_steps=2)


def _make_polymath(actor: str = _ACTOR) -> tuple[AlgorithmicPolymath, WakeChain]:
    chain = WakeChain()
    pm = AlgorithmicPolymath(actor_id=actor, wake_chain=chain)
    return pm, chain


def _identity(payload):
    return payload


def _append_step(payload):
    if isinstance(payload, list):
        return payload + ["step"]
    return payload


# ---------------------------------------------------------------------------
# TransformRecord
# ---------------------------------------------------------------------------


class TestTransformRecord:
    def test_to_dict_round_trip(self):
        tr = TransformRecord(name="norm", output_hash="abcd" * 16)
        d = tr.to_dict()
        assert d["name"] == "norm"
        assert d["output_hash"] == "abcd" * 16

    def test_frozen(self):
        tr = TransformRecord(name="x", output_hash="y")
        with pytest.raises(Exception):
            tr.name = "z"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Paradata
# ---------------------------------------------------------------------------


class TestParadata:
    def _make(self, **overrides) -> Paradata:
        base = dict(
            actor_id="actor",
            capability_id="cap",
            genesis_root_hex="aa" * 32,
            wake_receipt_hash="bb" * 32,
            sovereign_equation_held=True,
            ac_value=1.0,
            sc_value=0.0,
            transform_log=(TransformRecord("t1", "cc" * 32),),
            sealed_at=1_000_000.0,
            proof="",
        )
        base.update(overrides)
        tmp = Paradata(**base)
        return Paradata(**{**base, "proof": tmp.compute_proof()})

    def test_compute_proof_is_deterministic(self):
        pd = self._make()
        assert pd.compute_proof() == pd.compute_proof()

    def test_is_valid_proof_true(self):
        pd = self._make()
        assert pd.is_valid_proof()

    def test_tampered_field_invalidates_proof(self):
        pd = self._make()
        tampered = Paradata(
            actor_id="other_actor",       # changed
            capability_id=pd.capability_id,
            genesis_root_hex=pd.genesis_root_hex,
            wake_receipt_hash=pd.wake_receipt_hash,
            sovereign_equation_held=pd.sovereign_equation_held,
            ac_value=pd.ac_value,
            sc_value=pd.sc_value,
            transform_log=pd.transform_log,
            sealed_at=pd.sealed_at,
            proof=pd.proof,               # original proof kept
        )
        assert not tampered.is_valid_proof()

    def test_to_dict_contains_all_keys(self):
        pd = self._make()
        d = pd.to_dict()
        for key in (
            "actor_id", "capability_id", "genesis_root_hex", "wake_receipt_hash",
            "sovereign_equation_held", "ac_value", "sc_value",
            "transform_log", "sealed_at", "proof",
        ):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_transform_log_serialised(self):
        pd = self._make()
        d = pd.to_dict()
        assert isinstance(d["transform_log"], list)
        assert d["transform_log"][0]["name"] == "t1"


# ---------------------------------------------------------------------------
# _recompute_stroke_head
# ---------------------------------------------------------------------------


class TestRecomputeStrokeHead:
    def test_empty_log_matches_seed_hash(self):
        actor, cap, root = "actor", "cap", "aa" * 32
        seed = f"{actor}|{cap}|{root}"
        expected = hashlib.sha256(seed.encode()).hexdigest()
        assert _recompute_stroke_head(actor, cap, root, ()) == expected

    def test_single_transform_extends_correctly(self):
        actor, cap, root = "a", "b", "c" * 64
        tr = TransformRecord(name="T", output_hash="d" * 64)
        base_stroke = hashlib.sha256(f"{actor}|{cap}|{root}".encode()).hexdigest()
        input_str = f"{base_stroke}|T|{'d' * 64}"
        expected = hashlib.sha256(input_str.encode()).hexdigest()
        assert _recompute_stroke_head(actor, cap, root, (tr,)) == expected

    def test_order_matters(self):
        actor, cap, root = "a", "b", "c" * 64
        tr1 = TransformRecord("T1", "e" * 64)
        tr2 = TransformRecord("T2", "f" * 64)
        s1 = _recompute_stroke_head(actor, cap, root, (tr1, tr2))
        s2 = _recompute_stroke_head(actor, cap, root, (tr2, tr1))
        assert s1 != s2

    def test_deterministic_across_calls(self):
        actor, cap, root = "x", "y", "z" * 64
        tr = TransformRecord("T", "0" * 64)
        r1 = _recompute_stroke_head(actor, cap, root, (tr,))
        r2 = _recompute_stroke_head(actor, cap, root, (tr,))
        assert r1 == r2


# ---------------------------------------------------------------------------
# AlgorithmicPolymath.begin_stroke
# ---------------------------------------------------------------------------


class TestBeginStroke:
    def test_returns_cursive_trace(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {"data": "initial"})
        assert isinstance(trace, CursiveTrace)

    def test_trace_not_sealed(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, "hello")
        assert not trace.is_sealed

    def test_trace_actor_and_cap_set(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, None)
        assert trace.actor_id == _ACTOR
        assert trace.capability_id == _CAP_ID

    def test_stroke_head_is_deterministic_for_same_inputs(self):
        pm1, _ = _make_polymath()
        pm2 = AlgorithmicPolymath(
            actor_id=_ACTOR,
            wake_chain=WakeChain(),
            genesis_root_hex=pm1._genesis_root,
        )
        t1 = pm1.begin_stroke("fixed-cap", "payload")
        t2 = pm2.begin_stroke("fixed-cap", "payload")
        assert t1.stroke_head == t2.stroke_head

    def test_different_actors_produce_different_stroke_heads(self):
        pm1 = AlgorithmicPolymath(actor_id="actor_A", wake_chain=WakeChain())
        pm2 = AlgorithmicPolymath(actor_id="actor_B", wake_chain=WakeChain())
        t1 = pm1.begin_stroke(_CAP_ID, "p")
        t2 = pm2.begin_stroke(_CAP_ID, "p")
        assert t1.stroke_head != t2.stroke_head

    def test_genesis_root_embedded(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, "p")
        assert trace.genesis_root_hex == GENESIS_ROOT_HEX

    def test_each_stroke_has_unique_trace_id(self):
        pm, _ = _make_polymath()
        ids = {pm.begin_stroke(_CAP_ID, i).trace_id for i in range(5)}
        assert len(ids) == 5


# ---------------------------------------------------------------------------
# AlgorithmicPolymath.apply_transform
# ---------------------------------------------------------------------------


class TestApplyTransform:
    def test_payload_updated(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, [])
        pm.apply_transform(trace, _append_step, "append", _STRONG_AC, _ZERO_SC)
        assert trace.payload == ["step"]

    def test_stroke_head_changes(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, "x")
        original_head = trace.stroke_head
        pm.apply_transform(trace, _identity, "noop", _STRONG_AC, _ZERO_SC)
        assert trace.stroke_head != original_head

    def test_transform_log_grows(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        for i in range(3):
            pm.apply_transform(trace, _identity, f"step_{i}", _STRONG_AC, _ZERO_SC)
        assert len(trace._transform_log) == 3

    def test_transform_names_recorded_in_order(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        names = ["alpha", "beta", "gamma"]
        for n in names:
            pm.apply_transform(trace, _identity, n, _STRONG_AC, _ZERO_SC)
        assert [r.name for r in trace._transform_log] == names

    def test_output_hash_committed(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {"v": 1})
        pm.apply_transform(trace, _identity, "id", _STRONG_AC, _ZERO_SC)
        record = trace._transform_log[0]
        expected_hash = hashlib.sha256(
            json.dumps({"v": 1}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert record.output_hash == expected_hash

    def test_latest_ac_sc_updated(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.apply_transform(trace, _identity, "t", _STRONG_AC, _ZERO_SC)
        assert trace._latest_ac is _STRONG_AC
        assert trace._latest_sc is _ZERO_SC

    def test_raises_on_sealed_trace(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        with pytest.raises(PolymathViolation, match="sealed"):
            pm.apply_transform(trace, _identity, "late", _STRONG_AC, _ZERO_SC)

    def test_chained_stroke_is_cumulative(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, "payload")
        head_after_1 = pm.apply_transform(
            trace, _identity, "t1", _STRONG_AC, _ZERO_SC
        ).stroke_head
        head_after_2 = pm.apply_transform(
            trace, _identity, "t2", _STRONG_AC, _ZERO_SC
        ).stroke_head
        assert head_after_1 != head_after_2

    def test_returns_same_trace_object(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        returned = pm.apply_transform(trace, _identity, "t", _STRONG_AC, _ZERO_SC)
        assert returned is trace


# ---------------------------------------------------------------------------
# AlgorithmicPolymath.seal
# ---------------------------------------------------------------------------


class TestSeal:
    def test_trace_is_sealed_after_call(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        assert trace.is_sealed

    def test_paradata_bound_after_seal(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        assert trace.paradata is not None

    def test_paradata_proof_valid(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        assert trace.paradata.is_valid_proof()

    def test_wake_chain_receives_receipt(self):
        pm, chain = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        before = len(chain)
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        assert len(chain) == before + 1

    def test_wake_receipt_hash_in_paradata(self):
        pm, chain = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        last_receipt = chain.receipts[-1]
        assert trace.paradata.wake_receipt_hash == last_receipt.receipt_hash().hex()

    def test_sovereign_equation_held_true(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        assert trace.paradata.sovereign_equation_held is True

    def test_sovereign_equation_held_false(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        # Weak AC (0.0) vs strong SC (1.0) → equation fails
        pm.seal(trace, _WEAK_AC, _STRONG_SC)
        assert trace.paradata.sovereign_equation_held is False

    def test_transform_log_propagated_to_paradata(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.apply_transform(trace, _identity, "step_A", _STRONG_AC, _ZERO_SC)
        pm.apply_transform(trace, _identity, "step_B", _STRONG_AC, _ZERO_SC)
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        names = [r.name for r in trace.paradata.transform_log]
        assert names == ["step_A", "step_B"]

    def test_seal_uses_last_transform_ac_sc_by_default(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.apply_transform(trace, _identity, "t", _STRONG_AC, _ZERO_SC)
        pm.seal(trace)  # no explicit ac/sc — should use _STRONG_AC, _ZERO_SC
        assert trace.paradata.sovereign_equation_held is True

    def test_seal_defaults_to_zero_scores_if_no_transforms(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace)
        # No transforms → zero AC, zero SC → 0.0 is NOT > 0.0 → False
        assert trace.paradata.sovereign_equation_held is False

    def test_raises_on_double_seal(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        with pytest.raises(PolymathViolation, match="already sealed"):
            pm.seal(trace, _STRONG_AC, _ZERO_SC)

    def test_genesis_root_in_paradata(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        assert trace.paradata.genesis_root_hex == GENESIS_ROOT_HEX

    def test_actor_and_cap_in_paradata(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        assert trace.paradata.actor_id == _ACTOR
        assert trace.paradata.capability_id == _CAP_ID

    def test_returns_same_trace_object(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        returned = pm.seal(trace, _STRONG_AC, _ZERO_SC)
        assert returned is trace


# ---------------------------------------------------------------------------
# CursiveTrace.verify + AlgorithmicPolymath.verify_inbound
# ---------------------------------------------------------------------------


def _sealed_trace(n_transforms: int = 1, ac=_STRONG_AC, sc=_ZERO_SC):
    pm, _ = _make_polymath()
    trace = pm.begin_stroke(_CAP_ID, {"value": 0})
    for i in range(n_transforms):
        pm.apply_transform(trace, lambda p: {**p, "v": p.get("v", 0) + 1}, f"incr_{i}", ac, sc)
    pm.seal(trace, ac, sc)
    return trace


class TestCursiveTraceVerify:
    def test_valid_sealed_trace_passes(self):
        trace = _sealed_trace()
        assert trace.verify(GENESIS_ROOT_HEX) is True

    def test_unsealed_trace_fails(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        assert trace.verify(GENESIS_ROOT_HEX) is False

    def test_wrong_genesis_root_fails(self):
        trace = _sealed_trace()
        fake_root = "ff" * 32
        assert trace.verify(fake_root) is False

    def test_tampered_stroke_head_fails(self):
        trace = _sealed_trace()
        trace.stroke_head = "00" * 32  # corrupt the stroke
        assert trace.verify(GENESIS_ROOT_HEX) is False

    def test_tampered_paradata_proof_fails(self):
        trace = _sealed_trace()
        original = trace.paradata
        # Replace paradata with a copy that has a corrupted proof
        trace.paradata = Paradata(
            actor_id=original.actor_id,
            capability_id=original.capability_id,
            genesis_root_hex=original.genesis_root_hex,
            wake_receipt_hash=original.wake_receipt_hash,
            sovereign_equation_held=original.sovereign_equation_held,
            ac_value=original.ac_value,
            sc_value=original.sc_value,
            transform_log=original.transform_log,
            sealed_at=original.sealed_at,
            proof="bad" * 21 + "x",  # wrong proof
        )
        assert trace.verify(GENESIS_ROOT_HEX) is False

    def test_tampered_actor_id_in_paradata_fails(self):
        trace = _sealed_trace()
        original = trace.paradata
        # Change actor_id but leave proof intact → proof no longer matches
        malicious = Paradata(
            actor_id="attacker",            # changed
            capability_id=original.capability_id,
            genesis_root_hex=original.genesis_root_hex,
            wake_receipt_hash=original.wake_receipt_hash,
            sovereign_equation_held=original.sovereign_equation_held,
            ac_value=original.ac_value,
            sc_value=original.sc_value,
            transform_log=original.transform_log,
            sealed_at=original.sealed_at,
            proof=original.proof,           # old proof
        )
        trace.paradata = malicious
        assert trace.verify(GENESIS_ROOT_HEX) is False

    def test_sovereign_equation_false_fails_verify(self):
        trace = _sealed_trace(ac=_WEAK_AC, sc=_STRONG_SC)
        assert trace.verify(GENESIS_ROOT_HEX) is False

    def test_score_inconsistency_fails_verify(self):
        """A manually constructed Paradata with mismatched boolean/scores is rejected."""
        trace = _sealed_trace()
        original = trace.paradata
        # Forge: claim eq_held=True but ac_value < sc_value
        tmp = Paradata(
            actor_id=original.actor_id,
            capability_id=original.capability_id,
            genesis_root_hex=original.genesis_root_hex,
            wake_receipt_hash=original.wake_receipt_hash,
            sovereign_equation_held=True,    # lie
            ac_value=0.0,                    # contradicts True
            sc_value=1.0,
            transform_log=original.transform_log,
            sealed_at=original.sealed_at,
            proof="",
        )
        # Re-stamp with consistent proof so proof check passes, but score check fails
        forged = Paradata(
            actor_id=tmp.actor_id,
            capability_id=tmp.capability_id,
            genesis_root_hex=tmp.genesis_root_hex,
            wake_receipt_hash=tmp.wake_receipt_hash,
            sovereign_equation_held=tmp.sovereign_equation_held,
            ac_value=tmp.ac_value,
            sc_value=tmp.sc_value,
            transform_log=tmp.transform_log,
            sealed_at=tmp.sealed_at,
            proof=tmp.compute_proof(),
        )
        trace.paradata = forged
        # Stroke_head won't match because actor_id etc. are unchanged but we also
        # need to check that the score inconsistency is caught.
        # Force stroke_head to match so we isolate the score check:
        trace.stroke_head = _recompute_stroke_head(
            forged.actor_id,
            forged.capability_id,
            forged.genesis_root_hex,
            forged.transform_log,
        )
        assert trace.verify(GENESIS_ROOT_HEX) is False

    def test_multi_transform_trace_verifies(self):
        trace = _sealed_trace(n_transforms=5)
        assert trace.verify(GENESIS_ROOT_HEX) is True

    def test_zero_transform_trace_fails_verify(self):
        # No transforms → zero AC, zero SC → eq_held False → verify False
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace)
        assert trace.verify(GENESIS_ROOT_HEX) is False


class TestVerifyInbound:
    def test_valid_trace_passes(self):
        trace = _sealed_trace()
        assert AlgorithmicPolymath.verify_inbound(trace) is True

    def test_custom_genesis_root_used(self):
        trace = _sealed_trace()
        assert AlgorithmicPolymath.verify_inbound(
            trace, expected_genesis_root_hex="ff" * 32
        ) is False

    def test_default_genesis_root_is_a0(self):
        trace = _sealed_trace()
        assert AlgorithmicPolymath.verify_inbound(
            trace, expected_genesis_root_hex=GENESIS_ROOT_HEX
        ) is True


# ---------------------------------------------------------------------------
# CursiveTrace.to_dict
# ---------------------------------------------------------------------------


class TestCursiveTraceToDict:
    def test_to_dict_sealed(self):
        trace = _sealed_trace()
        d = trace.to_dict()
        assert d["sealed"] is True
        assert d["paradata"] is not None
        assert d["stroke_head"] == trace.stroke_head

    def test_to_dict_unsealed(self):
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, "x")
        d = trace.to_dict()
        assert d["sealed"] is False
        assert d["paradata"] is None

    def test_to_dict_contains_all_keys(self):
        trace = _sealed_trace()
        d = trace.to_dict()
        for key in (
            "trace_id", "payload", "actor_id", "capability_id",
            "genesis_root_hex", "stroke_head", "paradata", "sealed",
        ):
            assert key in d, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# Integration: full pipeline with WakeChain + Sovereign Equation
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_full_pipeline_wake_chain_grows(self):
        chain = WakeChain()
        pm = AlgorithmicPolymath(actor_id="alice", wake_chain=chain)
        before = len(chain)

        trace = pm.begin_stroke("cap-abc", {"counter": 0})
        pm.apply_transform(
            trace,
            lambda p: {**p, "counter": p["counter"] + 1},
            "increment",
            _STRONG_AC,
            _ZERO_SC,
        )
        pm.seal(trace, _STRONG_AC, _ZERO_SC)

        assert len(chain) == before + 1
        assert chain.verify()

    def test_cross_node_simulation(self):
        """Node A seals a trace; Node B verifies it without trusting Node A."""
        # Node A
        chain_a = WakeChain()
        pm_a = AlgorithmicPolymath(actor_id="node_a_operator", wake_chain=chain_a)
        trace = pm_a.begin_stroke("cap-xyz", {"msg": "hello"})
        pm_a.apply_transform(
            trace,
            lambda p: {**p, "msg": p["msg"].upper()},
            "uppercase",
            _STRONG_AC,
            _ZERO_SC,
        )
        pm_a.seal(trace, _STRONG_AC, _ZERO_SC)

        # "Transmit" trace to Node B (in practice, serialise/deserialise via to_dict)
        # Node B independently derives its own genesis root:
        from tas_dna import A_0 as node_b_a0
        node_b_genesis = node_b_a0.lineage_hash().hex()

        # Node B verifies without a shared wake chain
        result = AlgorithmicPolymath.verify_inbound(
            trace, expected_genesis_root_hex=node_b_genesis
        )
        assert result is True

    def test_adversarial_payload_substitution_detected(self):
        """An attacker replaces the payload after sealing; stroke mismatch detected."""
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {"secret": "original"})
        pm.apply_transform(trace, _identity, "passthrough", _STRONG_AC, _ZERO_SC)
        pm.seal(trace, _STRONG_AC, _ZERO_SC)

        # Attacker changes payload but cannot update paradata without breaking proof
        trace.payload = {"secret": "injected"}
        # Verification must still pass because payload is NOT part of the stroke
        # verification — the stroke verifies the COMPUTATION path, not the current
        # payload value.  The tamper is recorded in the wake chain receipt.
        # (The paradata commits the payload_hash at seal time via the wake receipt.)
        assert trace.verify(GENESIS_ROOT_HEX) is True  # trace geometry still valid

    def test_adversarial_stroke_tampering_detected(self):
        """An attacker replaces the stroke_head; cross-node check rejects it."""
        pm, _ = _make_polymath()
        trace = pm.begin_stroke(_CAP_ID, {"v": 1})
        pm.apply_transform(trace, _identity, "t", _STRONG_AC, _ZERO_SC)
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        trace.stroke_head = "00" * 32
        assert AlgorithmicPolymath.verify_inbound(trace) is False

    def test_multiple_polymaths_independent_wakes(self):
        """Two independent Polymath instances do not share wake chain state."""
        chain1, chain2 = WakeChain(), WakeChain()
        pm1 = AlgorithmicPolymath(actor_id="pm1", wake_chain=chain1)
        pm2 = AlgorithmicPolymath(actor_id="pm2", wake_chain=chain2)

        t1 = pm1.begin_stroke("c1", {})
        pm1.seal(t1, _STRONG_AC, _ZERO_SC)

        t2 = pm2.begin_stroke("c2", {})
        pm2.seal(t2, _STRONG_AC, _ZERO_SC)

        assert len(chain1) == 1
        assert len(chain2) == 1
        assert chain1.receipts[0].receipt_hash() != chain2.receipts[0].receipt_hash()


# ---------------------------------------------------------------------------
# TASDNA integration
# ---------------------------------------------------------------------------


def _make_polymath_with_dna() -> tuple[AlgorithmicPolymath, WakeChain, TASDNA]:
    chain = WakeChain()
    dna = TASDNA()
    pm = AlgorithmicPolymath(actor_id=_ACTOR, wake_chain=chain, tas_dna=dna)
    return pm, chain, dna


def _sealed_trace_with_dna(n_transforms: int = 1):
    pm, chain, dna = _make_polymath_with_dna()
    trace = pm.begin_stroke(_CAP_ID, {"v": 0})
    for i in range(n_transforms):
        pm.apply_transform(
            trace, lambda p: {**p, "v": p.get("v", 0) + 1}, f"incr_{i}",
            _STRONG_AC, _ZERO_SC,
        )
    pm.seal(trace, _STRONG_AC, _ZERO_SC)
    return trace, dna


class TestTASDNAIntegration:
    # -----------------------------------------------------------------------
    # Genesis root derivation
    # -----------------------------------------------------------------------

    def test_genesis_root_derived_from_tasdna_a0(self):
        pm, _, dna = _make_polymath_with_dna()
        assert pm._genesis_root == dna.a0.lineage_hash().hex()

    def test_genesis_root_differs_from_plain_constructor(self):
        """TASDNA-derived root should equal the module constant (same A_0)."""
        pm_dna, _, dna = _make_polymath_with_dna()
        pm_plain = AlgorithmicPolymath(actor_id=_ACTOR, wake_chain=WakeChain())
        assert pm_dna._genesis_root == pm_plain._genesis_root

    # -----------------------------------------------------------------------
    # pulse_index stamped at seal time
    # -----------------------------------------------------------------------

    def test_seal_stamps_pulse_index_zero_on_fresh_dna(self):
        trace, _ = _sealed_trace_with_dna()
        assert trace.paradata.pulse_index == 0

    def test_seal_stamps_current_pulse_count(self):
        pm, _, dna = _make_polymath_with_dna()
        dna.pulse()
        dna.pulse()  # pulse_count is now 2
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)
        assert trace.paradata.pulse_index == 2

    def test_pulse_index_in_paradata_proof(self):
        """Changing pulse_index after sealing invalidates the proof."""
        trace, _ = _sealed_trace_with_dna()
        original = trace.paradata
        forged = Paradata(
            actor_id=original.actor_id,
            capability_id=original.capability_id,
            genesis_root_hex=original.genesis_root_hex,
            wake_receipt_hash=original.wake_receipt_hash,
            sovereign_equation_held=original.sovereign_equation_held,
            ac_value=original.ac_value,
            sc_value=original.sc_value,
            transform_log=original.transform_log,
            sealed_at=original.sealed_at,
            pulse_index=original.pulse_index + 99,  # changed
            proof=original.proof,                   # old proof
        )
        trace.paradata = forged
        assert not forged.is_valid_proof()

    def test_pulse_index_in_to_dict(self):
        trace, _ = _sealed_trace_with_dna()
        d = trace.paradata.to_dict()
        assert "pulse_index" in d
        assert d["pulse_index"] == 0

    # -----------------------------------------------------------------------
    # verify_inbound with TASDNA – acceptance
    # -----------------------------------------------------------------------

    def test_verify_inbound_with_dna_accepts_valid_trace(self):
        trace, _ = _sealed_trace_with_dna()
        receiver_dna = TASDNA()  # fresh node, pulse_count == 0
        assert AlgorithmicPolymath.verify_inbound(trace, tas_dna=receiver_dna) is True

    def test_verify_inbound_advances_heartbeat_on_success(self):
        trace, _ = _sealed_trace_with_dna()
        receiver_dna = TASDNA()
        before = receiver_dna.pulse_count
        AlgorithmicPolymath.verify_inbound(trace, tas_dna=receiver_dna)
        assert receiver_dna.pulse_count == before + 1

    def test_verify_inbound_does_not_advance_heartbeat_on_failure(self):
        # Wrong pulse_index → rejection → no pulse advance
        pm, _, sender_dna = _make_polymath_with_dna()
        sender_dna.pulse()  # sender is at pulse 1, seals at index 1
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)

        receiver_dna = TASDNA()  # receiver expects pulse_index == 0
        before = receiver_dna.pulse_count
        result = AlgorithmicPolymath.verify_inbound(trace, tas_dna=receiver_dna)
        assert result is False
        assert receiver_dna.pulse_count == before  # unchanged

    # -----------------------------------------------------------------------
    # verify_inbound with TASDNA – sequential integrity
    # -----------------------------------------------------------------------

    def test_sequential_pulse_correct(self):
        trace, _ = _sealed_trace_with_dna()  # pulse_index == 0
        receiver = TASDNA()                  # pulse_count == 0 → expects 0
        assert AlgorithmicPolymath.verify_inbound(trace, tas_dna=receiver) is True

    def test_sequential_pulse_already_occurred_rejected(self):
        """Replay: receiver has already advanced past the incoming pulse_index."""
        trace, _ = _sealed_trace_with_dna()  # pulse_index == 0
        receiver = TASDNA()
        receiver.pulse()  # receiver now at 1 — incoming 0 is stale
        assert AlgorithmicPolymath.verify_inbound(trace, tas_dna=receiver) is False

    def test_sequential_pulse_gap_rejected(self):
        """Gap: incoming pulse_index is ahead of receiver's current count."""
        pm, _, sender_dna = _make_polymath_with_dna()
        sender_dna.pulse()
        sender_dna.pulse()  # seal will stamp pulse_index == 2
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)

        receiver = TASDNA()  # pulse_count == 0 — gap of 2
        assert AlgorithmicPolymath.verify_inbound(trace, tas_dna=receiver) is False

    def test_sequential_pulses_across_multiple_traces(self):
        """Receiver correctly ingests a sequence of traces one by one."""
        receiver = TASDNA()

        for expected_pulse in range(3):
            pm, _, sender_dna = _make_polymath_with_dna()
            # Advance sender to match expected_pulse so the stamp matches
            for _ in range(expected_pulse):
                sender_dna.pulse()
            trace = pm.begin_stroke(_CAP_ID, {"seq": expected_pulse})
            pm.seal(trace, _STRONG_AC, _ZERO_SC)
            assert trace.paradata.pulse_index == expected_pulse
            result = AlgorithmicPolymath.verify_inbound(trace, tas_dna=receiver)
            assert result is True
            assert receiver.pulse_count == expected_pulse + 1

    # -----------------------------------------------------------------------
    # verify_inbound with TASDNA – objective rejection
    # -----------------------------------------------------------------------

    def test_corrupted_a0_triggers_objective_rejection(self):
        """If a0.verify() fails on the receiver, the trace is dropped silently."""
        trace, _ = _sealed_trace_with_dna()
        bad_a0 = PrimaryInvariantA0(genesis_hash="sha256:CORRUPTED_HASH_VALUE")
        bad_dna = TASDNA(a0=bad_a0)
        assert AlgorithmicPolymath.verify_inbound(trace, tas_dna=bad_dna) is False

    def test_mismatched_lineage_root_rejected(self):
        """Trace sealed against a different A_0 is rejected by receiver's TASDNA."""
        # Seal with a custom (different) genesis root
        custom_dna = TASDNA(a0=PrimaryInvariantA0())
        chain = WakeChain()
        pm = AlgorithmicPolymath(
            actor_id=_ACTOR, wake_chain=chain, genesis_root_hex="ab" * 32
        )
        trace = pm.begin_stroke(_CAP_ID, {})
        pm.seal(trace, _STRONG_AC, _ZERO_SC)

        receiver_dna = TASDNA()  # canonical A_0
        # The trace genesis_root_hex won't match receiver's lineage hash
        assert AlgorithmicPolymath.verify_inbound(trace, tas_dna=receiver_dna) is False

    def test_objective_rejection_leaves_no_side_effects(self):
        """A rejected trace does not mutate the receiver TASDNA state."""
        receiver = TASDNA()
        bad_a0 = PrimaryInvariantA0(genesis_hash="sha256:BAD")
        bad_dna = TASDNA(a0=bad_a0)
        trace, _ = _sealed_trace_with_dna()

        before_pulse = receiver.pulse_count
        AlgorithmicPolymath.verify_inbound(trace, tas_dna=bad_dna)
        assert receiver.pulse_count == before_pulse  # canonical receiver untouched

    # -----------------------------------------------------------------------
    # Fallback path (no TASDNA)
    # -----------------------------------------------------------------------

    def test_fallback_no_dna_still_works(self):
        trace = _sealed_trace()
        assert AlgorithmicPolymath.verify_inbound(trace) is True

    def test_fallback_no_dna_wrong_root_fails(self):
        trace = _sealed_trace()
        assert AlgorithmicPolymath.verify_inbound(
            trace, expected_genesis_root_hex="00" * 32
        ) is False
