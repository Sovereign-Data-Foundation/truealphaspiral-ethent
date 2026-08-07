import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from admission_gate import evaluate_proposal


def _proposal():
    return {"operation": "increment", "amount": 1}


def _evidence(**overrides):
    base = {
        "sig_valid": True,
        "authority_valid": True,
        "lineage_valid": True,
        "context_valid": True,
        "invariant_pass": True,
        "replay_detected": False,
        "timestamp_ns": 1786064400000000000,
    }
    base.update(overrides)
    return base


def test_refusal_gate_short_circuits_in_declared_order():
    admitted, receipt = evaluate_proposal(
        _proposal(),
        _evidence(sig_valid=False, authority_valid=False),
        "a" * 64,
    )
    assert admitted is False
    assert receipt["failed_gate"] == "GATE_FAIL_SIG_INVALID"
    assert receipt["delta_s"] == 0
    assert receipt["resulting_state"] == "REFUSED"


def test_refusal_gate_detects_replay_after_other_gates_pass():
    admitted, receipt = evaluate_proposal(
        _proposal(),
        _evidence(replay_detected=True),
        "b" * 64,
    )
    assert admitted is False
    assert receipt["failed_gate"] == "GATE_FAIL_REPLAY_DETECTED"
    assert receipt["delta_s"] == 0


def test_refusal_receipt_hash_is_deterministic():
    admitted1, receipt1 = evaluate_proposal(
        _proposal(),
        _evidence(context_valid=False),
        "c" * 64,
    )
    admitted2, receipt2 = evaluate_proposal(
        _proposal(),
        _evidence(context_valid=False),
        "c" * 64,
    )
    assert admitted1 is False
    assert admitted2 is False
    assert receipt1["receipt_hash"] == receipt2["receipt_hash"]
    assert receipt1["proposal_hash"] == receipt2["proposal_hash"]


def test_admitted_path_returns_admitted_decision():
    admitted, result = evaluate_proposal(
        _proposal(),
        _evidence(),
        "d" * 64,
    )
    assert admitted is True
    assert result["resulting_state"] == "ADMITTED"
    assert result["failed_gate"] is None
    assert result["delta_s"] == 0
