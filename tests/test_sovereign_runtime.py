import os
import sys
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sovereign_runtime import SovereignRuntime


@dataclass
class DummyDecision:
    admissible: bool
    reason: str = ""
    principal_id: str = "principal-1"
    agent_id: str = "agent-1"
    receipt_hash: str = "receipt-1"
    parent_state_root: str | None = None


class DummyGate:
    def __init__(self, decision):
        self._decision = decision

    def evaluate(self, _raw_payload: bytes):
        return self._decision


def test_admission_denied_preserves_state_and_appends_witness_receipt():
    runtime = SovereignRuntime(
        initial_state_root="root-0",
        initial_state={"vault_balance": 1000},
        gate_factory=lambda _root: DummyGate(
            DummyDecision(admissible=False, reason="POLICY_REFUSAL")
        ),
    )

    result = runtime.execute(b'{"action_payload":{"op":"SET","key":"vault_balance","value":0}}')

    assert result.success is False
    assert runtime.current_state_root == "root-0"
    assert runtime.state_store["vault_balance"] == 1000
    assert len(runtime.history_ledger) == 1
    assert runtime.history_ledger[0]["event"] == "ROLLBACK"
    assert runtime.history_ledger[0]["reason"] == "ADMISSION_DENIED"


def test_runtime_panic_preserves_state_and_appends_witness_receipt():
    runtime = SovereignRuntime(
        initial_state_root="root-0",
        initial_state={"vault_balance": 1000},
        gate_factory=lambda _root: DummyGate(DummyDecision(admissible=True)),
    )

    result = runtime.execute(b'{"action_payload":{"op":"DELETE","key":"missing"}}')

    assert result.success is False
    assert runtime.current_state_root == "root-0"
    assert runtime.state_store == {"vault_balance": 1000}
    assert len(runtime.history_ledger) == 1
    assert runtime.history_ledger[0]["event"] == "ROLLBACK"
    assert runtime.history_ledger[0]["reason"] == "RUNTIME_PANIC"


def test_decode_error_after_admission_is_rolled_back_with_witness():
    runtime = SovereignRuntime(
        initial_state_root="root-0",
        initial_state={"x": 1},
        gate_factory=lambda _root: DummyGate(DummyDecision(admissible=True)),
    )

    result = runtime.execute(b"{invalid-json")

    assert result.success is False
    assert runtime.current_state_root == "root-0"
    assert runtime.state_store == {"x": 1}
    assert len(runtime.history_ledger) == 1
    assert runtime.history_ledger[0]["reason"] == "PAYLOAD_DECODE_PANIC"


def test_state_root_commits_to_actual_post_state_not_only_request():
    payload = b'{"action_payload":{"op":"SET","key":"k","value":2}}'

    runtime_a = SovereignRuntime(
        initial_state_root="root-0",
        initial_state={"k": 1},
        gate_factory=lambda _root: DummyGate(DummyDecision(admissible=True, receipt_hash="r")),
    )
    runtime_b = SovereignRuntime(
        initial_state_root="root-0",
        initial_state={"k": 1, "other": 99},
        gate_factory=lambda _root: DummyGate(DummyDecision(admissible=True, receipt_hash="r")),
    )

    result_a = runtime_a.execute(payload)
    result_b = runtime_b.execute(payload)

    assert result_a.success is True
    assert result_b.success is True
    assert result_a.new_state_root != result_b.new_state_root


def test_speculative_state_isolated_from_protected_state_on_panic():
    runtime = SovereignRuntime(
        initial_state_root="root-0",
        initial_state={"nested": {"x": 1}},
        gate_factory=lambda _root: DummyGate(DummyDecision(admissible=True)),
    )

    def mutating_then_panicking(state, _action):
        state["nested"]["x"] = 2
        raise RuntimeError("boom")

    runtime._apply_sandbox_action = mutating_then_panicking  # type: ignore[method-assign]
    result = runtime.execute(b'{"action_payload":{"op":"SET","key":"unused","value":0}}')

    assert result.success is False
    assert runtime.state_store["nested"]["x"] == 1
    assert runtime.current_state_root == "root-0"
    assert runtime.history_ledger[0]["reason"] == "RUNTIME_PANIC"


def test_parent_state_mismatch_rolls_back_and_records_witness():
    runtime = SovereignRuntime(
        initial_state_root="root-0",
        initial_state={"x": 1},
        gate_factory=lambda _root: DummyGate(
            DummyDecision(admissible=True, parent_state_root="root-old")
        ),
    )

    result = runtime.execute(b'{"action_payload":{"op":"SET","key":"x","value":2}}')

    assert result.success is False
    assert runtime.current_state_root == "root-0"
    assert runtime.state_store["x"] == 1
    assert len(runtime.history_ledger) == 1
    assert runtime.history_ledger[0]["reason"] == "PARENT_STATE_MISMATCH"
