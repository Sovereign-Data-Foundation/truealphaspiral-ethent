"""Sovereign runtime with admission-gated speculative execution and atomic rollback."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import copy
import hashlib
import json
from typing import Any, Callable, Dict, Mapping, Optional


@dataclass(frozen=True)
class AdmissibilityDecision:
    admissible: bool
    reason: str = ""
    principal_id: Optional[str] = None
    agent_id: Optional[str] = None
    receipt_hash: str = ""
    parent_state_root: Optional[str] = None


@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    previous_state_root: str
    new_state_root: str
    decision: AdmissibilityDecision
    state_delta: Dict[str, Any]
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SovereignRuntime:
    def __init__(
        self,
        initial_state_root: str,
        initial_state: Optional[Dict[str, Any]] = None,
        gate_factory: Optional[Callable[[str], Any]] = None,
    ):
        self.current_state_root = initial_state_root
        self.state_store: Dict[str, Any] = copy.deepcopy(initial_state) if initial_state else {}
        self.history_ledger: list[Dict[str, Any]] = []
        self._gate_factory = gate_factory

    def execute(self, raw_payload: bytes) -> ExecutionResult:
        """Evaluate, speculate, and commit only on successful admissible execution."""
        previous_root = self.current_state_root
        request_hash = hashlib.sha256(raw_payload).hexdigest()
        gate = self._build_gate(previous_root)
        try:
            decision = self._normalize_decision(gate.evaluate(raw_payload))
        except Exception as gate_error:
            decision = AdmissibilityDecision(
                admissible=False,
                reason=f"GATE_EVALUATION_ERROR:{type(gate_error).__name__}",
            )
            return self._rollback_with_witness(
                previous_root=previous_root,
                decision=decision,
                error=f"ADMISSION_DENIED: {decision.reason}",
                reason="ADMISSION_DENIED",
                request_hash=request_hash,
            )

        if not decision.admissible:
            reason = decision.reason or "NOT_ADMISSIBLE"
            return self._rollback_with_witness(
                previous_root=previous_root,
                decision=decision,
                error=f"ADMISSION_DENIED: {reason}",
                reason="ADMISSION_DENIED",
                request_hash=request_hash,
            )
        if (
            decision.parent_state_root is not None
            and decision.parent_state_root != previous_root
        ):
            return self._rollback_with_witness(
                previous_root=previous_root,
                decision=decision,
                error=(
                    "STALE_PARENT_ROOT: "
                    f"PARENT_STATE_MISMATCH:{decision.parent_state_root}!={previous_root}"
                ),
                reason="PARENT_STATE_MISMATCH",
                request_hash=request_hash,
            )

        try:
            payload_text = raw_payload.decode("utf-8")
        except UnicodeDecodeError as decode_error:
            return self._rollback_with_witness(
                previous_root=previous_root,
                decision=decision,
                error=f"PAYLOAD_DECODE_ROLLBACK: {decode_error}",
                reason="PAYLOAD_UTF8_PANIC",
                request_hash=request_hash,
            )
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError as decode_error:
            return self._rollback_with_witness(
                previous_root=previous_root,
                decision=decision,
                error=f"PAYLOAD_DECODE_ROLLBACK: {decode_error}",
                reason="PAYLOAD_JSON_PANIC",
                request_hash=request_hash,
            )
        if not isinstance(payload, Mapping):
            return self._rollback_with_witness(
                previous_root=previous_root,
                decision=decision,
                error="PAYLOAD_DECODE_ROLLBACK: top-level payload must be an object",
                reason="PAYLOAD_SHAPE_PANIC",
                request_hash=request_hash,
            )

        if "action_payload" not in payload or not isinstance(
            payload["action_payload"], Mapping
        ):
            return self._rollback_with_witness(
                previous_root=previous_root,
                decision=decision,
                error="PAYLOAD_DECODE_ROLLBACK: action_payload must be an object",
                reason="PAYLOAD_SHAPE_PANIC",
                request_hash=request_hash,
            )
        action_payload = payload["action_payload"]
        speculative_state = copy.deepcopy(self.state_store)

        try:
            state_delta = self._apply_sandbox_action(speculative_state, action_payload)
        except Exception as runtime_err:
            return self._rollback_with_witness(
                previous_root=previous_root,
                decision=decision,
                error=f"RUNTIME_PANIC_ROLLBACK: {runtime_err}",
                reason="RUNTIME_PANIC",
                request_hash=request_hash,
            )

        state_hash = self._state_commitment_hash(speculative_state)
        self.state_store = speculative_state
        new_root = self._compute_next_state_root(
            previous_root,
            request_hash,
            state_hash,
            decision.receipt_hash,
        )
        self.current_state_root = new_root

        self._append_history_leaf(
            {
                "event": "COMMIT",
                "previous_root": previous_root,
                "new_root": new_root,
                "principal_id": decision.principal_id,
                "agent_id": decision.agent_id,
                "receipt_hash": decision.receipt_hash,
                "request_hash": request_hash,
                "state_hash": state_hash,
                "delta": state_delta,
            }
        )

        return ExecutionResult(
            success=True,
            previous_state_root=previous_root,
            new_state_root=new_root,
            decision=decision,
            state_delta=state_delta,
            error=None,
        )

    def _rollback_with_witness(
        self,
        *,
        previous_root: str,
        decision: AdmissibilityDecision,
        error: str,
        reason: str,
        request_hash: str,
    ) -> ExecutionResult:
        state_hash = self._state_commitment_hash(self.state_store)
        self._append_history_leaf(
            {
                "event": "ROLLBACK",
                "reason": reason,
                "previous_root": previous_root,
                "new_root": previous_root,
                "principal_id": decision.principal_id,
                "agent_id": decision.agent_id,
                "receipt_hash": decision.receipt_hash,
                "request_hash": request_hash,
                "state_hash": state_hash,
                "delta": {},
                "error": error,
            }
        )
        return ExecutionResult(
            success=False,
            previous_state_root=previous_root,
            new_state_root=previous_root,
            decision=decision,
            state_delta={},
            error=error,
        )

    def _build_gate(self, current_state_root: str) -> Any:
        if self._gate_factory is not None:
            return self._gate_factory(current_state_root)

        try:
            from admission_gate import AdmissionGate  # type: ignore
        except ImportError as import_error:  # pragma: no cover
            raise RuntimeError(
                "No gate_factory provided and admission_gate.AdmissionGate is unavailable"
            ) from import_error
        return AdmissionGate(current_state_root=current_state_root)

    @staticmethod
    def _normalize_decision(raw_decision: Any) -> AdmissibilityDecision:
        if isinstance(raw_decision, AdmissibilityDecision):
            return raw_decision

        if isinstance(raw_decision, Mapping):
            return AdmissibilityDecision(
                admissible=bool(raw_decision.get("admissible", False)),
                reason=str(raw_decision.get("reason", "")),
                principal_id=_as_optional_str(raw_decision.get("principal_id")),
                agent_id=_as_optional_str(raw_decision.get("agent_id")),
                receipt_hash=str(raw_decision.get("receipt_hash", "")),
                parent_state_root=_as_optional_str(raw_decision.get("parent_state_root")),
            )

        return AdmissibilityDecision(
            admissible=bool(getattr(raw_decision, "admissible", False)),
            reason=str(getattr(raw_decision, "reason", "")),
            principal_id=_as_optional_str(getattr(raw_decision, "principal_id", None)),
            agent_id=_as_optional_str(getattr(raw_decision, "agent_id", None)),
            receipt_hash=str(getattr(raw_decision, "receipt_hash", "")),
            parent_state_root=_as_optional_str(
                getattr(raw_decision, "parent_state_root", None)
            ),
        )

    @staticmethod
    def _canonical_hash(value: Any) -> str:
        normalized = _normalize_for_canonical(value)
        canonical = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def _state_commitment_hash(cls, state: Mapping[str, Any]) -> str:
        return cls._canonical_hash(state)

    @staticmethod
    def _compute_next_state_root(
        previous_root: str,
        request_hash: str,
        post_state_hash: str,
        receipt_hash: str,
    ) -> str:
        material = {
            "previous_root": previous_root,
            "request_hash": request_hash,
            "post_state_hash": post_state_hash,
            "receipt_hash": receipt_hash,
        }
        return SovereignRuntime._canonical_hash(material)

    def _append_history_leaf(self, entry: Dict[str, Any]) -> None:
        self.history_ledger.append(entry)

    def _apply_sandbox_action(
        self,
        sandbox_state: Dict[str, Any],
        action: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Execute bounded deterministic state mutations in speculative memory."""
        if not isinstance(action, Mapping):
            raise TypeError("Action payload must be a mapping.")

        op = action.get("op")
        key = action.get("key")
        value = action.get("value")

        if op == "SET":
            if not isinstance(key, str) or not key:
                raise ValueError("SET operation requires a valid key.")
            sandbox_state[key] = value
            return {key: value}

        if op == "DELETE":
            if not isinstance(key, str) or not key:
                raise ValueError("DELETE operation requires a valid key.")
            if key not in sandbox_state:
                raise KeyError(f"Key '{key}' does not exist in state store.")
            sandbox_state.pop(key)
            return {key: "<DELETED>"}

        raise ValueError(f"Unsupported operation: {op!r}")


def _as_optional_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _normalize_for_canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _normalize_for_canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_for_canonical(v) for v in value]
    if isinstance(value, tuple):
        return [_normalize_for_canonical(v) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float, str)):
        return value
    return str(value)
