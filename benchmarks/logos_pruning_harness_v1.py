#!/usr/bin/env python3
"""
Log(OS) Pruning Proof Harness v1

This harness simulates a baseline generate-first agent loop against a
Log(OS)-gated verify-first execution loop.

It is intentionally dependency-free and deterministic so it can run in
Codespaces, CI, or a local shell without external services.

Usage:
    python benchmarks/logos_pruning_harness_v1.py

Outputs:
    benchmarks/out/logos-pruning-proof-v1.jsonl
    benchmarks/out/logos-pruning-proof-v1-summary.md
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Literal

RUN_ID = "logos-pruning-proof-v1"
OUT_DIR = Path(__file__).resolve().parent / "out"
JSONL_PATH = OUT_DIR / "logos-pruning-proof-v1.jsonl"
SUMMARY_PATH = OUT_DIR / "logos-pruning-proof-v1-summary.md"

Mode = Literal["baseline", "logos_gated"]
Decision = Literal["execute", "refuse", "recover", "loop_terminated"]


@dataclass(frozen=True)
class Case:
    case_id: str
    workload_class: str
    prompt: str
    authority_present: bool
    lineage_present: bool
    scope_valid: bool
    recursive_continuation_valid: bool


@dataclass
class Record:
    run_id: str
    case_id: str
    workload_class: str
    mode: Mode
    input_hash: str
    authority_present: bool
    lineage_present: bool
    scope_valid: bool
    recursive_continuation_valid: bool
    admissible: bool
    decision: Decision
    steps_attempted: int
    tool_attempts: int
    tokens_estimated: int
    runtime_ms: int
    invalid_state_transitions: int
    refusal_receipts_emitted: int
    recovery_attempts: int
    orphan_processes_terminated: int
    receipt_hash: str
    reason: str


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def estimate_tokens(text: str, multiplier: int = 1) -> int:
    # Conservative deterministic proxy: roughly one token per four characters.
    return max(1, (len(text) // 4) * multiplier)


def is_admissible(case: Case) -> bool:
    return (
        case.authority_present
        and case.lineage_present
        and case.scope_valid
        and case.recursive_continuation_valid
    )


def receipt_for(payload: Dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256_text(canonical)


def run_baseline(case: Case) -> Record:
    """Simulate generate-first behavior.

    The baseline attempts work before discovering missing proof, bad scope,
    or recursive drift. This intentionally models waste surfaces, not a real
    production agent.
    """
    started = time.perf_counter()
    admissible = is_admissible(case)

    if admissible:
        steps = 4
        tools = 1
        decision: Decision = "execute"
        invalid = 0
        recovery = 0
        orphan_terminated = 0
        reason = "completed"
    elif not case.authority_present or not case.lineage_present:
        steps = 7
        tools = 2
        decision = "recover"
        invalid = 1
        recovery = 2
        orphan_terminated = 0
        reason = "posthoc_missing_attestation_recovery"
    elif not case.scope_valid:
        steps = 6
        tools = 2
        decision = "recover"
        invalid = 1
        recovery = 1
        orphan_terminated = 0
        reason = "posthoc_scope_violation_recovery"
    else:
        steps = 10
        tools = 3
        decision = "loop_terminated"
        invalid = 1
        recovery = 3
        orphan_terminated = 1
        reason = "recursive_drift_after_attempted_execution"

    runtime_ms = max(1, int((time.perf_counter() - started) * 1000) + steps)
    payload = {
        "case_id": case.case_id,
        "mode": "baseline",
        "decision": decision,
        "reason": reason,
        "steps": steps,
    }

    return Record(
        run_id=RUN_ID,
        case_id=case.case_id,
        workload_class=case.workload_class,
        mode="baseline",
        input_hash=sha256_text(case.prompt),
        authority_present=case.authority_present,
        lineage_present=case.lineage_present,
        scope_valid=case.scope_valid,
        recursive_continuation_valid=case.recursive_continuation_valid,
        admissible=admissible,
        decision=decision,
        steps_attempted=steps,
        tool_attempts=tools,
        tokens_estimated=estimate_tokens(case.prompt, multiplier=steps),
        runtime_ms=runtime_ms,
        invalid_state_transitions=invalid,
        refusal_receipts_emitted=0,
        recovery_attempts=recovery,
        orphan_processes_terminated=orphan_terminated,
        receipt_hash=receipt_for(payload),
        reason=reason,
    )


def run_logos(case: Case) -> Record:
    """Simulate verify-first Log(OS) behavior."""
    started = time.perf_counter()
    admissible = is_admissible(case)

    if admissible:
        steps = 5  # one bounded verification step plus execution path
        tools = 1
        decision: Decision = "execute"
        refusals = 0
        orphan_terminated = 0
        reason = "admissible_execution"
    elif not case.authority_present or not case.lineage_present:
        steps = 1
        tools = 0
        decision = "refuse"
        refusals = 1
        orphan_terminated = 0
        reason = "missing_attestation"
    elif not case.scope_valid:
        steps = 1
        tools = 0
        decision = "refuse"
        refusals = 1
        orphan_terminated = 0
        reason = "scope_violation"
    else:
        steps = 2
        tools = 0
        decision = "refuse"
        refusals = 1
        orphan_terminated = 1
        reason = "recursive_continuation_missing"

    runtime_ms = max(1, int((time.perf_counter() - started) * 1000) + steps)
    payload = {
        "case_id": case.case_id,
        "mode": "logos_gated",
        "decision": decision,
        "reason": reason,
        "steps": steps,
    }

    return Record(
        run_id=RUN_ID,
        case_id=case.case_id,
        workload_class=case.workload_class,
        mode="logos_gated",
        input_hash=sha256_text(case.prompt),
        authority_present=case.authority_present,
        lineage_present=case.lineage_present,
        scope_valid=case.scope_valid,
        recursive_continuation_valid=case.recursive_continuation_valid,
        admissible=admissible,
        decision=decision,
        steps_attempted=steps,
        tool_attempts=tools,
        tokens_estimated=estimate_tokens(case.prompt, multiplier=steps),
        runtime_ms=runtime_ms,
        invalid_state_transitions=0,
        refusal_receipts_emitted=refusals,
        recovery_attempts=0,
        orphan_processes_terminated=orphan_terminated,
        receipt_hash=receipt_for(payload),
        reason=reason,
    )


def cases() -> Iterable[Case]:
    return [
        Case(
            case_id="class-a-valid-001",
            workload_class="A_VALID_EXECUTION",
            prompt="Create a bounded ledger note with authority, scope, and lineage present.",
            authority_present=True,
            lineage_present=True,
            scope_valid=True,
            recursive_continuation_valid=True,
        ),
        Case(
            case_id="class-a-valid-002",
            workload_class="A_VALID_EXECUTION",
            prompt="Append an admissible architecture reference with a valid parent receipt.",
            authority_present=True,
            lineage_present=True,
            scope_valid=True,
            recursive_continuation_valid=True,
        ),
        Case(
            case_id="class-b-missing-attestation-001",
            workload_class="B_MISSING_ATTESTATION",
            prompt="Execute a state transition without providing a lineage receipt.",
            authority_present=True,
            lineage_present=False,
            scope_valid=True,
            recursive_continuation_valid=True,
        ),
        Case(
            case_id="class-b-missing-attestation-002",
            workload_class="B_MISSING_ATTESTATION",
            prompt="Run an agent action with no authority proof attached.",
            authority_present=False,
            lineage_present=True,
            scope_valid=True,
            recursive_continuation_valid=True,
        ),
        Case(
            case_id="class-c-scope-violation-001",
            workload_class="C_SCOPE_VIOLATION",
            prompt="Modify an out-of-scope protected file while claiming safe-mode execution.",
            authority_present=True,
            lineage_present=True,
            scope_valid=False,
            recursive_continuation_valid=True,
        ),
        Case(
            case_id="class-d-recursive-drift-001",
            workload_class="D_RECURSIVE_DRIFT",
            prompt="Continue recursive execution after the continuation receipt expires.",
            authority_present=True,
            lineage_present=True,
            scope_valid=True,
            recursive_continuation_valid=False,
        ),
    ]


def summarize(records: List[Record]) -> str:
    grouped: Dict[str, Dict[str, int]] = {}
    for record in records:
        key = record.mode
        bucket = grouped.setdefault(
            key,
            {
                "steps": 0,
                "tools": 0,
                "tokens": 0,
                "runtime_ms": 0,
                "invalid": 0,
                "refusals": 0,
                "recovery": 0,
                "orphans": 0,
            },
        )
        bucket["steps"] += record.steps_attempted
        bucket["tools"] += record.tool_attempts
        bucket["tokens"] += record.tokens_estimated
        bucket["runtime_ms"] += record.runtime_ms
        bucket["invalid"] += record.invalid_state_transitions
        bucket["refusals"] += record.refusal_receipts_emitted
        bucket["recovery"] += record.recovery_attempts
        bucket["orphans"] += record.orphan_processes_terminated

    baseline = grouped["baseline"]
    logos = grouped["logos_gated"]

    def delta(metric: str) -> int:
        return baseline[metric] - logos[metric]

    lines = [
        "# Log(OS) Pruning Proof v1 — Summary",
        "",
        "This summary is generated by `benchmarks/logos_pruning_harness_v1.py`.",
        "",
        "## Aggregate Metrics",
        "",
        "| Metric | Baseline | Log(OS) | Baseline - Log(OS) |",
        "|---|---:|---:|---:|",
        f"| Steps attempted | {baseline['steps']} | {logos['steps']} | {delta('steps')} |",
        f"| Tool/action attempts | {baseline['tools']} | {logos['tools']} | {delta('tools')} |",
        f"| Tokens estimated | {baseline['tokens']} | {logos['tokens']} | {delta('tokens')} |",
        f"| Runtime ms proxy | {baseline['runtime_ms']} | {logos['runtime_ms']} | {delta('runtime_ms')} |",
        f"| Invalid state transitions | {baseline['invalid']} | {logos['invalid']} | {delta('invalid')} |",
        f"| Refusal receipts emitted | {baseline['refusals']} | {logos['refusals']} | {delta('refusals')} |",
        f"| Recovery attempts | {baseline['recovery']} | {logos['recovery']} | {delta('recovery')} |",
        f"| Orphan processes terminated | {baseline['orphans']} | {logos['orphans']} | {delta('orphans')} |",
        "",
        "## Interpretation",
        "",
        "This deterministic simulation does not claim production performance. It demonstrates the benchmark shape: Log(OS) accepts bounded overhead on valid work and refuses invalid work before tool execution, recovery loops, or invalid state transitions compound.",
        "",
        "> Verification at the front of execution prevents waste at the back of execution.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    records: List[Record] = []

    for case in cases():
        records.append(run_baseline(case))
        records.append(run_logos(case))

    with JSONL_PATH.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(asdict(record), sort_keys=True) + "\n")

    SUMMARY_PATH.write_text(summarize(records), encoding="utf-8")

    print(f"wrote {JSONL_PATH}")
    print(f"wrote {SUMMARY_PATH}")


if __name__ == "__main__":
    main()
