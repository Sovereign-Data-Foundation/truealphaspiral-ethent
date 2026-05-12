#!/usr/bin/env python3
"""Day One deterministic workflow gate receipt tooling.

The Day One directive is intentionally fail-closed: the receipt must be emitted
before a workflow gate can proceed, and verification rejects any missing receipt,
failed invariant, workflow mismatch, head-SHA mismatch, or missing
sovereign-intent proof.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release-docker.yaml"
FALLBACK_WORKFLOW_NAME = "blank.yml"
FALLBACK_WORKFLOW = ROOT / ".github" / "workflows" / FALLBACK_WORKFLOW_NAME
DEFAULT_RECEIPT = ROOT / "receipts" / "day-one-receipt.json"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from capability import CapabilityTable, Right  # noqa: E402
from uvk import AdmissionStatus, Invariant, UVK  # noqa: E402
from wake_chain import WakeChain  # noqa: E402


def _run_git(args: Iterable[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def active_head_sha() -> str:
    """Return the active repository HEAD SHA."""
    return _run_git(["rev-parse", "HEAD"])


def sha256_text(value: str) -> str:
    """Return a SHA-256 digest for *value* without storing the value itself."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def resolve_workflow(workflow_name: str) -> Path:
    """Resolve a workflow name relative to ``.github/workflows``."""
    workflow_path = ROOT / ".github" / "workflows" / workflow_name
    return workflow_path.resolve()


def release_workflow_available() -> bool:
    """Return true when the production release Docker workflow exists."""
    return RELEASE_WORKFLOW.exists()


def workflow_is_admissible(workflow_name: str) -> bool:
    """Return true when the requested Day One workflow is allowed now."""
    workflow_path = resolve_workflow(workflow_name)
    if release_workflow_available():
        return workflow_path == RELEASE_WORKFLOW.resolve() and workflow_path.exists()
    return (
        workflow_name == FALLBACK_WORKFLOW_NAME
        and workflow_path == FALLBACK_WORKFLOW.resolve()
        and workflow_path.exists()
    )


def build_invariants() -> list[Invariant]:
    """Build fail-closed invariants for the Day One receipt emission."""
    return [
        Invariant(
            name="active_head_matches_dispatch_head",
            version="1.0.0",
            check=lambda state, _action, inputs: state.get("active_head_sha")
            == inputs.get("head_sha"),
        ),
        Invariant(
            name="sovereign_intent_proof_present",
            version="1.0.0",
            check=lambda _state, _action, inputs: bool(
                str(inputs.get("sovereign_intent_proof", "")).strip()
            ),
        ),
        Invariant(
            name="workflow_gate_available",
            version="1.0.0",
            check=lambda _state, _action, inputs: workflow_is_admissible(
                str(inputs.get("workflow_name", ""))
            ),
        ),
    ]


def emit_receipt(
    *,
    head_sha: str,
    workflow_name: str,
    sovereign_intent_proof: str,
    receipt_path: Path = DEFAULT_RECEIPT,
) -> Dict[str, Any]:
    """Emit and persist the Day One provenance receipt.

    Raises ``RuntimeError`` when any fail-closed invariant denies admission.
    """
    active_sha = active_head_sha()
    workflow_path = resolve_workflow(workflow_name)
    state = {
        "active_head_sha": active_sha,
        "release_workflow_available": release_workflow_available(),
    }
    inputs = {
        "head_sha": head_sha,
        "workflow_name": workflow_name,
        "workflow_path": str(workflow_path.relative_to(ROOT))
        if workflow_path.is_relative_to(ROOT)
        else str(workflow_path),
        "sovereign_intent_proof": sovereign_intent_proof,
    }

    wake = WakeChain(session_id=f"day-one-{head_sha[:12]}")
    cap_table = CapabilityTable()
    cap = cap_table.retype(
        "day-one-deterministic-workflow-gate", Right.EXECUTE | Right.MINT
    )
    uvk = UVK(
        capability_table=cap_table,
        wake_chain=wake,
        invariants=build_invariants(),
    )
    result = uvk.admit(
        cap,
        Right.EXECUTE,
        action="dispatch_deterministic_workflow_gate",
        state=state,
        inputs=inputs,
        extra_info={
            "directive": "PR-158-Day-One",
            "fallback_workflow": FALLBACK_WORKFLOW_NAME,
            "release_workflow_available": release_workflow_available(),
        },
    )

    receipt_present = result.receipt is not None
    payload: Dict[str, Any] = {
        "directive": "PR-158-Day-One",
        "admitted": result.admitted,
        "status": result.status.name,
        "receipt_present": receipt_present,
        "active_head_sha": active_sha,
        "requested_head_sha": head_sha,
        "workflow_name": workflow_name,
        "workflow_path": inputs["workflow_path"],
        "release_workflow_available": release_workflow_available(),
        "fallback_active": not release_workflow_available(),
        "sovereign_intent_proof_sha256": sha256_text(sovereign_intent_proof)
        if sovereign_intent_proof.strip()
        else "",
        "failed_invariants": result.failed_invariants,
        "wake_valid": wake.verify(),
        "wake_head": wake.head.hex(),
        "receipt_hash": result.receipt.receipt_hash().hex() if result.receipt else "",
        "receipt": result.receipt.to_dict() if result.receipt else None,
    }

    if not result.admitted or not receipt_present or not wake.verify():
        raise RuntimeError(json.dumps(payload, indent=2, sort_keys=True))

    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return payload


def verify_receipt(
    *,
    receipt_path: Path = DEFAULT_RECEIPT,
    head_sha: Optional[str] = None,
    workflow_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify that an emitted Day One receipt satisfies fail-closed gates."""
    if not receipt_path.exists():
        raise FileNotFoundError(f"missing Day One receipt: {receipt_path}")

    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    failures = []
    if not payload.get("receipt_present"):
        failures.append("missing receipt")
    if not payload.get("admitted") or payload.get("status") != AdmissionStatus.ADMITTED.name:
        failures.append("receipt admission failed")
    if payload.get("failed_invariants"):
        failures.append("failed invariant")
    if not payload.get("wake_valid"):
        failures.append("wake verification failed")
    if not payload.get("receipt_hash"):
        failures.append("missing receipt hash")
    if not payload.get("sovereign_intent_proof_sha256"):
        failures.append("missing sovereign-intent proof")
    if head_sha and payload.get("requested_head_sha") != head_sha:
        failures.append("receipt head SHA mismatch")
    if workflow_name and payload.get("workflow_name") != workflow_name:
        failures.append("receipt workflow mismatch")
    if not workflow_is_admissible(str(payload.get("workflow_name", ""))):
        failures.append("workflow gate unavailable")

    if failures:
        raise RuntimeError("; ".join(failures))
    return payload


def cmd_emit(args: argparse.Namespace) -> int:
    payload = emit_receipt(
        head_sha=args.head_sha,
        workflow_name=args.workflow_name,
        sovereign_intent_proof=args.sovereign_intent_proof,
        receipt_path=Path(args.receipt_path),
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    payload = verify_receipt(
        receipt_path=Path(args.receipt_path),
        head_sha=args.head_sha,
        workflow_name=args.workflow_name,
    )
    print(
        json.dumps(
            {"verified": True, "receipt_hash": payload["receipt_hash"]}, indent=2
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Emit or verify the Day One workflow-gate receipt."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    emit = subparsers.add_parser(
        "emit", help="emit the Day One receipt before dispatching the gate"
    )
    emit.add_argument(
        "--head-sha", required=True, help="active head SHA that the gate must prove"
    )
    emit.add_argument(
        "--workflow-name",
        default=FALLBACK_WORKFLOW_NAME,
        help="workflow file name to gate",
    )
    emit.add_argument(
        "--sovereign-intent-proof",
        required=True,
        help="non-empty proof binding the human directive",
    )
    emit.add_argument(
        "--receipt-path",
        default=str(DEFAULT_RECEIPT),
        help="path to write the emitted receipt JSON",
    )
    emit.set_defaults(func=cmd_emit)

    verify = subparsers.add_parser("verify", help="verify an emitted Day One receipt")
    verify.add_argument(
        "--receipt-path",
        default=str(DEFAULT_RECEIPT),
        help="receipt JSON path to verify",
    )
    verify.add_argument("--head-sha", help="expected head SHA")
    verify.add_argument("--workflow-name", help="expected workflow file name")
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
