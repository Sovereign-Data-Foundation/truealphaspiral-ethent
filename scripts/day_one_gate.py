#!/usr/bin/env python3
"""Day One deterministic workflow gate receipt tooling.

The Day One directive is intentionally fail-closed: the receipt must be emitted
before a workflow gate can proceed, and verification rejects any missing receipt,
failed invariant, workflow mismatch, head-SHA mismatch, missing sovereign-intent
proof, or missing path-sensitive acquisition proof.
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
DEFAULT_NOVELTY_ASSERTION = "day-one-active-head-treated-as-new"
DEFAULT_ACQUISITION_TRACE = (
    "resolve-head -> emit-receipt -> verify-receipt -> deterministic-test-gate"
)
DEFAULT_SEARCH_STEPS = 4
DEFAULT_MAX_SEARCH_STEPS = 16
DEFAULT_INTERFACE_PROVENANCE = "github-actions-workflow-dispatch-or-pull-request-checkout"
PATH_SENSITIVE_GATE_NAMES = (
    "novelty_gate",
    "acquisition_trace_gate",
    "efficiency_gate",
    "interface_exploit_gate",
    "refusal_gate",
)
DEFAULT_MAXIM_PROOFS = {
    "ignorance_no_excuse": "operator acknowledges law and policy are not optional",
    "agreements_kept": "Day One action preserves stated steward agreement",
    "clean_hands": "receipt records provenance before seeking workflow relief",
    "do_equity": "gate applies the same proof burden to every execution path",
    "wrong_has_remedy": "failures are surfaced as explicit denial receipts",
    "ought_done": "promised receipt is emitted before workflow execution",
    "no_laches": "known missing proofs fail immediately",
    "truth_sovereign": "receipt hashes bind claims to verifiable artifacts",
    "unrebutted_claims": "unanswered gate failures remain denial facts",
    "workman_worthy_hire": "human steward intent is attributed and preserved",
    "mens_rea_recklessness": "known unbounded or opaque execution is refused",
    "no_self_accusation": "receipt stores proof hashes instead of raw sensitive proof",
    "wrongful_possession": "unconsented or unproven inputs are inadmissible",
}
MAXIMS_OF_LAW_GATE_NAMES = tuple(DEFAULT_MAXIM_PROOFS)

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


def proof_present(inputs: Dict[str, Any], field: str) -> bool:
    """Return true when a named proof field is non-empty."""
    return bool(str(inputs.get(field, "")).strip())


def parse_maxim_proof_item(value: str) -> tuple[str, str]:
    """Parse a ``NAME=PROOF`` CLI maxim override."""
    if "=" not in value:
        raise argparse.ArgumentTypeError("maxim proof must be formatted as NAME=PROOF")
    name, proof = value.split("=", 1)
    if name not in DEFAULT_MAXIM_PROOFS:
        known = ", ".join(MAXIMS_OF_LAW_GATE_NAMES)
        raise argparse.ArgumentTypeError(f"unknown maxim proof {name!r}; known: {known}")
    return name, proof


def normalize_maxim_proofs(
    overrides: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Return maxim proofs with deterministic defaults plus explicit overrides."""
    proofs = dict(DEFAULT_MAXIM_PROOFS)
    if overrides:
        proofs.update(overrides)
    return proofs


def maxims_of_law_report(maxim_proofs: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    """Build hashed proof receipts for the maxims-of-law admissibility layer."""
    report: Dict[str, Dict[str, Any]] = {}
    for name in MAXIMS_OF_LAW_GATE_NAMES:
        proof = str(maxim_proofs.get(name, ""))
        report[name] = {
            "passed": bool(proof.strip()),
            "proof_sha256": sha256_text(proof) if proof.strip() else "",
        }
    return report


def maxims_of_law_hold(inputs: Dict[str, Any]) -> bool:
    """Return true iff every required maxim proof is present."""
    report = maxims_of_law_report(inputs.get("maxim_proofs", {}))
    return all(report[name]["passed"] for name in MAXIMS_OF_LAW_GATE_NAMES)


def bounded_search_values(inputs: Dict[str, Any]) -> tuple[Optional[int], Optional[int]]:
    """Return parsed bounded-search values, or ``None`` for invalid values."""
    try:
        search_steps = int(inputs.get("search_steps", -1))
        max_search_steps = int(inputs.get("max_search_steps", -1))
    except (TypeError, ValueError):
        return None, None
    return search_steps, max_search_steps


def bounded_search(inputs: Dict[str, Any]) -> bool:
    """Return true iff the declared search stayed within deterministic bounds."""
    search_steps, max_search_steps = bounded_search_values(inputs)
    if search_steps is None or max_search_steps is None:
        return False
    return 0 <= search_steps <= max_search_steps


def no_refusal_basis(inputs: Dict[str, Any]) -> bool:
    """Return true when execution is not carrying a constructive refusal basis."""
    return not str(inputs.get("refusal_basis", "")).strip()


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


def path_sensitive_gate_report(inputs: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Build the five path-sensitive admissibility gate receipts."""
    novelty_assertion = str(inputs.get("novelty_assertion", ""))
    acquisition_trace = str(inputs.get("acquisition_trace", ""))
    interface_provenance = str(inputs.get("interface_provenance", ""))
    refusal_basis = str(inputs.get("refusal_basis", ""))
    search_steps, max_search_steps = bounded_search_values(inputs)
    return {
        "novelty_gate": {
            "passed": proof_present(inputs, "novelty_assertion"),
            "proof_sha256": sha256_text(novelty_assertion)
            if novelty_assertion.strip()
            else "",
        },
        "acquisition_trace_gate": {
            "passed": proof_present(inputs, "acquisition_trace"),
            "trace_sha256": sha256_text(acquisition_trace)
            if acquisition_trace.strip()
            else "",
        },
        "efficiency_gate": {
            "passed": bounded_search(inputs),
            "search_steps": search_steps,
            "max_search_steps": max_search_steps,
        },
        "interface_exploit_gate": {
            "passed": proof_present(inputs, "interface_provenance"),
            "provenance_sha256": sha256_text(interface_provenance)
            if interface_provenance.strip()
            else "",
        },
        "refusal_gate": {
            "passed": no_refusal_basis(inputs),
            "refusal_basis_sha256": sha256_text(refusal_basis)
            if refusal_basis.strip()
            else "",
        },
    }


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
            check=lambda _state, _action, inputs: proof_present(
                inputs, "sovereign_intent_proof"
            ),
        ),
        Invariant(
            name="workflow_gate_available",
            version="1.0.0",
            check=lambda _state, _action, inputs: workflow_is_admissible(
                str(inputs.get("workflow_name", ""))
            ),
        ),
        Invariant(
            name="novelty_gate",
            version="1.0.0",
            check=lambda _state, _action, inputs: proof_present(
                inputs, "novelty_assertion"
            ),
        ),
        Invariant(
            name="acquisition_trace_gate",
            version="1.0.0",
            check=lambda _state, _action, inputs: proof_present(
                inputs, "acquisition_trace"
            ),
        ),
        Invariant(
            name="efficiency_gate",
            version="1.0.0",
            check=lambda _state, _action, inputs: bounded_search(inputs),
        ),
        Invariant(
            name="interface_exploit_gate",
            version="1.0.0",
            check=lambda _state, _action, inputs: proof_present(
                inputs, "interface_provenance"
            ),
        ),
        Invariant(
            name="refusal_gate",
            version="1.0.0",
            check=lambda _state, _action, inputs: no_refusal_basis(inputs),
        ),
        Invariant(
            name="maxims_of_law_gate",
            version="1.0.0",
            check=lambda _state, _action, inputs: maxims_of_law_hold(inputs),
        ),
    ]


def emit_receipt(
    *,
    head_sha: str,
    workflow_name: str,
    sovereign_intent_proof: str,
    receipt_path: Path = DEFAULT_RECEIPT,
    novelty_assertion: str = DEFAULT_NOVELTY_ASSERTION,
    acquisition_trace: str = DEFAULT_ACQUISITION_TRACE,
    search_steps: int = DEFAULT_SEARCH_STEPS,
    max_search_steps: int = DEFAULT_MAX_SEARCH_STEPS,
    interface_provenance: str = DEFAULT_INTERFACE_PROVENANCE,
    refusal_basis: str = "",
    maxim_proofs: Optional[Dict[str, str]] = None,
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
        "novelty_assertion": novelty_assertion,
        "acquisition_trace": acquisition_trace,
        "search_steps": search_steps,
        "max_search_steps": max_search_steps,
        "interface_provenance": interface_provenance,
        "refusal_basis": refusal_basis,
        "maxim_proofs": normalize_maxim_proofs(maxim_proofs),
    }
    gate_report = path_sensitive_gate_report(inputs)
    maxim_report = maxims_of_law_report(inputs["maxim_proofs"])

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
            "path_sensitive_gates": gate_report,
            "maxims_of_law": maxim_report,
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
        "path_sensitive_gates": gate_report,
        "maxims_of_law": maxim_report,
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

    gates = payload.get("path_sensitive_gates") or {}
    for gate_name in PATH_SENSITIVE_GATE_NAMES:
        if not gates.get(gate_name, {}).get("passed"):
            failures.append(f"path-sensitive gate failed: {gate_name}")

    maxims = payload.get("maxims_of_law") or {}
    for maxim_name in MAXIMS_OF_LAW_GATE_NAMES:
        if not maxims.get(maxim_name, {}).get("passed"):
            failures.append(f"maxim proof failed: {maxim_name}")

    if failures:
        raise RuntimeError("; ".join(failures))
    return payload


def cmd_emit(args: argparse.Namespace) -> int:
    payload = emit_receipt(
        head_sha=args.head_sha,
        workflow_name=args.workflow_name,
        sovereign_intent_proof=args.sovereign_intent_proof,
        receipt_path=Path(args.receipt_path),
        novelty_assertion=args.novelty_assertion,
        acquisition_trace=args.acquisition_trace,
        search_steps=args.search_steps,
        max_search_steps=args.max_search_steps,
        interface_provenance=args.interface_provenance,
        refusal_basis=args.refusal_basis,
        maxim_proofs=dict(args.maxim_proof or []),
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
        "--novelty-assertion",
        default=DEFAULT_NOVELTY_ASSERTION,
        help="non-empty anti-contamination assertion for the active head",
    )
    emit.add_argument(
        "--acquisition-trace",
        default=DEFAULT_ACQUISITION_TRACE,
        help="non-empty derivation trace for the admitted workflow action",
    )
    emit.add_argument(
        "--search-steps",
        type=int,
        default=DEFAULT_SEARCH_STEPS,
        help="declared bounded-search step count",
    )
    emit.add_argument(
        "--max-search-steps",
        type=int,
        default=DEFAULT_MAX_SEARCH_STEPS,
        help="maximum admissible bounded-search step count",
    )
    emit.add_argument(
        "--interface-provenance",
        default=DEFAULT_INTERFACE_PROVENANCE,
        help="non-empty interface provenance proof for the workflow path",
    )
    emit.add_argument(
        "--refusal-basis",
        default="",
        help="non-empty value records constructive refusal and denies execution",
    )
    emit.add_argument(
        "--maxim-proof",
        action="append",
        default=[],
        metavar="NAME=PROOF",
        type=parse_maxim_proof_item,
        help="override a maxims-of-law proof; may be supplied multiple times",
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
