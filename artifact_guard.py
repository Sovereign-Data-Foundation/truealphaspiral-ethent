"""Artifact guard for capturing per-step execution metadata.

Every execution step is now committed to the process-level
:class:`~wake_chain.WakeChain` so that a tamper-evident provenance record
(a *wake*) is maintained across the entire run.  The wake receipt hash is
stored alongside the artifact digest in ``ledger/artifacts.hash``.

Before each step executes, :func:`logos_gate` performs a Logos pre-flight
check via :class:`~tas_logos_gatekeeper.LogosValidationLoop`, enforcing
lineage continuity and minimum payload-density constraints.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

import json
import hashlib
import time
import subprocess
import pathlib
from typing import Any, Optional

from wake_chain import get_default_chain
from tas_logos_gatekeeper import LogosValidationLoop, SovereignStructuralViolation

ART_DIR = pathlib.Path("artifacts")
ART_DIR.mkdir(exist_ok=True)
LEDGER_FILE = pathlib.Path("ledger/artifacts.hash")
LEDGER_FILE.parent.mkdir(exist_ok=True)


def logos_gate(
    name: str,
    payload_vector: Any,
    uvk: Optional[Any] = None,
    nonce: int = 0,
) -> None:
    """Run the Logos pre-flight gate before executing a step.

    Instantiates a :class:`~tas_logos_gatekeeper.LogosValidationLoop` bound to
    the current wake-chain head and evaluates the payload against the
    biconditional gate (lineage continuity + invariant alignment + density
    floor).  Raises :class:`~tas_logos_gatekeeper.SovereignStructuralViolation`
    if the payload fails.

    Parameters
    ----------
    name:
        Human-readable step name (used in the exception message on failure).
    payload_vector:
        The JSON-serialisable payload to score for density.
    uvk:
        Optional :class:`~uvk.UVK` instance.  When supplied, its
        ``check_all_invariants()`` method is used as the invariant check;
        otherwise the invariant gate always passes (structural-only mode).
    nonce:
        Nonce passed through to the sentient-lock receipt on failure.
    """
    chain = get_default_chain()
    current_state_hash: bytes = chain.head

    manifest = {
        "lineage_parent_hash": current_state_hash.hex(),
        "payload_vector": payload_vector,
    }

    if uvk is not None:
        invariant_check = lambda: uvk.check_all_invariants()
    else:
        invariant_check = lambda: True

    loop = LogosValidationLoop(invariant_check=invariant_check)
    if not loop.evaluate_logos_bounds(current_state_hash, manifest, nonce=nonce):
        raise SovereignStructuralViolation(
            f"Logos gate rejected step '{name}': payload failed pre-flight invariants."
        )


def run_step(name: str, code: str):
    """Execute code in bash and record an artifact with metadata.

    Before execution, this function calls :func:`logos_gate` to enforce the
    Logos pre-flight invariants (lineage continuity + payload density floor).
    If the gate rejects the payload, :class:`~tas_logos_gatekeeper.SovereignStructuralViolation`
    is raised and the step is not executed.

    In addition to writing a JSON artifact file, this function commits a
    :class:`~wake_chain.ProvenanceMark` to the default
    :class:`~wake_chain.WakeChain`, binding the step name, code hash, and
    execution outcome into the immutable provenance record.
    """
    logos_gate(name, {"step": name, "code": code})
    uid = f"{int(time.time()*1000)}-{hashlib.sha256(code.encode()).hexdigest()[:8]}"
    meta = {
        "uid": uid,
        "step": name,
        "code": code,
        "t_start": time.time(),
    }
    try:
        result = subprocess.run([
            "bash",
            "-c",
            code,
        ], capture_output=True, text=True)
        meta.update(
            {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
        )
    finally:
        meta["t_end"] = time.time()
        art_path = ART_DIR / f"artifact-{uid}.json"
        art_path.write_text(json.dumps(meta, indent=2))
        digest = hashlib.sha256(art_path.read_bytes()).hexdigest()

        # Commit a wake receipt for this step and record its hash
        wake = get_default_chain()
        receipt = wake.commit(
            event={"step": name, "uid": uid, "code_hash": hashlib.sha256(code.encode()).hexdigest()},
            info={
                "artifact": art_path.name,
                "artifact_digest": digest,
                "returncode": meta.get("returncode"),
            },
        )
        wake_hash = receipt.receipt_hash().hex()

        with LEDGER_FILE.open("a") as lf:
            lf.write(f"{digest}  {art_path.name}  wake={wake_hash}\n")
    return meta
