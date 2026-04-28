"""Artifact guard for capturing per-step execution metadata.

Every execution step is now committed to the process-level
:class:`~wake_chain.WakeChain` so that a tamper-evident provenance record
(a *wake*) is maintained across the entire run.  The wake receipt hash is
stored alongside the artifact digest in ``ledger/artifacts.hash``.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

import json
import hashlib
import time
import subprocess
import pathlib

from wake_chain import get_default_chain

ART_DIR = pathlib.Path("artifacts")
ART_DIR.mkdir(exist_ok=True)
LEDGER_FILE = pathlib.Path("ledger/artifacts.hash")
LEDGER_FILE.parent.mkdir(exist_ok=True)

def run_step(name: str, code: str):
    """Execute code in bash and record an artifact with metadata.

    In addition to writing a JSON artifact file, this function commits a
    :class:`~wake_chain.ProvenanceMark` to the default
    :class:`~wake_chain.WakeChain`, binding the step name, code hash, and
    execution outcome into the immutable provenance record.
    """
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
