"""Run the TAS self-test workflow via a Codex-generated bash script."""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

"""
Set ``OPENAI_API_KEY`` in your environment and execute with ``python
codex_tas_runner.py``. The script requests a minimal bash recipe from
GPT-4o-code, runs it, and prints a JSON summary.

Wake-based authentication (§5) is enforced via the UVK: the Codex script
execution is only admitted if the agent presents a valid capability and all
declared invariants hold.  Every admitted action is committed to the wake
chain and its receipt is recorded in ``ledger/artifacts.hash``.
"""
import importlib
import importlib.util
import os
import subprocess
import json
import hashlib
import time
from artifact_guard import run_step
from wake_chain import reset_default_chain, get_default_chain
from capability import CapabilityTable, Right
from uvk import UVK, Invariant

def _require_api_key() -> str:
    """Return the OpenAI API key or raise an informative error."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "OPENAI_API_KEY is required to run the self-test"
        )
    return api_key

SYSTEM = """You are a reliable DevOps assistant.
Produce a POSIX-compliant bash script that:
1. Clones https://github.com/truealphaspiral/tas_gpt.git if not present.
2. Creates a Python venv  (.venv)  and installs requirements.
3. Copies examples/config.safe_mode.yaml to config.yaml.
4. Creates ledger/  directory if missing.
5. Runs:  python tas_agent.py --task "self-test"
6. Captures the console output to audit.log.
7. Computes SHA-256 of audit.log and writes it to ledger/self_test.hash
"""


def _load_openai():
    """Return the ``openai`` module or raise an informative error."""
    if importlib.util.find_spec("openai") is None:
        raise ModuleNotFoundError(
            "The 'openai' package is required. Install it with "
            "`pip install openai` before running codex_tas_runner.py."
        )
    return importlib.import_module("openai")

def get_codex_script(openai_client):
    resp = openai_client.ChatCompletion.create(
        model="gpt-4o-code",  # or "gpt-4o"
        messages=[{"role":"system","content":SYSTEM}]
    )
    return resp.choices[0].message.content

def run_bash(script: str) -> subprocess.CompletedProcess:
    """Write the script to a file, run it via ``run_step`` and return the result.

    Admission control is enforced by the UVK before execution: the script
    is only run if the ``execute_codex_script`` capability is valid and all
    declared invariants hold.  If admission is denied the function raises
    :class:`PermissionError`.
    """
    # Build UVK with capability and a basic non-empty-script invariant
    # Each script execution starts a fresh wake chain (new session/trajectory).
    # reset_default_chain() is intentional here so that main() can later read
    # the session chain via get_default_chain().
    wake = reset_default_chain()
    cap_table = CapabilityTable()
    execute_cap = cap_table.retype("execute_codex_script", Right.EXECUTE | Right.MINT)

    non_empty_inv = Invariant(
        name="script_non_empty",
        version="1.0.0",
        check=lambda _state, action, _inputs: bool(action and action.strip()),
    )
    uvk = UVK(capability_table=cap_table, wake_chain=wake, invariants=[non_empty_inv])

    result = uvk.admit(
        capability=execute_cap,
        required_right=Right.EXECUTE,
        action=script,
        inputs={"source": "codex"},
    )
    if not result.admitted:
        raise PermissionError(
            f"UVK denied execution: {result.status.name} "
            f"(failed_invariants={result.failed_invariants}, "
            f"cap_error={result.cap_error})"
        )

    with open("run.sh", "w", encoding="utf-8") as f:
        f.write(script)
    os.chmod("run.sh", 0o755)
    meta = run_step("codex_script", f"bash run.sh")
    proc = subprocess.CompletedProcess(
        args=["bash", "run.sh"],
        returncode=meta.get("returncode", 1),
        stdout=meta.get("stdout", ""),
        stderr=meta.get("stderr", ""),
    )
    return proc


def main() -> None:
    openai_client = _load_openai()
    openai_client.api_key = _require_api_key()

    bash_script = get_codex_script(openai_client)
    result = run_bash(bash_script)

    # compute SHA-256 of audit.log after execution
    audit_log = "audit.log"
    ledger = os.path.join("ledger", "self_test.hash")
    hash_val = ""
    if os.path.exists(audit_log):
        with open(audit_log, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        os.makedirs("ledger", exist_ok=True)
        with open(ledger, "w") as f:
            f.write(digest)
        hash_val = digest
    elif os.path.exists(ledger):
        with open(ledger, "r") as f:
            hash_val = f.read().strip()

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "returncode": result.returncode,
        # include the last 10 lines of stdout/stderr for quick diagnostics
        "stdout_tail": result.stdout.splitlines()[-10:],
        "stderr_tail": result.stderr.splitlines()[-10:],
        "audit_hash": hash_val,
        "wake_chain": {
            "session_id": get_default_chain().session_id,
            "receipt_count": len(get_default_chain()),
            "wake_head": get_default_chain().head.hex(),
            "chain_valid": get_default_chain().verify(),
        },
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
