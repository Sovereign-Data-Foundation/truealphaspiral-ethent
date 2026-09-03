import hashlib
import os
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from context_snapshot import canonical_json
from protected_effects import (
    CommitIndeterminate,
    EffectProof,
    FileProtectedStateStore,
    ProtectedEffectRuntime,
    RuntimeLatchedError,
)

PARENT = hashlib.sha256(b"parent").hexdigest()
NEXT = hashlib.sha256(b"next").hexdigest()
AUTHORITY = hashlib.sha256(b"authority").hexdigest()


@pytest.fixture
def system(tmp_path):
    store = FileProtectedStateStore(tmp_path, Ed25519PrivateKey.generate())
    return store, ProtectedEffectRuntime(
        store, lambda proof: proof.provider_proof.get("valid") is True
    )


def _arguments():
    return {"amount": 25, "currency": "USD"}


def _identity(runtime):
    return runtime.execution_identity(
        domain="payments",
        tool="bank",
        operation="transfer",
        arguments=_arguments(),
        expected_parent=PARENT,
        execution_nonce="nonce-0000000001",
        authority_digest=AUTHORITY,
    )


def _proof(runtime, disposition="COMMIT_PROVEN", root=NEXT, valid=True):
    effect_digest, _ = _identity(runtime)
    return EffectProof(
        disposition=disposition,
        parent_root=PARENT,
        resulting_root=root,
        execution_nonce="nonce-0000000001",
        effect_digest=effect_digest,
        provider_proof={"valid": valid},
    )


def _execute(runtime, adapter):
    return runtime.execute(
        domain="payments",
        initial_root=PARENT,
        tool="bank",
        operation="transfer",
        arguments=_arguments(),
        execution_nonce="nonce-0000000001",
        authority_digest=AUTHORITY,
        adapter=adapter,
    )


def test_indeterminate_effect_cannot_be_retried(system):
    store, runtime = system
    executions = 0

    def uncertain_adapter():
        nonlocal executions
        executions += 1
        raise CommitIndeterminate({"acknowledgement": "lost"})

    with pytest.raises(RuntimeLatchedError):
        _execute(runtime, uncertain_adapter)
    with pytest.raises(RuntimeLatchedError):
        _execute(runtime, uncertain_adapter)

    document = store.read("payments")
    assert executions == 1
    assert document["latch"]["status"] == "LATCHED"
    assert [record["event_type"] for record in document["witnesses"]] == [
        "ATTEMPT_PREPARED",
        "INDETERMINATE_LATCHED",
    ]


def test_orphaned_prepare_latches_after_process_restart(system):
    store, runtime = system
    executions = 0

    def process_dies_after_dispatch():
        nonlocal executions
        executions += 1
        raise SystemExit

    with pytest.raises(SystemExit):
        _execute(runtime, process_dies_after_dispatch)
    assert store.read("payments")["prepared"] is not None

    restarted = ProtectedEffectRuntime(store, runtime.verify_proof)
    with pytest.raises(RuntimeLatchedError):
        _execute(restarted, process_dies_after_dispatch)

    assert executions == 1
    assert store.read("payments")["latch"] is not None


def test_commit_proof_allows_idempotent_unchanged_root(system):
    store, runtime = system
    proof = _proof(runtime, root=PARENT)

    assert _execute(runtime, lambda: proof) == proof
    assert store.read("payments")["root"] == PARENT
    assert store.read("payments")["prepared"] is None


def test_unknown_reconciliation_keeps_latch_and_commit_closes_once(system):
    store, runtime = system
    with pytest.raises(RuntimeLatchedError):
        _execute(runtime, lambda: (_ for _ in ()).throw(CommitIndeterminate()))

    assert (
        runtime.reconcile("payments", _proof(runtime, valid=False))
        == "LATCH_REMAINS_CLOSED"
    )
    assert store.read("payments")["latch"] is not None
    assert runtime.reconcile("payments", _proof(runtime)) == "RECOVERED_TO_COMMIT"
    assert store.read("payments")["root"] == NEXT
    assert store.read("payments")["latch"] is None
    assert runtime.reconcile("payments", _proof(runtime)) == "NO_ACTIVE_LATCH"


def test_noncommit_proof_preserves_parent(system):
    store, runtime = system
    with pytest.raises(RuntimeLatchedError):
        _execute(runtime, lambda: (_ for _ in ()).throw(CommitIndeterminate()))

    proof = _proof(runtime, disposition="NON_COMMIT_PROVEN", root=PARENT)
    assert runtime.reconcile("payments", proof) == "RECOVERED_TO_NONCOMMIT"
    document = store.read("payments")
    assert document["root"] == PARENT
    assert document["latch"] is None


def test_effect_identity_binds_tool_parent_authority_and_arguments(system):
    _, runtime = system
    baseline, attempt = _identity(runtime)
    changed, changed_attempt = runtime.execution_identity(
        domain="payments",
        tool="different-bank",
        operation="transfer",
        arguments=_arguments(),
        expected_parent=PARENT,
        execution_nonce="nonce-0000000001",
        authority_digest=AUTHORITY,
    )
    assert baseline != changed
    assert attempt != changed_attempt
    assert _identity(runtime) == (baseline, attempt)


def test_witnesses_are_hash_chained_and_signed(system):
    store, runtime = system
    with pytest.raises(RuntimeLatchedError):
        _execute(runtime, lambda: (_ for _ in ()).throw(CommitIndeterminate()))

    witnesses = store.read("payments")["witnesses"]
    assert witnesses[1]["parent_witness_hash"] == witnesses[0]["record_hash"]
    for record in witnesses:
        body = {
            key: value
            for key, value in record.items()
            if key not in {"evidence", "record_hash", "signature", "signer_key_id"}
        }
        expected = hashlib.sha256(
            b"TAS\x00WITNESS\x00V1\x00"
            + bytes.fromhex(record["parent_witness_hash"])
            + canonical_json(body)
        ).hexdigest()
        assert record["record_hash"] == expected
        store.signer.public_key().verify(
            bytes.fromhex(record["signature"]), bytes.fromhex(expected)
        )
