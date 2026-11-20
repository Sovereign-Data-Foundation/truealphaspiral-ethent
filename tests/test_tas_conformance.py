import csv
import hashlib
import os
import sqlite3
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tas_conformance import (
    AUTHORIZATION_DOMAIN,
    UINT64_MAX,
    MergeState,
    ReplayRejected,
    SQLiteEscrow,
    Settlement,
    SparseProof,
    TransitionRejected,
    _normalize_statement,
    allocation_digest,
    apply_authorized_transition,
    canonical_json,
    settle_u64,
    sparse_root,
)


ROOT = Path(__file__).resolve().parents[1]


def _authorized_fixture(path, **updates):
    private_key = Ed25519PrivateKey.generate()
    statement = {
        "epoch": 9,
        "nonce": "nonce-1",
        "ledger_account": "tas:default",
        "cvp": {
            "permissions": ["read", "write"],
            "obligations": ["retain"],
            "satisfied_obligations": ["retain"],
        },
        "allocations": [{"recipient": "alice", "amount": 7}],
        "total": 7,
        "ledger_balance": 10,
    }
    statement.update(updates)
    encoded = canonical_json(_normalize_statement(statement))
    key = hashlib.sha256(
        b"TAS-CVP-KEY-V0.8\x00" + encoded
    ).hexdigest()
    proof = SparseProof(key, encoded, ["00" * 32] * 256)
    signature = private_key.sign(AUTHORIZATION_DOMAIN + encoded)
    public_key = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    escrow = SQLiteEscrow(path)
    escrow.initialize_balance(statement["ledger_account"], statement["ledger_balance"])
    return (
        statement,
        signature,
        proof,
        {9: public_key},
        sparse_root(proof),
        MergeState(frozenset({"read", "write"}), frozenset({"retain"})),
        escrow,
    )


def _apply(fixture, **overrides):
    names = (
        "statement",
        "signature",
        "proof",
        "trusted_epoch_keys",
        "configured_smt_root",
        "current_state",
        "escrow",
    )
    arguments = dict(zip(names, fixture))
    arguments.update(overrides)
    return apply_authorized_transition(**arguments)


def test_authorized_transition_verifies_proof_and_merges_lattices(tmp_path):
    fixture = _authorized_fixture(tmp_path / "escrow.sqlite")

    result = _apply(fixture)

    assert result["ledger_balance"] == 3
    assert result["state"] == MergeState(
        frozenset({"read", "write"}), frozenset({"retain"})
    )
    assert fixture[-1].get_balance("tas:default") == 3
    assert len(result["allocation_digest"]) == 64


def test_nonce_is_consumed_even_when_replayed_with_same_allocation(tmp_path):
    fixture = _authorized_fixture(tmp_path / "escrow.sqlite")
    result = _apply(fixture)
    with sqlite3.connect(fixture[-1].path) as connection:
        consumed_digest = connection.execute(
            "SELECT allocation_digest FROM escrow WHERE nonce = ?",
            ("nonce-1",),
        ).fetchone()[0]
    assert consumed_digest == result["allocation_digest"]
    assert consumed_digest == allocation_digest(
        _normalize_statement(fixture[0])["allocations"]
    )
    with pytest.raises(TransitionRejected, match="stale"):
        fixture[-1].consume(
            "nonce-2",
            "tas:default",
            expected_balance=10,
            total=7,
            allocations=[{"recipient": "alice", "amount": 7}],
        )
    assert fixture[-1].get_balance("tas:default") == 3

    with pytest.raises(ReplayRejected):
        _apply(fixture)


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"trusted_epoch_keys": {}}, "epoch"),
        ({"signature": b"invalid"}, "Ed25519"),
        ({"configured_smt_root": "00" * 32}, "sparse proof"),
    ],
)
def test_invalid_authorization_does_not_consume_nonce(tmp_path, changes, message):
    fixture = _authorized_fixture(tmp_path / "escrow.sqlite")
    arguments = dict(
        zip(
            (
                "statement",
                "signature",
                "proof",
                "trusted_epoch_keys",
                "configured_smt_root",
                "current_state",
                "escrow",
            ),
            fixture,
        )
    )
    arguments.update(changes)

    with pytest.raises(TransitionRejected, match=message):
        apply_authorized_transition(**arguments)

    assert _apply(fixture)["ledger_balance"] == 3


def test_obligations_and_uint64_conservation_fail_closed(tmp_path):
    obligations = _authorized_fixture(
        tmp_path / "obligations.sqlite",
        cvp={
            "permissions": ["read"],
            "obligations": ["retain", "audit"],
            "satisfied_obligations": ["retain"],
        },
    )
    with pytest.raises(TransitionRejected, match="obligations"):
        _apply(obligations)

    overflow = _authorized_fixture(
        tmp_path / "overflow.sqlite",
        allocations=[
            {"recipient": "alice", "amount": UINT64_MAX},
            {"recipient": "bob", "amount": 1},
        ],
        total=UINT64_MAX,
        ledger_balance=UINT64_MAX,
    )
    with pytest.raises(TransitionRejected, match="overflows UInt64"):
        _apply(overflow)


def test_authorized_transition_preserves_full_uint64_balance(tmp_path):
    fixture = _authorized_fixture(
        tmp_path / "u64.sqlite",
        allocations=[{"recipient": "alice", "amount": UINT64_MAX}],
        total=UINT64_MAX,
        ledger_balance=UINT64_MAX,
    )

    result = _apply(fixture)

    assert result["ledger_balance"] == 0
    assert fixture[-1].get_balance("tas:default") == 0


def test_python_consumes_all_shared_settlement_vectors():
    with (ROOT / "vectors" / "tas_cross_lang_v0_8.csv").open(
        newline="", encoding="utf-8"
    ) as stream:
        rows = list(csv.DictReader(stream))

    assert len(rows) == 14
    for row in rows:
        settlement = settle_u64(
            int(row["gross"]),
            int(row["fee_bps"]),
            int(row["balance"]),
        )
        assert settlement == Settlement(
            int(row["expected_fee"]),
            int(row["expected_net"]),
            row["expected_valid"] == "true",
            int(row["expected_after"]),
        ), row["name"]
