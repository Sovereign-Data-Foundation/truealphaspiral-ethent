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
    SQLITE_INT_MAX,
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
        "expected_state_version": 0,
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
    escrow.initialize_balance(
        statement["ledger_account"],
        statement["ledger_balance"],
        statement["expected_state_version"],
    )
    return (
        statement,
        signature,
        proof,
        {9: public_key},
        sparse_root(proof),
        MergeState(frozenset({"read", "write"}), frozenset({"retain"})),
        escrow,
        private_key,
    )


def _resign_fixture(fixture, **updates):
    statement = dict(fixture[0])
    statement.update(updates)
    encoded = canonical_json(_normalize_statement(statement))
    proof = SparseProof(
        hashlib.sha256(b"TAS-CVP-KEY-V0.8\x00" + encoded).hexdigest(),
        encoded,
        ["00" * 32] * 256,
    )
    signature = fixture[7].sign(AUTHORIZATION_DOMAIN + encoded)
    return (
        statement,
        signature,
        proof,
        fixture[3],
        sparse_root(proof),
        fixture[5],
        fixture[6],
        fixture[7],
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
    assert result["state_version"] == 1
    assert result["state"] == MergeState(
        frozenset({"read", "write"}), frozenset({"retain"})
    )
    assert fixture[6].get_account_state("tas:default") == (3, 1)
    assert len(result["allocation_digest"]) == 64


def test_nonce_is_consumed_even_when_replayed_with_same_allocation(tmp_path):
    fixture = _authorized_fixture(tmp_path / "escrow.sqlite")
    result = _apply(fixture)
    with sqlite3.connect(fixture[6].path) as connection:
        consumed_digest = connection.execute(
            "SELECT allocation_digest FROM escrow WHERE nonce = ?",
            ("nonce-1",),
        ).fetchone()[0]
    assert consumed_digest == result["allocation_digest"]
    assert consumed_digest == allocation_digest(
        _normalize_statement(fixture[0])["allocations"]
    )
    with pytest.raises(TransitionRejected, match="stale"):
        fixture[6].consume(
            "nonce-2",
            "tas:default",
            expected_state_version=0,
            expected_balance=10,
            total=7,
            allocations=[{"recipient": "alice", "amount": 7}],
            authorization_digest="a" * 64,
        )
    with pytest.raises(TransitionRejected, match="INTEGER range"):
        fixture[6].consume(
            "nonce-3",
            "tas:default",
            expected_state_version=1,
            expected_balance=3,
            total=-1,
            allocations=[{"recipient": "alice", "amount": 0}],
            authorization_digest="a" * 64,
        )
    with pytest.raises(TransitionRejected, match="exceeds"):
        fixture[6].consume(
            "nonce-4",
            "tas:default",
            expected_state_version=1,
            expected_balance=3,
            total=4,
            allocations=[{"recipient": "alice", "amount": 4}],
            authorization_digest="a" * 64,
        )
    assert fixture[6].get_account_state("tas:default") == (3, 1)

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


def test_distinct_nonce_cannot_replay_stale_signed_balance_or_version(tmp_path):
    first = _authorized_fixture(tmp_path / "escrow.sqlite")
    second = _resign_fixture(first, nonce="nonce-2")

    committed = _apply(first)
    assert committed["ledger_balance"] == 3
    assert committed["state_version"] == 1

    with pytest.raises(TransitionRejected, match="stale state version"):
        _apply(second)

    assert first[6].get_account_state("tas:default") == (3, 1)
    with sqlite3.connect(first[6].path) as connection:
        assert connection.execute(
            "SELECT 1 FROM escrow WHERE nonce = ?", ("nonce-2",)
        ).fetchone() is None
        row = connection.execute(
            """SELECT expected_state_version, debited_amount, post_balance,
                authorization_digest
            FROM escrow WHERE nonce = ?""",
            ("nonce-1",),
        ).fetchone()
    assert row == (
        0,
        7,
        3,
        hashlib.sha256(AUTHORIZATION_DOMAIN + canonical_json(_normalize_statement(first[0]))).hexdigest(),
    )


def test_signed_balance_must_match_authoritative_state(tmp_path):
    fixture = _authorized_fixture(tmp_path / "escrow.sqlite")
    stale_balance = _resign_fixture(fixture, nonce="nonce-2", ledger_balance=9)

    with pytest.raises(TransitionRejected, match="stale ledger balance"):
        _apply(stale_balance)

    assert fixture[6].get_account_state("tas:default") == (10, 0)
    with sqlite3.connect(fixture[6].path) as connection:
        assert connection.execute(
            "SELECT 1 FROM escrow WHERE nonce = ?", ("nonce-2",)
        ).fetchone() is None


def test_old_nonce_and_balance_tables_migrate_without_replay_window(tmp_path):
    path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE escrow (nonce TEXT PRIMARY KEY, allocation_digest TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO escrow VALUES (?, ?)", ("already-used", "f" * 64)
        )
        connection.execute(
            "CREATE TABLE ledger_balances (account TEXT PRIMARY KEY, balance TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO ledger_balances VALUES (?, ?)", ("tas:default", "4")
        )

    escrow = SQLiteEscrow(path)

    assert escrow.get_account_state("tas:default") == (4, 0)
    with pytest.raises(ReplayRejected):
        escrow.consume(
            "already-used",
            "tas:default",
            expected_state_version=0,
            expected_balance=4,
            total=0,
            allocations=[],
            authorization_digest="a" * 64,
        )


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
        ledger_balance=SQLITE_INT_MAX,
    )
    with pytest.raises(TransitionRejected, match="overflows UInt64"):
        _apply(overflow)


def test_authorized_transition_preserves_sqlite_integer_balance(tmp_path):
    fixture = _authorized_fixture(
        tmp_path / "u64.sqlite",
        allocations=[{"recipient": "alice", "amount": SQLITE_INT_MAX}],
        total=SQLITE_INT_MAX,
        ledger_balance=SQLITE_INT_MAX,
    )

    result = _apply(fixture)

    assert result["ledger_balance"] == 0
    assert fixture[6].get_account_state("tas:default") == (0, 1)


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
