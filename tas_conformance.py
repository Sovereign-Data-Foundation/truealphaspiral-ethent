"""Authenticated TAS v0.8 admission, merge, and replay-safe allocation escrow."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

UINT64_MAX = (1 << 64) - 1
AUTHORIZATION_DOMAIN = b"TAS-CONFORMANCE-AUTHORIZATION-V0.8\x00"
SPARSE_LEAF_DOMAIN = b"\x00"
SPARSE_NODE_DOMAIN = b"\x01"
ALLOCATION_DOMAIN = b"TAS-ALLOCATION-V0.8\x00"
_STATEMENT_FIELDS = {
    "epoch",
    "nonce",
    "cvp",
    "allocations",
    "total",
    "ledger_account",
    "ledger_balance",
}


class TransitionRejected(ValueError):
    """The proposed transition failed an authorization or invariant check."""


class ReplayRejected(TransitionRejected):
    """An authorization nonce was already consumed."""


@dataclass(frozen=True)
class SparseProof:
    key: str
    value: bytes
    siblings: Sequence[str]


@dataclass(frozen=True)
class MergeState:
    permissions: frozenset[str]
    obligations: frozenset[str]


@dataclass(frozen=True)
class Settlement:
    fee: int
    net: int
    valid: bool
    balance_after: int


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _uint64(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= UINT64_MAX:
        raise TransitionRejected(f"{label} is outside UInt64")
    return value


def settle_u64(gross: int, fee_bps: int, balance: int) -> Settlement:
    gross = _uint64(gross, "gross settlement")
    balance = _uint64(balance, "ledger balance")
    if type(fee_bps) is not int or not 0 <= fee_bps <= 10_000:
        raise TransitionRejected("fee basis points must be in [0, 10000]")
    fee = gross * fee_bps // 10_000
    valid = gross <= balance
    return Settlement(
        fee=fee,
        net=gross - fee,
        valid=valid,
        balance_after=balance - gross if valid else 0,
    )


def _normalized_identifiers(values: Any, label: str) -> list[str]:
    if not isinstance(values, list):
        raise TransitionRejected(f"{label} must be a list")
    normalized = []
    for value in values:
        if not isinstance(value, str):
            raise TransitionRejected(f"{label} entries must be strings")
        value = unicodedata.normalize("NFC", value.strip())
        if not value:
            raise TransitionRejected(f"{label} entries cannot be empty")
        normalized.append(value)
    if len(set(normalized)) != len(normalized):
        raise TransitionRejected(f"{label} contains duplicates")
    return sorted(normalized)


def normalize_cvp(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, dict) or set(value) != {
        "permissions",
        "obligations",
        "satisfied_obligations",
    }:
        raise TransitionRejected("CVP fields are invalid")
    return {
        field: _normalized_identifiers(value[field], field)
        for field in ("permissions", "obligations", "satisfied_obligations")
    }


def _normalize_allocations(allocations: Any) -> list[dict[str, Any]]:
    if not isinstance(allocations, list):
        raise TransitionRejected("allocations must be a list")
    normalized = []
    for allocation in allocations:
        if not isinstance(allocation, dict) or set(allocation) != {
            "recipient",
            "amount",
        }:
            raise TransitionRejected("allocation fields are invalid")
        recipient = allocation["recipient"]
        if not isinstance(recipient, str):
            raise TransitionRejected("allocation recipient must be a string")
        recipient = unicodedata.normalize("NFC", recipient.strip())
        if not recipient:
            raise TransitionRejected("allocation recipient cannot be empty")
        normalized.append(
            {
                "recipient": recipient,
                "amount": _uint64(allocation["amount"], "allocation amount"),
            }
        )
    if len({allocation["recipient"] for allocation in normalized}) != len(normalized):
        raise TransitionRejected("allocation recipients must be unique")
    return sorted(normalized, key=lambda allocation: allocation["recipient"])


def _normalize_statement(statement: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(statement, Mapping) or set(statement) != _STATEMENT_FIELDS:
        raise TransitionRejected("authorization statement fields are invalid")
    epoch = statement["epoch"]
    if type(epoch) is not int or epoch < 0:
        raise TransitionRejected("epoch must be a nonnegative integer")
    nonce = statement["nonce"]
    if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
        raise TransitionRejected("nonce must contain 1 to 256 characters")
    ledger_account = statement["ledger_account"]
    if not isinstance(ledger_account, str):
        raise TransitionRejected("ledger account must be a string")
    ledger_account = unicodedata.normalize("NFC", ledger_account.strip())
    if not ledger_account:
        raise TransitionRejected("ledger account cannot be empty")
    cvp = normalize_cvp(statement["cvp"])
    normalized_allocations = _normalize_allocations(statement["allocations"])
    return {
        "epoch": epoch,
        "nonce": nonce,
        "cvp": cvp,
        "allocations": normalized_allocations,
        "total": _uint64(statement["total"], "total"),
        "ledger_account": ledger_account,
        "ledger_balance": _uint64(statement["ledger_balance"], "ledger balance"),
    }


def allocation_digest(allocations: Sequence[Mapping[str, Any]]) -> str:
    return hashlib.sha256(
        ALLOCATION_DOMAIN + canonical_json(list(allocations))
    ).hexdigest()


def sparse_root(proof: SparseProof) -> str:
    if len(proof.key) != 64 or len(proof.siblings) != 256:
        raise TransitionRejected("sparse proof requires a 256-bit key and path")
    try:
        key_bytes = bytes.fromhex(proof.key)
        siblings = [bytes.fromhex(sibling) for sibling in proof.siblings]
    except (TypeError, ValueError) as error:
        raise TransitionRejected("sparse proof hashes must be hexadecimal") from error
    if any(len(sibling) != 32 for sibling in siblings):
        raise TransitionRejected("sparse proof siblings must be 32 bytes")
    current = hashlib.sha256(SPARSE_LEAF_DOMAIN + key_bytes + proof.value).digest()
    key_bits = int.from_bytes(key_bytes, "big")
    for depth, sibling in enumerate(siblings):
        if (key_bits >> depth) & 1:
            current = hashlib.sha256(
                SPARSE_NODE_DOMAIN + sibling + current
            ).digest()
        else:
            current = hashlib.sha256(
                SPARSE_NODE_DOMAIN + current + sibling
            ).digest()
    return current.hex()


class SQLiteEscrow:
    """A durable, transactional nonce ledger bound to canonical allocations."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS escrow (
                    nonce TEXT PRIMARY KEY,
                    allocation_digest TEXT NOT NULL
                )"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS ledger_balances (
                    account TEXT PRIMARY KEY,
                    balance TEXT NOT NULL
                )"""
            )

    def initialize_balance(self, account: str, balance: int) -> None:
        account = unicodedata.normalize("NFC", account.strip())
        if not account:
            raise TransitionRejected("ledger account cannot be empty")
        balance = _uint64(balance, "initial ledger balance")
        with sqlite3.connect(
            self.path, timeout=30, isolation_level=None
        ) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT OR IGNORE INTO ledger_balances (account, balance) "
                    "VALUES (?, ?)",
                    (account, str(balance)),
                )
                row = connection.execute(
                    "SELECT balance FROM ledger_balances WHERE account = ?",
                    (account,),
                ).fetchone()
                if row is None or int(row[0]) != balance:
                    raise TransitionRejected(
                        "ledger account is already initialized differently"
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def get_balance(self, account: str) -> int | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT balance FROM ledger_balances WHERE account = ?",
                (unicodedata.normalize("NFC", account.strip()),),
            ).fetchone()
        return None if row is None else int(row[0])

    def consume(
        self,
        nonce: str,
        account: str,
        expected_balance: int,
        total: int,
        allocations: Sequence[Mapping[str, Any]],
    ) -> str:
        if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
            raise TransitionRejected("nonce must contain 1 to 256 characters")
        account = unicodedata.normalize("NFC", account.strip())
        if not account:
            raise TransitionRejected("ledger account cannot be empty")
        expected_balance = _uint64(expected_balance, "expected ledger balance")
        total = _uint64(total, "settlement total")
        if total > expected_balance:
            raise TransitionRejected("settlement exceeds the ledger balance")
        normalized_allocations = _normalize_allocations(list(allocations))
        allocated = 0
        for allocation in normalized_allocations:
            allocated += allocation["amount"]
            if allocated > UINT64_MAX:
                raise TransitionRejected("allocation sum overflows UInt64")
        if allocated != total:
            raise TransitionRejected("allocations do not conserve the declared total")
        digest = allocation_digest(normalized_allocations)
        with sqlite3.connect(self.path, timeout=30, isolation_level=None) as connection:
            connection.execute("PRAGMA busy_timeout = 30000")
            connection.execute("BEGIN IMMEDIATE")
            try:
                if connection.execute(
                    "SELECT 1 FROM escrow WHERE nonce = ?", (nonce,)
                ).fetchone():
                    raise ReplayRejected("authorization nonce was already consumed")
                row = connection.execute(
                    "SELECT balance FROM ledger_balances WHERE account = ?",
                    (account,),
                ).fetchone()
                if row is None or int(row[0]) != expected_balance:
                    raise TransitionRejected(
                        "ledger balance is uninitialized or stale"
                    )
                connection.execute(
                    "INSERT INTO escrow (nonce, allocation_digest) VALUES (?, ?)",
                    (nonce, digest),
                )
                updated = connection.execute(
                    "UPDATE ledger_balances SET balance = ? "
                    "WHERE account = ? AND balance = ?",
                    (str(expected_balance - total), account, str(expected_balance)),
                )
                if updated.rowcount != 1:
                    raise TransitionRejected("ledger balance changed during escrow")
                connection.commit()
            except sqlite3.IntegrityError as error:
                connection.rollback()
                raise ReplayRejected("authorization nonce was already consumed") from error
            except Exception:
                connection.rollback()
                raise
        return digest


def apply_authorized_transition(
    *,
    statement: Mapping[str, Any],
    signature: bytes,
    proof: SparseProof,
    trusted_epoch_keys: Mapping[int, bytes],
    configured_smt_root: str,
    current_state: MergeState,
    escrow: SQLiteEscrow,
) -> dict[str, Any]:
    """Verify and atomically consume one authorized allocation transition."""
    normalized = _normalize_statement(statement)
    encoded = canonical_json(normalized)
    epoch_key = trusted_epoch_keys.get(normalized["epoch"])
    if epoch_key is None:
        raise TransitionRejected("authorization epoch is not trusted")
    try:
        Ed25519PublicKey.from_public_bytes(epoch_key).verify(
            signature, AUTHORIZATION_DOMAIN + encoded
        )
    except (ValueError, InvalidSignature) as error:
        raise TransitionRejected("Ed25519 authorization failed") from error

    proof_key = hashlib.sha256(b"TAS-CVP-KEY-V0.8\x00" + encoded).hexdigest()
    if proof.key != proof_key or proof.value != encoded:
        raise TransitionRejected("sparse proof is not bound to the CVP statement")
    if sparse_root(proof) != configured_smt_root:
        raise TransitionRejected("sparse proof does not match configured SMT root")

    requested_cvp = normalized["cvp"]
    permissions = current_state.permissions.intersection(
        requested_cvp["permissions"]
    )
    obligations = current_state.obligations.union(requested_cvp["obligations"])
    if not obligations.issubset(requested_cvp["satisfied_obligations"]):
        raise TransitionRejected("required obligations are not satisfied")

    total = normalized["total"]
    balance = normalized["ledger_balance"]
    allocated = 0
    for allocation in normalized["allocations"]:
        allocated += allocation["amount"]
        if allocated > UINT64_MAX:
            raise TransitionRejected("allocation sum overflows UInt64")
    if allocated != total:
        raise TransitionRejected("allocations do not conserve the declared total")
    if total > balance:
        raise TransitionRejected("settlement exceeds the ledger balance")

    digest = escrow.consume(
        normalized["nonce"],
        normalized["ledger_account"],
        balance,
        total,
        normalized["allocations"],
    )
    return {
        "allocation_digest": digest,
        "ledger_balance": balance - total,
        "state": MergeState(frozenset(permissions), frozenset(obligations)),
    }
