#!/usr/bin/env python3
"""Run the shared settlement and optimistic escrow vectors."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from tas_conformance import (
    SQLiteEscrow,
    TransitionRejected,
    canonical_json,
    settle_u64,
)

ROOT = Path(__file__).resolve().parent
SETTLEMENT_VECTORS = ROOT / "vectors" / "tas_cross_lang_v0_8.csv"
LEDGER_VECTORS = ROOT / "vectors" / "tas_vectors_v0_7_0.json"
_LEAN_LEDGER_FIELDS = (
    "name",
    "account_id",
    "pre_balance",
    "pre_state_version",
    "token_state_version",
    "ledger_balance",
    "total_debit",
    "status",
    "expected_balance",
    "expected_state_version",
)


def _check_settlement_vectors() -> int:
    with SETTLEMENT_VECTORS.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != 14:
        raise AssertionError(f"expected 14 arithmetic vectors, found {len(rows)}")
    for row in rows:
        result = settle_u64(
            int(row["gross"]),
            int(row["fee_bps"]),
            int(row["balance"]),
        )
        expected = (
            int(row["expected_fee"]),
            int(row["expected_net"]),
            row["expected_valid"] == "true",
            int(row["expected_after"]),
        )
        if (
            result.fee,
            result.net,
            result.valid,
            result.balance_after,
        ) != expected:
            raise AssertionError(f"settlement vector failed: {row['name']}")
    return len(rows)


def _check_ledger_vectors(lean_csv: Path | None) -> int:
    vectors: dict[str, Any] = json.loads(LEDGER_VECTORS.read_text(encoding="utf-8"))
    if vectors.get("version") != "tas_vectors_v0_7_0":
        raise AssertionError("unexpected ledger vector version")
    rows = []
    count = 0
    with tempfile.TemporaryDirectory() as temporary:
        for case in vectors["cases"]:
            initial = case["initial"]
            escrow = SQLiteEscrow(Path(temporary) / f"{case['name']}.sqlite")
            escrow.initialize_balance(
                initial["account_id"],
                initial["authoritative_balance"],
                initial["state_version"],
            )
            for index, token in enumerate(case["transitions"]):
                before = escrow.get_account_state(initial["account_id"])
                if before is None:
                    raise AssertionError("escrow account disappeared")
                statement = {
                    "case": case["name"],
                    "index": index,
                    **token,
                }
                try:
                    escrow.consume(
                        token["nonce"],
                        initial["account_id"],
                        token["expected_state_version"],
                        token["ledger_balance"],
                        token["total_debit"],
                        token["allocations"],
                        hashlib.sha256(canonical_json(statement)).hexdigest(),
                    )
                    status = "COMMITTED"
                    reason = None
                except TransitionRejected as error:
                    status = "REFUSED"
                    reason = (
                        "stale_state_version"
                        if "stale state version" in str(error)
                        else "refused"
                    )
                after = escrow.get_account_state(initial["account_id"])
                if after is None:
                    raise AssertionError("escrow account disappeared")
                with sqlite3.connect(escrow.path) as connection:
                    consumed = connection.execute(
                        "SELECT 1 FROM escrow WHERE nonce = ?",
                        (token["nonce"],),
                    ).fetchone() is not None
                actual = {
                    "status": status,
                    "balance": after[0],
                    "state_version": after[1],
                    "delta_balance": after[0] - before[0],
                    "delta_state_version": after[1] - before[1],
                    "nonce_consumed": consumed,
                }
                expected = {
                    "status": token["expected_status"],
                    "balance": token["expected_balance"],
                    "state_version": token["expected_state_version_after"],
                    "delta_balance": token["expected_delta_balance"],
                    "delta_state_version": token["expected_delta_state_version"],
                    "nonce_consumed": token["expected_nonce_consumed"],
                }
                if actual != expected:
                    raise AssertionError(
                        f"ledger vector failed ({case['name']}): "
                        f"expected {expected}, got {actual}"
                    )
                if reason != token.get("expected_reason"):
                    if token.get("expected_reason") is not None or reason is not None:
                        raise AssertionError(
                            f"ledger refusal reason mismatch ({case['name']})"
                        )
                rows.append(
                    {
                        "name": f"{case['name']}_{index + 1}",
                        "account_id": initial["account_id"],
                        "pre_balance": before[0],
                        "pre_state_version": before[1],
                        "token_state_version": token["expected_state_version"],
                        "ledger_balance": token["ledger_balance"],
                        "total_debit": token["total_debit"],
                        "status": status,
                        "expected_balance": after[0],
                        "expected_state_version": after[1],
                    }
                )
                count += 1
    if lean_csv is not None:
        lean_csv.parent.mkdir(parents=True, exist_ok=True)
        with lean_csv.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=_LEAN_LEDGER_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    return count


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lean-ledger-csv", type=Path)
    args = parser.parse_args()
    arithmetic_count = _check_settlement_vectors()
    ledger_count = _check_ledger_vectors(args.lean_ledger_csv)
    print(
        f"{arithmetic_count} settlement vectors and "
        f"{ledger_count} optimistic escrow vectors passed"
    )


if __name__ == "__main__":
    main()
