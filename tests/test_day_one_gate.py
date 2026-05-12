# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from pathlib import Path

import pytest

from scripts.day_one_gate import emit_receipt, verify_receipt, active_head_sha


def test_day_one_receipt_emits_before_gate(tmp_path: Path):
    receipt_path = tmp_path / "receipt.json"
    head_sha = active_head_sha()

    payload = emit_receipt(
        head_sha=head_sha,
        workflow_name="blank.yml",
        sovereign_intent_proof="PR #158 merged Day One directive",
        receipt_path=receipt_path,
    )

    assert payload["admitted"] is True
    assert payload["receipt_present"] is True
    assert payload["workflow_name"] == "blank.yml"
    assert payload["requested_head_sha"] == head_sha
    assert payload["sovereign_intent_proof_sha256"]
    assert receipt_path.exists()


def test_day_one_receipt_fails_closed_without_intent(tmp_path: Path):
    receipt_path = tmp_path / "receipt.json"

    with pytest.raises(RuntimeError, match="sovereign_intent_proof_present"):
        emit_receipt(
            head_sha=active_head_sha(),
            workflow_name="blank.yml",
            sovereign_intent_proof=" ",
            receipt_path=receipt_path,
        )

    assert not receipt_path.exists()


def test_day_one_verify_fails_closed_on_missing_receipt(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="missing Day One receipt"):
        verify_receipt(receipt_path=tmp_path / "missing.json")


def test_day_one_verify_fails_closed_on_head_mismatch(tmp_path: Path):
    receipt_path = tmp_path / "receipt.json"
    emit_receipt(
        head_sha=active_head_sha(),
        workflow_name="blank.yml",
        sovereign_intent_proof="PR #158 merged Day One directive",
        receipt_path=receipt_path,
    )

    with pytest.raises(RuntimeError, match="receipt head SHA mismatch"):
        verify_receipt(
            receipt_path=receipt_path,
            head_sha="0" * 40,
            workflow_name="blank.yml",
        )
