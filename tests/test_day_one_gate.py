# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

import json
from pathlib import Path

import pytest

from scripts.day_one_gate import (
    MAXIMS_OF_LAW_GATE_NAMES,
    PATH_SENSITIVE_GATE_NAMES,
    active_head_sha,
    emit_receipt,
    verify_receipt,
)


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
    assert set(PATH_SENSITIVE_GATE_NAMES).issubset(payload["path_sensitive_gates"])
    assert all(
        payload["path_sensitive_gates"][gate_name]["passed"]
        for gate_name in PATH_SENSITIVE_GATE_NAMES
    )
    assert set(MAXIMS_OF_LAW_GATE_NAMES).issubset(payload["maxims_of_law"])
    assert all(
        payload["maxims_of_law"][maxim_name]["passed"]
        for maxim_name in MAXIMS_OF_LAW_GATE_NAMES
    )
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


@pytest.mark.parametrize(
    ("override", "failed_gate"),
    [
        ({"novelty_assertion": " "}, "novelty_gate"),
        ({"acquisition_trace": " "}, "acquisition_trace_gate"),
        ({"interface_provenance": " "}, "interface_exploit_gate"),
    ],
)
def test_day_one_receipt_fails_closed_without_path_proof(
    tmp_path: Path, override: dict[str, str], failed_gate: str
):
    receipt_path = tmp_path / "receipt.json"

    with pytest.raises(RuntimeError, match=failed_gate):
        emit_receipt(
            head_sha=active_head_sha(),
            workflow_name="blank.yml",
            sovereign_intent_proof="PR #158 merged Day One directive",
            receipt_path=receipt_path,
            **override,
        )

    assert not receipt_path.exists()


def test_day_one_receipt_fails_closed_on_unbounded_search(tmp_path: Path):
    receipt_path = tmp_path / "receipt.json"

    with pytest.raises(RuntimeError, match="efficiency_gate"):
        emit_receipt(
            head_sha=active_head_sha(),
            workflow_name="blank.yml",
            sovereign_intent_proof="PR #158 merged Day One directive",
            search_steps=17,
            max_search_steps=16,
            receipt_path=receipt_path,
        )

    assert not receipt_path.exists()


def test_day_one_receipt_fails_closed_on_refusal_basis(tmp_path: Path):
    receipt_path = tmp_path / "receipt.json"

    with pytest.raises(RuntimeError, match="refusal_gate"):
        emit_receipt(
            head_sha=active_head_sha(),
            workflow_name="blank.yml",
            sovereign_intent_proof="PR #158 merged Day One directive",
            refusal_basis="missing acquisition proof",
            receipt_path=receipt_path,
        )

    assert not receipt_path.exists()



def test_day_one_receipt_fails_closed_without_maxim_proof(tmp_path: Path):
    receipt_path = tmp_path / "receipt.json"

    with pytest.raises(RuntimeError, match="maxims_of_law_gate"):
        emit_receipt(
            head_sha=active_head_sha(),
            workflow_name="blank.yml",
            sovereign_intent_proof="PR #158 merged Day One directive",
            maxim_proofs={"clean_hands": " "},
            receipt_path=receipt_path,
        )

    assert not receipt_path.exists()


def test_day_one_verify_fails_closed_on_missing_maxim_report(tmp_path: Path):
    receipt_path = tmp_path / "receipt.json"
    payload = emit_receipt(
        head_sha=active_head_sha(),
        workflow_name="blank.yml",
        sovereign_intent_proof="PR #158 merged Day One directive",
        receipt_path=receipt_path,
    )
    payload.pop("maxims_of_law")
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(RuntimeError, match="maxim proof failed: clean_hands"):
        verify_receipt(receipt_path=receipt_path)

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
