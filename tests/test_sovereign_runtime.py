import hashlib
import json
import os
import sys
from dataclasses import replace

import jsonschema
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sovereign_runtime import (
    AdmissibilityDecision,
    FileRuntimeReceiptLedger,
    RuntimeSecurityError,
    SovereignRuntime,
)


@pytest.fixture
def signed_decision_factory():
    private_key = Ed25519PrivateKey.generate()
    public_key = (
        private_key.public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
        .hex()
    )

    def build(**changes):
        fields = {
            "authority_pubkey": public_key,
            "authority_snapshot_hash": hashlib.sha256(b"authority").hexdigest(),
            "context_snapshot_hash": hashlib.sha256(b"context").hexdigest(),
            "candidate_hash": hashlib.sha256(b"candidate").hexdigest(),
            "parent_receipt_hash": hashlib.sha256(b"parent").hexdigest(),
            "allowed_action_tokens": ("TOKEN_EXECUTE_QUERY", "TOKEN_UPDATE_STATE"),
            "is_admitted": True,
            "nonce": "5a9f23e41b098c1a",
            "timestamp_utc": "2026-08-03T12:00:00Z",
        }
        fields.update(changes)
        decision = AdmissibilityDecision(**fields)
        signature = private_key.sign(decision.compute_digest()).hex()
        return decision.with_signature(signature)

    return build


def _runtime(tmp_path):
    return SovereignRuntime(FileRuntimeReceiptLedger(tmp_path))


def _assert_durable_refusal(error, tmp_path):
    receipt = error.value.receipt
    assert receipt.status == "REFUSED"
    reopened = FileRuntimeReceiptLedger(tmp_path)
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    assert reopened.get(files[0].stem) == receipt.mapping


def test_happy_path_consumes_closed_set_and_persists_receipt(
    tmp_path, signed_decision_factory
):
    decision = signed_decision_factory()
    result = _runtime(tmp_path).execute(decision, "TOKEN_EXECUTE_QUERY")

    assert result["status"] == "EXECUTED"
    assert result["decision_digest_hex"] == decision.compute_digest_hex()
    assert FileRuntimeReceiptLedger(tmp_path).get(result["receipt_hash"])


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda decision: replace(decision, verifier_signature=None), "signature"),
        (lambda decision: decision.with_signature("0" * 128), "verification"),
        (
            lambda decision: replace(decision, candidate_hash="f" * 64),
            "verification",
        ),
    ],
)
def test_invalid_decisions_fail_closed_with_durable_receipt(
    tmp_path, signed_decision_factory, mutate, reason
):
    decision = mutate(signed_decision_factory())
    with pytest.raises(RuntimeSecurityError) as error:
        _runtime(tmp_path).execute(decision, "TOKEN_EXECUTE_QUERY")

    assert reason in error.value.receipt.refusal_reason.lower()
    _assert_durable_refusal(error, tmp_path)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        (
            {"is_admitted": False, "refusal_reason": "RevokedAuthorityKey"},
            "RevokedAuthorityKey",
        ),
        ({"allowed_action_tokens": ()}, "empty allowed action set"),
    ],
)
def test_authentic_but_inadmissible_decisions_fail_closed(
    tmp_path, signed_decision_factory, changes, reason
):
    decision = signed_decision_factory(**changes)
    with pytest.raises(RuntimeSecurityError) as error:
        _runtime(tmp_path).execute(decision, "TOKEN_EXECUTE_QUERY")

    assert reason in error.value.receipt.refusal_reason
    _assert_durable_refusal(error, tmp_path)


def test_token_outside_closed_set_fails_closed(tmp_path, signed_decision_factory):
    decision = signed_decision_factory()
    with pytest.raises(RuntimeSecurityError) as error:
        _runtime(tmp_path).execute(decision, "TOKEN_WRITE_STATE")

    assert "outside the allowed set" in error.value.receipt.refusal_reason
    _assert_durable_refusal(error, tmp_path)


@pytest.mark.parametrize(
    "target_action_token", [None, 1, ""], ids=["null", "integer", "empty"]
)
def test_malformed_target_token_fails_closed(
    tmp_path, signed_decision_factory, target_action_token
):
    with pytest.raises(RuntimeSecurityError) as error:
        _runtime(tmp_path).execute(
            signed_decision_factory(), target_action_token
        )

    assert error.value.receipt.action_token == ""
    assert "target action token" in error.value.receipt.refusal_reason
    _assert_durable_refusal(error, tmp_path)


def test_replay_fails_closed_after_restart(tmp_path, signed_decision_factory):
    decision = signed_decision_factory()
    _runtime(tmp_path).execute(decision, "TOKEN_EXECUTE_QUERY")

    with pytest.raises(RuntimeSecurityError) as error:
        _runtime(tmp_path).execute(decision, "TOKEN_EXECUTE_QUERY")

    assert "already been consumed" in error.value.receipt.refusal_reason
    assert len(list(tmp_path.glob("*.json"))) == 2


def test_contract_round_trip_and_json_schema(tmp_path, signed_decision_factory):
    decision = signed_decision_factory()
    restored = AdmissibilityDecision.from_json(decision.to_json())
    schema_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "schemas",
        "tas.admissibility-decision.v1.schema.json",
    )
    with open(schema_path, encoding="utf-8") as stream:
        schema = json.load(stream)

    assert restored == decision
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )
    validator.validate(json.loads(decision.to_json()))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("is_admitted", 1),
        ("allowed_action_tokens", "TOKEN_EXECUTE_QUERY"),
        ("allowed_action_tokens", ["TOKEN_EXECUTE_QUERY", ""]),
        ("allowed_action_tokens", ["TOKEN_EXECUTE_QUERY", "TOKEN_EXECUTE_QUERY"]),
    ],
)
def test_from_json_rejects_malformed_admissibility_fields(
    signed_decision_factory, field, value
):
    payload = json.loads(signed_decision_factory().to_json())
    payload[field] = value

    with pytest.raises((TypeError, ValueError)):
        AdmissibilityDecision.from_json(json.dumps(payload))


def test_runtime_refuses_tampered_duplicate_action_tokens(
    tmp_path, signed_decision_factory
):
    decision = signed_decision_factory()
    object.__setattr__(
        decision,
        "allowed_action_tokens",
        ("TOKEN_EXECUTE_QUERY", "TOKEN_EXECUTE_QUERY"),
    )

    with pytest.raises(RuntimeSecurityError) as error:
        _runtime(tmp_path).execute(decision, "TOKEN_EXECUTE_QUERY")

    assert "not unique" in error.value.receipt.refusal_reason
    _assert_durable_refusal(error, tmp_path)
