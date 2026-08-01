import json
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
SHA = "sha256:" + "a" * 64
OTHER_SHA = "sha256:" + "b" * 64


def load(name):
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def validator(name):
    schema = load(name)
    receipt_schema = load("tas.crp.receipt.v1.schema.json")
    registry = Registry().with_resource(
        receipt_schema["$id"], Resource.from_contents(receipt_schema)
    )
    return Draft202012Validator(
        schema,
        registry=registry,
        format_checker=FormatChecker(),
    )


def authority():
    return {
        "evaluator_id": "tas:evaluator:release-board",
        "key_id": "tas:key:2026-07",
        "authorization_snapshot_digest": OTHER_SHA,
        "key_valid_from": "2026-07-01T00:00:00Z",
        "key_valid_until": None,
        "key_status_at_evaluation": "ACTIVE",
        "status_checked_at": "2026-08-01T12:00:00Z",
    }


def verifier_value():
    return {
        "id": "tas-crp-verifier",
        "version": "1.0.0",
        "implementation_digest": OTHER_SHA,
    }


def receipt(gate=1):
    return {
        "schema_id": "tas.crp.receipt.v1",
        "canonicalization": "RFC8785",
        "protocol_id": "tas.crp",
        "protocol_version": "1.0.0",
        "receipt_id": "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
        "gate": gate,
        "result": "PASS",
        "evaluated_at": "2026-08-01T12:00:00Z",
        "scope_digest": SHA,
        "parent_receipt_digest": None if gate == 1 else OTHER_SHA,
        "evidence": [{"name": "gate-evidence", "digest": OTHER_SHA}],
        "verifier": verifier_value(),
        "authority": authority(),
    }


def migration():
    return {
        "schema_id": "tas.crp.migration.v1",
        "canonicalization": "RFC8785",
        "protocol_id": "tas.crp",
        "migration_id": "urn:uuid:123e4567-e89b-42d3-a456-426614174001",
        "source_version": "1.0.0",
        "target_version": "2.0.0",
        "source_head_digest": SHA,
        "target_scope_digest": OTHER_SHA,
        "result": "PASS",
        "evaluated_at": "2026-08-01T12:00:00Z",
        "invariant_attestations": [
            {"invariant_id": "tas.crp.v2:chain", "evidence_digest": SHA, "result": "PASS"}
        ],
        "verifier": verifier_value(),
        "authority": authority(),
    }


def test_completion_receipt_accepts_each_valid_gate_shape():
    check = validator("tas.crp.receipt.v1.schema.json")
    for gate in range(1, 5):
        check.validate(receipt(gate))


def test_completion_receipt_enforces_ancestry_and_closed_shape():
    check = validator("tas.crp.receipt.v1.schema.json")
    bad_parent = receipt(2)
    bad_parent["parent_receipt_digest"] = None
    assert list(check.iter_errors(bad_parent))

    unknown = receipt()
    unknown["readiness_state"] = "IOC_READY"
    assert list(check.iter_errors(unknown))


def test_completion_receipt_rejects_wrong_protocol_or_digest():
    check = validator("tas.crp.receipt.v1.schema.json")
    for field, value in (("protocol_id", "other"), ("scope_digest", "a" * 64)):
        candidate = receipt()
        candidate[field] = value
        assert list(check.iter_errors(candidate))


def test_migration_payload_resolves_shared_definitions():
    validator("tas.crp.migration.v1.schema.json").validate(migration())


def test_migration_payload_requires_attestations_and_rejects_extra_state():
    check = validator("tas.crp.migration.v1.schema.json")
    no_attestations = migration()
    no_attestations["invariant_attestations"] = []
    assert list(check.iter_errors(no_attestations))

    asserted_head = deepcopy(migration())
    asserted_head["current_head"] = SHA
    assert list(check.iter_errors(asserted_head))
