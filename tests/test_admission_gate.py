import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from admission_gate import (AUTHORIZATION_DOMAIN, AdmissionGatekeeper, AuthoritySnapshot,
                            AuthenticatedLineageVerifier, CANONICALIZATION_VERSION, InMemoryDecisionLedger,
                            LocalSecp256k1Signer, Secp256k1Verifier, canonical_hash,
                            canonical_json, parse_canonical_json)


class Resolver:
    def __init__(self, snapshot): self.snapshot = snapshot
    def resolve(self, *, credential_id, checkpoint_hash):
        return self.snapshot if (credential_id, checkpoint_hash) == (self.snapshot.credential_id, self.snapshot.checkpoint_hash) else None


def _gate():
    authority_key, receipt_key = ec.generate_private_key(ec.SECP256K1()), ec.generate_private_key(ec.SECP256K1())
    authority = LocalSecp256k1Signer(authority_key)
    snapshot = AuthoritySnapshot("credential-1", authority.algorithm, authority.public_key, 7, False,
                                 "scope", "a" * 64, "2030-01-01T00:00:00Z")
    ledger = InMemoryDecisionLedger()
    return AdmissionGatekeeper(gatekeeper_id="gate-1", authority_resolver=Resolver(snapshot),
                               verifier=Secp256k1Verifier(), receipt_signer=LocalSecp256k1Signer(receipt_key), ledger=ledger), authority, ledger


def _request(authority, candidate={"operation": "READ"}):
    body = {"schema_version": 1, "canonicalization_version": CANONICALIZATION_VERSION,
            "domain_separator": "TAS_AUTHORITY_GATE_V1", "credential_id": "credential-1",
            "authority_checkpoint_hash": "a" * 64, "authority_epoch": 7,
            "signature_algorithm": authority.algorithm, "requested_operation": "READ",
            "candidate_hash": canonical_hash(candidate), "parent_receipt_hash": None, "nonce": "nonce-1"}
    return canonical_json(candidate), canonical_json({**body, "signature": base64.b64encode(authority.sign(AUTHORIZATION_DOMAIN + canonical_json(body))).decode()})


def test_admitted_decision_is_real_signature_and_is_recorded_before_return():
    gate, authority, ledger = _gate()
    candidate, envelope = _request(authority)
    result = gate.evaluate(raw_candidate=candidate, raw_envelope=envelope, current_time="2029-01-01T00:00:00Z")
    assert result["resulting_state"] == "ADMITTED" and result["durable_receipt"]
    assert ledger.get_receipt(result["receipt_hash"]) == result["receipt"]
    assert AuthenticatedLineageVerifier(ledger, Secp256k1Verifier()).verify(result["receipt_hash"])


def test_public_key_cannot_forge_authorization_signature():
    gate, authority, _ = _gate()
    candidate, envelope = _request(authority)
    forged = parse_canonical_json(envelope)
    forged["signature"] = base64.b64encode(b"not a signature").decode()
    result = gate.evaluate(raw_candidate=candidate, raw_envelope=canonical_json(forged), current_time="2029-01-01T00:00:00Z")
    assert result["resulting_state"] == "REFUSED" and result["durable_receipt"]


def test_duplicate_key_is_rejected_before_candidate_is_constructed():
    gate, authority, _ = _gate()
    _, envelope = _request(authority)
    result = gate.evaluate(raw_candidate=b'{"operation":"READ","operation":"DELETE"}', raw_envelope=envelope,
                           current_time="2029-01-01T00:00:00Z")
    assert result["resulting_state"] == "REFUSED"


def test_signing_or_append_failure_fails_closed():
    gate, authority, _ = _gate()
    candidate, envelope = _request(authority)
    class BrokenLedger:
        def append_decision(self, *_): raise OSError("offline")
        def get_receipt(self, *_): return None
    gate.ledger = BrokenLedger()
    result = gate.evaluate(raw_candidate=candidate, raw_envelope=envelope, current_time="2029-01-01T00:00:00Z")
    assert result == {"resulting_state": "CUTOFF", "failure_code": "RECEIPT_PRESERVATION_UNAVAILABLE", "durable_receipt": False}


def test_lineage_verifier_rejects_tampered_receipt_content():
    gate, authority, ledger = _gate()
    candidate, envelope = _request(authority)
    result = gate.evaluate(raw_candidate=candidate, raw_envelope=envelope, current_time="2029-01-01T00:00:00Z")
    ledger._records[result["receipt_hash"]]["requested_operation"] = "DELETE"
    assert not AuthenticatedLineageVerifier(ledger, Secp256k1Verifier()).verify(result["receipt_hash"])
