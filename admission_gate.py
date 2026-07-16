"""Authenticated, fail-closed admission decisions.

This module deliberately separates parsing, authority resolution, signature
verification, evidence recording, and later state transitions.  It is an
adapter boundary: private keys are only available to ``ReceiptSigner`` and are
never reconstructed from public authority material.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)


AUTHORIZATION_DOMAIN = b"TAS-AUTHORITY-GATE-V1\x00"
RECEIPT_DOMAIN = b"TAS-ADMISSION-RECEIPT-V1\x00"
CANONICALIZATION_VERSION = "TAS-CJSON-1"
RULE_SET_VERSION = "TAS-PI-GATE-1"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class CanonicalJSONError(ValueError):
    """Raised when input is not part of the constrained TAS-CJSON-1 subset."""


def _reject_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def parse_canonical_json(raw: bytes, *, max_bytes: int = 65536, max_depth: int = 32,
                         max_nodes: int = 4096) -> Any:
    """Decode untrusted UTF-8 JSON after rejecting ambiguous/non-portable forms."""
    if not isinstance(raw, bytes) or len(raw) > max_bytes:
        raise CanonicalJSONError("JSON input exceeds byte limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates,
                           parse_constant=lambda value: (_ for _ in ()).throw(
                               CanonicalJSONError(f"invalid JSON constant: {value}")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanonicalJSONError("invalid UTF-8 JSON") from error

    nodes = 0
    def validate(item: Any, depth: int = 0) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise CanonicalJSONError("JSON structural limit exceeded")
        if isinstance(item, float):
            if not math.isfinite(item) or item == 0.0 or item != int(item):
                raise CanonicalJSONError("TAS-CJSON-1 does not permit floating point values")
        elif isinstance(item, int) and not -(2**53 - 1) <= item <= 2**53 - 1:
            raise CanonicalJSONError("integer outside TAS-CJSON-1 range")
        elif isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise CanonicalJSONError("Unicode surrogate not permitted")
        elif isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise CanonicalJSONError("JSON object key is not a string")
                validate(key, depth + 1)
                validate(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                validate(child, depth + 1)
    validate(value)
    return value


def canonical_json(value: Any) -> bytes:
    """Serialize validated TAS-CJSON-1 data as deterministic UTF-8 bytes."""
    # Round trip through the validator to apply the same limits/types to local data.
    provisional = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
                             allow_nan=False).encode("utf-8")
    parse_canonical_json(provisional)
    return provisional


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class AuthoritySnapshot:
    credential_id: str
    algorithm: str
    public_key: bytes
    authority_epoch: int
    revoked: bool
    scope_policy_hash: str
    checkpoint_hash: str
    valid_until: str


class AuthorityResolver(Protocol):
    def resolve(self, *, credential_id: str, checkpoint_hash: str) -> AuthoritySnapshot | None: ...


class SignatureVerifier(Protocol):
    def verify_signature(self, *, algorithm: str, public_key: bytes, message: bytes,
                         signature: bytes) -> bool: ...


class ReceiptSigner(Protocol):
    @property
    def algorithm(self) -> str: ...
    @property
    def public_key(self) -> bytes: ...
    def sign(self, message: bytes) -> bytes: ...


class DecisionLedger(Protocol):
    def append_decision(self, receipt_hash: str, receipt: Mapping[str, Any]) -> None: ...
    def get_receipt(self, receipt_hash: str) -> Mapping[str, Any] | None: ...


class Secp256k1Verifier:
    """DER ECDSA/SHA-256 verifier for compressed SEC1 public keys and low-S signatures."""
    algorithm = "ECDSA-secp256k1-SHA256-DER-lowS"

    def verify_signature(self, *, algorithm: str, public_key: bytes, message: bytes,
                         signature: bytes) -> bool:
        if algorithm != self.algorithm or len(public_key) != 33:
            return False
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key)
            _r, s = decode_dss_signature(signature)
            if not 0 < s <= _SECP256K1_ORDER // 2:
                return False
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except (ValueError, InvalidSignature):
            return False


class LocalSecp256k1Signer:
    """Private-key-backed signer suitable for a KMS/HSM adapter replacement."""
    algorithm = Secp256k1Verifier.algorithm
    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        if not isinstance(private_key.curve, ec.SECP256K1):
            raise ValueError("receipt signer requires a secp256k1 private key")
        self._private_key = private_key
    @property
    def public_key(self) -> bytes:
        return self._private_key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    def sign(self, message: bytes) -> bytes:
        r, s = decode_dss_signature(self._private_key.sign(message, ec.ECDSA(hashes.SHA256())))
        # cryptography emits DER; normalize the mathematically equivalent high-S form.
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        return encode_dss_signature(r, min(s, _SECP256K1_ORDER - s))


class InMemoryDecisionLedger:
    """Test/development append-only reader; production implementations must be durable."""
    def __init__(self) -> None:
        self._records: dict[str, Mapping[str, Any]] = {}
    def append_decision(self, receipt_hash: str, receipt: Mapping[str, Any]) -> None:
        if receipt_hash in self._records:
            raise ValueError("receipt hash already recorded")
        self._records[receipt_hash] = dict(receipt)
    def get_receipt(self, receipt_hash: str) -> Mapping[str, Any] | None:
        receipt = self._records.get(receipt_hash)
        return dict(receipt) if receipt else None


class AuthenticatedLineageVerifier:
    """Verify bounded, signed receipt ancestry from a ledger reader.

    The store is intentionally a read-only protocol boundary.  Production
    deployments should back it with an append-only service rather than the
    in-memory implementation above.
    """
    def __init__(self, store: DecisionLedger, verifier: SignatureVerifier, max_depth: int = 128) -> None:
        self._store, self._verifier, self._max_depth = store, verifier, max_depth

    def verify(self, receipt_hash: str) -> bool:
        seen: set[str] = set()
        child: Mapping[str, Any] | None = None
        current_hash = receipt_hash
        for _ in range(self._max_depth):
            if current_hash in seen or not _HEX_64.fullmatch(current_hash):
                return False
            seen.add(current_hash)
            receipt = self._store.get_receipt(current_hash)
            if receipt is None or canonical_hash(receipt) != current_hash or not self._valid_signature(receipt):
                return False
            if child is not None and child.get("sequence") != receipt.get("sequence", -1) + 1:
                return False
            parent = receipt.get("parent_receipt_hash")
            if parent is None:
                return receipt.get("sequence") == 0
            if not isinstance(parent, str):
                return False
            child, current_hash = receipt, parent
        return False

    def _valid_signature(self, receipt: Mapping[str, Any]) -> bool:
        try:
            signature = base64.b64decode(receipt["signature"], validate=True)
            public_key = base64.b64decode(receipt["gatekeeper_public_key"], validate=True)
            body = {key: value for key, value in receipt.items()
                    if key not in {"signature", "signature_algorithm", "gatekeeper_public_key"}}
            return self._verifier.verify_signature(algorithm=receipt["signature_algorithm"], public_key=public_key,
                                                   message=RECEIPT_DOMAIN + canonical_json(body), signature=signature)
        except (KeyError, TypeError, ValueError, CanonicalJSONError):
            return False


class AdmissionGatekeeper:
    """Parse raw requests, bind one authority checkpoint, sign and append decisions."""
    _FIELDS = frozenset({"schema_version", "canonicalization_version", "domain_separator",
                         "credential_id", "authority_checkpoint_hash", "authority_epoch",
                         "signature_algorithm", "requested_operation", "candidate_hash",
                         "parent_receipt_hash", "nonce", "signature"})
    def __init__(self, *, gatekeeper_id: str, authority_resolver: AuthorityResolver,
                 verifier: SignatureVerifier, receipt_signer: ReceiptSigner,
                 ledger: DecisionLedger) -> None:
        self.gatekeeper_id, self.authority_resolver = gatekeeper_id, authority_resolver
        self.verifier, self.receipt_signer, self.ledger = verifier, receipt_signer, ledger

    def evaluate(self, *, raw_candidate: bytes, raw_envelope: bytes, current_time: str) -> dict[str, Any]:
        """Return only a signed-and-appended decision, otherwise a fail-closed CUTOFF."""
        try:
            candidate, envelope = parse_canonical_json(raw_candidate), parse_canonical_json(raw_envelope)
            if not isinstance(envelope, dict) or set(envelope) != self._FIELDS:
                raise ValueError("invalid envelope field set")
            if envelope["schema_version"] != 1 or envelope["canonicalization_version"] != CANONICALIZATION_VERSION:
                raise ValueError("unsupported envelope version")
            if envelope["domain_separator"] != "TAS_AUTHORITY_GATE_V1":
                raise ValueError("invalid authorization domain")
            if not all(isinstance(envelope[field], str) and envelope[field] for field in
                       ("credential_id", "signature_algorithm", "requested_operation", "signature", "nonce")):
                raise ValueError("invalid string envelope field")
            if (not isinstance(envelope["authority_epoch"], int) or isinstance(envelope["authority_epoch"], bool)
                    or not _HEX_64.fullmatch(envelope["authority_checkpoint_hash"])
                    or not _HEX_64.fullmatch(envelope["candidate_hash"])
                    or (envelope["parent_receipt_hash"] is not None
                        and (not isinstance(envelope["parent_receipt_hash"], str)
                             or not _HEX_64.fullmatch(envelope["parent_receipt_hash"])))):
                raise ValueError("invalid envelope identifier field")
            if not isinstance(envelope["nonce"], str) or not envelope["nonce"]:
                raise ValueError("invalid nonce")
            if envelope["candidate_hash"] != canonical_hash(candidate):
                raise ValueError("candidate binding mismatch")
            snapshot = self.authority_resolver.resolve(
                credential_id=envelope["credential_id"], checkpoint_hash=envelope["authority_checkpoint_hash"])
            admitted = self._authorized(envelope, snapshot, current_time)
            failure = None if admitted else "AUTHORIZATION_REFUSED"
        except Exception as error:
            envelope, snapshot, admitted, failure = {}, None, False, f"INVALID_INPUT:{type(error).__name__}"
            candidate = None
        return self._record(envelope, snapshot, candidate, current_time, admitted, failure)

    def _authorized(self, envelope: Mapping[str, Any], snapshot: AuthoritySnapshot | None,
                    current_time: str) -> bool:
        if snapshot is None or snapshot.revoked or envelope["authority_epoch"] != snapshot.authority_epoch:
            return False
        if envelope["signature_algorithm"] != snapshot.algorithm or current_time > snapshot.valid_until:
            return False
        try:
            signature = base64.b64decode(envelope["signature"], validate=True)
        except (ValueError, TypeError):
            return False
        body = {key: value for key, value in envelope.items() if key != "signature"}
        return self.verifier.verify_signature(algorithm=snapshot.algorithm, public_key=snapshot.public_key,
                                              message=AUTHORIZATION_DOMAIN + canonical_json(body), signature=signature)

    def _record(self, envelope: Mapping[str, Any], snapshot: AuthoritySnapshot | None, candidate: Any,
                current_time: str, admitted: bool, failure: str | None) -> dict[str, Any]:
        parent_hash = envelope.get("parent_receipt_hash")
        try:
            if parent_hash is None:
                sequence = 0
            else:
                parent = self.ledger.get_receipt(parent_hash)
                if parent is None or not isinstance(parent.get("sequence"), int):
                    raise ValueError("unknown lineage parent")
                sequence = parent["sequence"] + 1
        except Exception:
            return {"resulting_state": "CUTOFF", "failure_code": "LINEAGE_UNAVAILABLE", "durable_receipt": False}
        body = {"schema_version": 1, "canonicalization_version": CANONICALIZATION_VERSION,
                "rule_set_version": RULE_SET_VERSION, "gatekeeper_id": self.gatekeeper_id,
                "event_type": "ADMISSION_DECISION", "evaluated_at": current_time, "sequence": sequence,
                "decision_id": hashlib.sha256((str(envelope.get("nonce")) + str(envelope.get("candidate_hash")) + current_time).encode()).hexdigest(),
                "resulting_state": "ADMITTED" if admitted else "REFUSED",
                "credential_id": envelope.get("credential_id"),
                "authority_epoch": snapshot.authority_epoch if snapshot else None,
                "authority_checkpoint_hash": snapshot.checkpoint_hash if snapshot else None,
                "candidate_hash": canonical_hash(candidate) if candidate is not None else None,
                "authorization_envelope_hash": canonical_hash(envelope) if envelope else None,
                "requested_operation": envelope.get("requested_operation"),
                "parent_receipt_hash": envelope.get("parent_receipt_hash"), "nonce": envelope.get("nonce"),
                "failure_code": failure}
        try:
            signature = self.receipt_signer.sign(RECEIPT_DOMAIN + canonical_json(body))
            receipt = {**body, "signature_algorithm": self.receipt_signer.algorithm,
                       "gatekeeper_public_key": base64.b64encode(self.receipt_signer.public_key).decode(),
                       "signature": base64.b64encode(signature).decode()}
            receipt_hash = canonical_hash(receipt)
            self.ledger.append_decision(receipt_hash, receipt)
            return {"resulting_state": body["resulting_state"], "durable_receipt": True,
                    "receipt_hash": receipt_hash, "receipt": receipt}
        except Exception:
            return {"resulting_state": "CUTOFF", "failure_code": "RECEIPT_PRESERVATION_UNAVAILABLE",
                    "durable_receipt": False}
