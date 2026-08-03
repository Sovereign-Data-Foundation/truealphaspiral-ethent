"""Fail-closed consumption of verifier-produced admissibility decisions."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from context_snapshot import (
    CanonicalJSONError,
    canonical_hash,
    canonical_json,
    parse_canonical_json,
)

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_HEX_128 = re.compile(r"^[0-9a-f]{128}$")


@dataclass(frozen=True)
class AdmissibilityDecision:
    """Immutable, signed execution authority emitted by the Logos verifier."""

    authority_pubkey: str
    authority_snapshot_hash: str
    context_snapshot_hash: str
    candidate_hash: str
    parent_receipt_hash: str
    allowed_action_tokens: tuple[str, ...]
    is_admitted: bool
    nonce: str
    timestamp_utc: str
    refusal_reason: str | None = None
    verifier_signature: str | None = None

    def canonical_payload_dict(self) -> dict[str, Any]:
        return {
            "allowed_action_tokens": sorted(self.allowed_action_tokens),
            "authority_pubkey": self.authority_pubkey.lower(),
            "authority_snapshot_hash": self.authority_snapshot_hash.lower(),
            "candidate_hash": self.candidate_hash.lower(),
            "context_snapshot_hash": self.context_snapshot_hash.lower(),
            "is_admitted": self.is_admitted,
            "nonce": self.nonce,
            "parent_receipt_hash": self.parent_receipt_hash.lower(),
            "refusal_reason": self.refusal_reason or "",
            "timestamp_utc": self.timestamp_utc,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.canonical_payload_dict())

    def compute_digest(self) -> bytes:
        return hashlib.sha256(self.canonical_bytes()).digest()

    def compute_digest_hex(self) -> str:
        return self.compute_digest().hex()

    def with_signature(self, signature_hex: str) -> "AdmissibilityDecision":
        return replace(self, verifier_signature=signature_hex.lower())

    def to_json(self) -> str:
        return canonical_json(
            {
                **self.canonical_payload_dict(),
                "verifier_signature": self.verifier_signature or "",
            }
        ).decode("utf-8")

    @classmethod
    def from_json(cls, raw: str) -> "AdmissibilityDecision":
        data = parse_canonical_json(raw.encode("utf-8"))
        if not isinstance(data, Mapping):
            raise ValueError("decision must be a JSON object")
        expected = set(cls.__dataclass_fields__)
        if set(data) != expected:
            raise ValueError("invalid decision field set")
        return cls(
            authority_pubkey=data["authority_pubkey"],
            authority_snapshot_hash=data["authority_snapshot_hash"],
            context_snapshot_hash=data["context_snapshot_hash"],
            candidate_hash=data["candidate_hash"],
            parent_receipt_hash=data["parent_receipt_hash"],
            allowed_action_tokens=tuple(data["allowed_action_tokens"]),
            is_admitted=data["is_admitted"],
            nonce=data["nonce"],
            timestamp_utc=data["timestamp_utc"],
            refusal_reason=data["refusal_reason"] or None,
            verifier_signature=data["verifier_signature"] or None,
        )


@dataclass(frozen=True)
class RuntimeReceipt:
    """Durable evidence of an execution or fail-closed refusal."""

    status: str
    action_token: str
    parent_receipt_hash: str
    decision_digest_hex: str
    refusal_reason: str | None

    @property
    def mapping(self) -> dict[str, Any]:
        return {
            "action_token": self.action_token,
            "decision_digest_hex": self.decision_digest_hex,
            "parent_receipt_hash": self.parent_receipt_hash,
            "refusal_reason": self.refusal_reason or "",
            "status": self.status,
        }


class RuntimeSecurityError(Exception):
    """Raised only after the runtime has durably recorded a refusal."""

    def __init__(self, receipt: RuntimeReceipt) -> None:
        self.receipt = receipt
        super().__init__(receipt)


class RuntimeReceiptLedger(Protocol):
    def append(self, receipt: RuntimeReceipt) -> str: ...

    def get(self, receipt_hash: str) -> Mapping[str, Any] | None: ...

    def contains_decision(self, decision_digest_hex: str) -> bool: ...


class FileRuntimeReceiptLedger:
    """Content-addressed runtime receipts with restart-safe replay detection."""

    def __init__(self, directory: str | os.PathLike[str]) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def append(self, receipt: RuntimeReceipt) -> str:
        payload = canonical_json(receipt.mapping)
        receipt_hash = hashlib.sha256(payload).hexdigest()
        destination = self.directory / f"{receipt_hash}.json"
        temporary = self.directory / f".{receipt_hash}.{os.getpid()}.tmp"
        try:
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError as error:
                raise RuntimeError("runtime receipt already exists") from error
            temporary.unlink()
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
        return receipt_hash

    def get(self, receipt_hash: str) -> Mapping[str, Any] | None:
        if not _HEX_64.fullmatch(receipt_hash):
            return None
        try:
            raw = (self.directory / f"{receipt_hash}.json").read_bytes()
            receipt = parse_canonical_json(raw)
        except (FileNotFoundError, CanonicalJSONError):
            return None
        if (
            not isinstance(receipt, Mapping)
            or canonical_hash(receipt) != receipt_hash
        ):
            return None
        return dict(receipt)

    def contains_decision(self, decision_digest_hex: str) -> bool:
        for path in self.directory.glob("*.json"):
            receipt = self.get(path.stem)
            if receipt and receipt.get("decision_digest_hex") == decision_digest_hex:
                return True
        return False


class SovereignRuntime:
    """Execute only tokens present in a cryptographically verified closed set."""

    def __init__(self, ledger: RuntimeReceiptLedger) -> None:
        self.ledger = ledger

    def _verify_decision(self, decision: AdmissibilityDecision) -> None:
        digest_fields = (
            decision.authority_snapshot_hash,
            decision.context_snapshot_hash,
            decision.candidate_hash,
            decision.parent_receipt_hash,
        )
        if not _HEX_64.fullmatch(decision.authority_pubkey):
            raise ValueError("invalid authority public key")
        if not all(_HEX_64.fullmatch(value) for value in digest_fields):
            raise ValueError("invalid content binding digest")
        if len(decision.nonce) < 16:
            raise ValueError("nonce is too short")
        if (
            not decision.verifier_signature
            or not _HEX_128.fullmatch(decision.verifier_signature)
        ):
            raise ValueError("missing or malformed verifier signature")
        if len(set(decision.allowed_action_tokens)) != len(
            decision.allowed_action_tokens
        ):
            raise ValueError("allowed action tokens are not unique")
        try:
            Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(decision.authority_pubkey)
            ).verify(
                bytes.fromhex(decision.verifier_signature),
                decision.compute_digest(),
            )
        except (ValueError, InvalidSignature) as error:
            raise ValueError("cryptographic signature verification failed") from error
        if not decision.is_admitted:
            raise ValueError(
                "execution rejected by Logos gate: "
                f"{decision.refusal_reason or 'unspecified'}"
            )
        if not decision.allowed_action_tokens:
            raise ValueError("admitted decision contains an empty allowed action set")

    def execute(
        self, decision: AdmissibilityDecision, target_action_token: str
    ) -> dict[str, Any]:
        try:
            self._verify_decision(decision)
            if self.ledger.contains_decision(decision.compute_digest_hex()):
                raise ValueError("decision nonce has already been consumed")
            if target_action_token not in decision.allowed_action_tokens:
                raise ValueError("target action token is outside the allowed set")
        except (ValueError, TypeError) as error:
            receipt = RuntimeReceipt(
                status="REFUSED",
                action_token=target_action_token,
                parent_receipt_hash=decision.parent_receipt_hash,
                decision_digest_hex=decision.compute_digest_hex(),
                refusal_reason=str(error),
            )
            self.ledger.append(receipt)
            raise RuntimeSecurityError(receipt) from error

        receipt = RuntimeReceipt(
            status="EXECUTED",
            action_token=target_action_token,
            parent_receipt_hash=decision.parent_receipt_hash,
            decision_digest_hex=decision.compute_digest_hex(),
            refusal_reason=None,
        )
        receipt_hash = self.ledger.append(receipt)
        return {**receipt.mapping, "receipt_hash": receipt_hash}
