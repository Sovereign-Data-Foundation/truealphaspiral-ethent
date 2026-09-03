"""Crash-safe execution of effects whose outcome can become unknowable.

The durable domain document is the unit of atomicity.  It contains the canonical
root, the operational attempt/latch, and its signed witness chain; consequently a
latch can never be published without the witness that explains it.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from context_snapshot import canonical_json, parse_canonical_json

_EMPTY_HASH = "0" * 64


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class PreparedAttempt:
    attempt_id: str
    protected_domain: str
    expected_parent: str
    effect_digest: str
    execution_nonce: str
    authority_digest: str


@dataclass(frozen=True)
class IndeterminateLatch:
    version: int
    attempt_id: str
    protected_domain: str
    expected_parent: str
    proposed_effect_digest: str
    execution_nonce: str
    authority_digest: str
    prepared_receipt_hash: str
    evidence_gap_digest: str
    # Decimal string because TAS-CJSON-1 rejects integers outside IEEE-754's
    # exactly representable range; current epoch nanoseconds exceed that range.
    first_observed_at_ns: str
    status: str = "LATCHED"


@dataclass(frozen=True)
class WitnessRecord:
    """Historical attestation; its signature conveys provenance, not authority."""

    version: int
    sequence: int
    event_type: str
    protected_domain: str
    attempt_id: str
    parent_witness_hash: str
    expected_state_parent: str
    effect_digest: str
    execution_nonce: str
    outcome: str
    evidence_digest: str
    timestamp_ns: str
    record_hash: str
    signer_key_id: str
    signature: str


@dataclass(frozen=True)
class EffectProof:
    disposition: str
    parent_root: str
    resulting_root: str
    execution_nonce: str
    effect_digest: str
    provider_proof: Mapping[str, Any]


class CommitIndeterminate(Exception):
    """The adapter may have committed but cannot return a terminal proof."""

    def __init__(self, evidence: Mapping[str, Any] | None = None) -> None:
        self.evidence = dict(evidence or {})
        super().__init__("effect outcome is indeterminate")


class RuntimeLatchedError(RuntimeError):
    def __init__(self, latch: IndeterminateLatch) -> None:
        self.latch = latch
        super().__init__(f"protected domain {latch.protected_domain!r} is latched")


class EffectProofVerifier(Protocol):
    def __call__(self, proof: EffectProof) -> bool: ...


class DomainTransaction:
    """A locked domain aggregate committed using atomic file replacement."""

    def __init__(self, store: "FileProtectedStateStore", domain: str) -> None:
        self.store = store
        self.domain = domain
        self.path = (
            store.directory / f"{hashlib.sha256(domain.encode()).hexdigest()}.json"
        )
        self.document: dict[str, Any] = {}
        self._dirty = False

    def initialize(self, initial_root: str) -> None:
        if not self.document:
            self.document = {
                "domain": self.domain,
                "latch": None,
                "prepared": None,
                "root": initial_root,
                "witnesses": [],
            }
            self._dirty = True

    def append_witness(
        self, event_type: str, body: Mapping[str, Any], evidence: Mapping[str, Any]
    ) -> str:
        evidence_digest = _digest(b"TAS\x00EVIDENCE\x00V1\x00", evidence)
        witnesses = self.document["witnesses"]
        parent = witnesses[-1]["record_hash"] if witnesses else _EMPTY_HASH
        record_body = {
            **body,
            "event_type": event_type,
            "evidence_digest": evidence_digest,
            "outcome": body.get("outcome", event_type),
            "parent_witness_hash": parent,
            "protected_domain": self.domain,
            "sequence": len(witnesses) + 1,
            "timestamp_ns": str(time.time_ns()),
            "version": 1,
        }
        record_hash = hashlib.sha256(
            b"TAS\x00WITNESS\x00V1\x00"
            + bytes.fromhex(parent)
            + canonical_json(record_body)
        ).hexdigest()
        signature = self.store.signer.sign(bytes.fromhex(record_hash)).hex()
        witnesses.append(
            {
                **record_body,
                "evidence": dict(evidence),
                "record_hash": record_hash,
                "signature": signature,
                "signer_key_id": self.store.signer_key_id,
            }
        )
        self._dirty = True
        return record_hash

    def commit(self) -> None:
        if not self._dirty:
            return
        payload = canonical_json(self.document)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        try:
            with open(temporary, "xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.store.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)
        self._dirty = False


class FileProtectedStateStore:
    """File-backed, process-safe store for protected domain aggregates."""

    def __init__(
        self, directory: str | os.PathLike[str], signer: Ed25519PrivateKey
    ) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.signer = signer
        public = signer.public_key().public_bytes_raw()
        self.signer_key_id = hashlib.sha256(public).hexdigest()

    @contextmanager
    def transaction(self, domain: str) -> Iterator[DomainTransaction]:
        lock_path = (
            self.directory / f".{hashlib.sha256(domain.encode()).hexdigest()}.lock"
        )
        with open(lock_path, "a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            transaction = DomainTransaction(self, domain)
            try:
                transaction.document = dict(
                    parse_canonical_json(transaction.path.read_bytes())
                )
            except FileNotFoundError:
                pass
            try:
                yield transaction
                transaction.commit()
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def read(self, domain: str) -> Mapping[str, Any] | None:
        with self.transaction(domain) as transaction:
            return transaction.document or None


class ProtectedEffectRuntime:
    """Implements durable PREPARE -> DISPATCH -> PROVE -> local COMMIT."""

    def __init__(
        self, store: FileProtectedStateStore, verify_proof: EffectProofVerifier
    ) -> None:
        self.store = store
        self.verify_proof = verify_proof

    @staticmethod
    def execution_identity(
        *,
        domain: str,
        tool: str,
        operation: str,
        arguments: Mapping[str, Any],
        expected_parent: str,
        execution_nonce: str,
        authority_digest: str,
    ) -> tuple[str, str]:
        coordinate = {
            "arguments": arguments,
            "authority_digest": authority_digest,
            "domain": domain,
            "execution_nonce": execution_nonce,
            "expected_parent": expected_parent,
            "operation": operation,
            "tool": tool,
            "version": 1,
        }
        effect_digest = _digest(b"TAS\x00EFFECT\x00V1\x00", coordinate)
        attempt_id = _digest(
            b"TAS\x00ATTEMPT\x00V1\x00",
            {
                "domain": domain,
                "effect_digest": effect_digest,
                "execution_nonce": execution_nonce,
                "expected_parent": expected_parent,
            },
        )
        return effect_digest, attempt_id

    def execute(
        self,
        *,
        domain: str,
        initial_root: str,
        tool: str,
        operation: str,
        arguments: Mapping[str, Any],
        execution_nonce: str,
        authority_digest: str,
        adapter: Callable[[], EffectProof],
    ) -> EffectProof:
        with self.store.transaction(domain) as transaction:
            transaction.initialize(initial_root)
            if transaction.document["latch"]:
                raise RuntimeLatchedError(
                    IndeterminateLatch(**transaction.document["latch"])
                )
            if transaction.document["prepared"]:
                latch = self._latch(
                    transaction, {"reason": "orphaned prepared attempt"}
                )
                transaction.commit()
                raise RuntimeLatchedError(latch)

            parent = transaction.document["root"]
            effect_digest, attempt_id = self.execution_identity(
                domain=domain,
                tool=tool,
                operation=operation,
                arguments=arguments,
                expected_parent=parent,
                execution_nonce=execution_nonce,
                authority_digest=authority_digest,
            )
            prepared = PreparedAttempt(
                attempt_id,
                domain,
                parent,
                effect_digest,
                execution_nonce,
                authority_digest,
            )
            receipt_hash = transaction.append_witness(
                "ATTEMPT_PREPARED",
                {
                    "attempt_id": attempt_id,
                    "authority_digest": authority_digest,
                    "effect_digest": effect_digest,
                    "execution_nonce": execution_nonce,
                    "expected_state_parent": parent,
                },
                {"tool": tool, "operation": operation},
            )
            transaction.document["prepared"] = {
                **asdict(prepared),
                "prepared_receipt_hash": receipt_hash,
            }
            transaction._dirty = True
            transaction.commit()  # durability boundary: adapter cannot run before this

            try:
                proof = adapter()
            except CommitIndeterminate as error:
                latch = self._latch(transaction, error.evidence)
                transaction.commit()
                raise RuntimeLatchedError(latch) from error

            except Exception as error:
                # Once the adapter is entered, an ordinary exception is not proof
                # that dispatch did not happen.  Preserve that uncertainty now,
                # rather than waiting for restart recovery.
                latch = self._latch(
                    transaction,
                    {
                        "exception_type": type(error).__name__,
                        "reason": "adapter exited without terminal proof",
                    },
                )
                transaction.commit()
                raise RuntimeLatchedError(latch) from error

            try:
                proof_is_valid = self._proof_matches(
                    proof, prepared
                ) and self.verify_proof(proof)
            except Exception:
                proof_is_valid = False
            if not proof_is_valid:
                latch = self._latch(
                    transaction, {"reason": "terminal effect proof absent or invalid"}
                )
                transaction.commit()
                raise RuntimeLatchedError(latch)

            if proof.disposition == "COMMIT_PROVEN":
                transaction.document["root"] = proof.resulting_root
            elif proof.disposition != "NON_COMMIT_PROVEN":
                latch = self._latch(
                    transaction, {"reason": "unknown proof disposition"}
                )
                transaction.commit()
                raise RuntimeLatchedError(latch)
            transaction.append_witness(
                proof.disposition,
                {
                    "attempt_id": attempt_id,
                    "effect_digest": effect_digest,
                    "execution_nonce": execution_nonce,
                    "expected_state_parent": parent,
                    "resulting_root": proof.resulting_root,
                },
                proof.provider_proof,
            )
            transaction.document["prepared"] = None
            transaction._dirty = True
            return proof

    @staticmethod
    def _proof_matches(proof: EffectProof, attempt: PreparedAttempt) -> bool:
        return (
            proof.parent_root == attempt.expected_parent
            and proof.execution_nonce == attempt.execution_nonce
            and proof.effect_digest == attempt.effect_digest
            and (
                proof.disposition != "NON_COMMIT_PROVEN"
                or proof.resulting_root == attempt.expected_parent
            )
        )

    def _latch(
        self, transaction: DomainTransaction, evidence: Mapping[str, Any]
    ) -> IndeterminateLatch:
        prepared = transaction.document["prepared"]
        evidence_digest = _digest(b"TAS\x00EVIDENCE\x00V1\x00", evidence)
        latch = IndeterminateLatch(
            version=1,
            attempt_id=prepared["attempt_id"],
            protected_domain=self._domain(transaction),
            expected_parent=prepared["expected_parent"],
            proposed_effect_digest=prepared["effect_digest"],
            execution_nonce=prepared["execution_nonce"],
            authority_digest=prepared["authority_digest"],
            prepared_receipt_hash=prepared["prepared_receipt_hash"],
            evidence_gap_digest=evidence_digest,
            first_observed_at_ns=str(time.time_ns()),
        )
        transaction.append_witness(
            "INDETERMINATE_LATCHED",
            {
                "attempt_id": latch.attempt_id,
                "authority_digest": latch.authority_digest,
                "effect_digest": latch.proposed_effect_digest,
                "execution_nonce": latch.execution_nonce,
                "expected_state_parent": latch.expected_parent,
                "prepared_receipt_hash": latch.prepared_receipt_hash,
            },
            evidence,
        )
        transaction.document["latch"] = asdict(latch)
        transaction.document["prepared"] = None
        transaction._dirty = True
        return latch

    @staticmethod
    def _domain(transaction: DomainTransaction) -> str:
        return transaction.document["domain"]

    def reconcile(self, domain: str, proof: EffectProof) -> str:
        """Verify and atomically update root, close latch, and append witness."""
        with self.store.transaction(domain) as transaction:
            if not transaction.document or not transaction.document["latch"]:
                return "NO_ACTIVE_LATCH"
            latch = IndeterminateLatch(**transaction.document["latch"])
            expected = PreparedAttempt(
                latch.attempt_id,
                domain,
                latch.expected_parent,
                latch.proposed_effect_digest,
                latch.execution_nonce,
                latch.authority_digest,
            )
            if not self._proof_matches(proof, expected) or not self.verify_proof(proof):
                return "LATCH_REMAINS_CLOSED"
            if proof.disposition == "COMMIT_PROVEN":
                transaction.document["root"] = proof.resulting_root
                result = "RECOVERED_TO_COMMIT"
            elif proof.disposition == "NON_COMMIT_PROVEN":
                result = "RECOVERED_TO_NONCOMMIT"
            else:
                return "LATCH_REMAINS_CLOSED"
            transaction.append_witness(
                "LATCH_RESOLVED",
                {
                    "attempt_id": latch.attempt_id,
                    "effect_digest": latch.proposed_effect_digest,
                    "execution_nonce": latch.execution_nonce,
                    "expected_state_parent": latch.expected_parent,
                    "resolution": proof.disposition,
                    "resulting_root": proof.resulting_root,
                },
                proof.provider_proof,
            )
            transaction.document["latch"] = None
            transaction._dirty = True
            return result
