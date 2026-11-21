"""Canonical OURSPACE-SMT-SHA256-V1 proof verification reference."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping


DOM_LEAF = b"\x00"
DOM_NODE = b"\x01"
DOM_INDEX = b"\x02"
DOM_ENTRY = b"\x03"
EMPTY_DIGEST = b"\x00" * 32


class SMTProofInvalid(ValueError):
    """The proof or one of its canonical encodings is invalid."""


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def length_prefixed_utf8(value: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) > 0xFFFFFFFF:
        raise SMTProofInvalid("UTF-8 identifier exceeds uint32 length")
    return len(encoded).to_bytes(4, "big") + encoded


def capability_index(issuer: str, capability_id: str) -> bytes:
    if not isinstance(issuer, str) or not isinstance(capability_id, str):
        raise SMTProofInvalid("issuer and capability_id must be strings")
    return hashlib.sha256(
        DOM_INDEX
        + length_prefixed_utf8(issuer)
        + length_prefixed_utf8(capability_id)
    ).digest()


def dom_entry_leaf(
    issuer: str,
    capability_id: str,
    epoch: int,
    revoked_at: str,
    reason_code: str,
) -> bytes:
    """Encode a revocation entry as SHA256(DOM_ENTRY || canonical JCS record)."""
    if type(epoch) is not int or epoch < 0:
        raise SMTProofInvalid("epoch must be a nonnegative integer")
    record = {
        "capability_id": capability_id,
        "epoch": epoch,
        "issuer": issuer,
        "reason_code": reason_code,
        "revoked_at": revoked_at,
    }
    return hashlib.sha256(DOM_ENTRY + canonical_json(record)).digest()


@dataclass(frozen=True)
class CompressedProof:
    value: bytes
    mask: bytes
    siblings: tuple[bytes, ...]


def default_nodes() -> tuple[bytes, ...]:
    nodes = [EMPTY_DIGEST]
    for _ in range(256):
        nodes.append(hashlib.sha256(DOM_NODE + nodes[-1] + nodes[-1]).digest())
    return tuple(nodes)


def mask_bit(mask: bytes, depth: int) -> int:
    if len(mask) != 32 or not 0 <= depth < 256:
        raise SMTProofInvalid("invalid mask or depth")
    return (mask[depth // 8] >> (depth % 8)) & 1


def decode_proof(value: bytes, mask: bytes, siblings: bytes) -> CompressedProof:
    if not isinstance(value, bytes) or len(value) != 32:
        raise SMTProofInvalid("leaf value must be exactly 32 bytes")
    if not isinstance(mask, bytes) or len(mask) != 32:
        raise SMTProofInvalid("sibling mask must be exactly 32 bytes")
    present_count = sum(mask_bit(mask, depth) for depth in range(256))
    if len(siblings) != present_count * 32:
        raise SMTProofInvalid("packed sibling length does not match mask")

    defaults = default_nodes()
    packed: list[bytes] = []
    cursor = 0
    for depth in range(256):
        if mask_bit(mask, depth):
            sibling = siblings[cursor * 32:(cursor + 1) * 32]
            if sibling == defaults[depth]:
                raise SMTProofInvalid("explicit default sibling is non-canonical")
            packed.append(sibling)
            cursor += 1
    return CompressedProof(value=value, mask=mask, siblings=tuple(packed))


def reconstruct_root(
    issuer: str,
    capability_id: str,
    proof: CompressedProof,
    trusted_root: bytes,
) -> tuple[str, bytes]:
    if not isinstance(trusted_root, bytes) or len(trusted_root) != 32:
        raise SMTProofInvalid("trusted epoch SMT root must be exactly 32 bytes")

    key = capability_index(issuer, capability_id)
    defaults = default_nodes()
    node = EMPTY_DIGEST if proof.value == EMPTY_DIGEST else hashlib.sha256(
        DOM_LEAF + key + proof.value
    ).digest()
    cursor = 0

    for depth in range(256):
        if mask_bit(proof.mask, depth):
            if cursor >= len(proof.siblings):
                raise SMTProofInvalid("missing packed sibling")
            sibling = proof.siblings[cursor]
            if sibling == defaults[depth]:
                raise SMTProofInvalid("explicit default sibling is non-canonical")
            cursor += 1
        else:
            sibling = defaults[depth]

        key_bit = (key[depth // 8] >> (depth % 8)) & 1
        if key_bit == 0:
            node = hashlib.sha256(DOM_NODE + node + sibling).digest()
        else:
            node = hashlib.sha256(DOM_NODE + sibling + node).digest()

    if cursor != len(proof.siblings):
        raise SMTProofInvalid("trailing packed sibling")
    verdict = (
        "VERIFIED" if proof.value == EMPTY_DIGEST
        else "REVOKED"
    ) if node == trusted_root else "INVALID"
    return verdict, node
