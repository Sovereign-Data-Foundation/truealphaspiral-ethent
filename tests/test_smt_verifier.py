import pytest
import hashlib

from smt_verifier import (
    EMPTY_DIGEST,
    SMTProofInvalid,
    capability_index,
    decode_proof,
    default_nodes,
    dom_entry_leaf,
    reconstruct_root,
)


def test_positive_empty_epoch_vector():
    issuer = "did:tas:root:test"
    capability_id = "cap:exec:001"
    key = capability_index(issuer, capability_id)
    assert key.hex() == (
        "d2e6084c18986cadb4faea9fae40111940a3"
        "eebd4c389cb0bc62a196e680ea08"
    )

    proof = decode_proof(EMPTY_DIGEST, b"\x00" * 32, b"")
    verdict, root = reconstruct_root(
        issuer,
        capability_id,
        proof,
        bytes.fromhex(
            "6155289130893872355eac98042d22aefa2c2"
            "e708bea169402760e3b55f9a2dc"
        ),
    )
    assert verdict == "VERIFIED"
    assert root == bytes.fromhex(
        "6155289130893872355eac98042d22aefa2c2"
        "e708bea169402760e3b55f9a2dc"
    )


def test_wrong_root_is_invalid():
    proof = decode_proof(EMPTY_DIGEST, b"\x00" * 32, b"")
    verdict, _ = reconstruct_root(
        "did:tas:root:test",
        "cap:exec:001",
        proof,
        b"\x9f" * 32,
    )
    assert verdict == "INVALID"


def test_explicit_default_sibling_is_invalid():
    defaults = default_nodes()
    with pytest.raises(SMTProofInvalid, match="explicit default"):
        decode_proof(
            EMPTY_DIGEST,
            bytes([1]) + b"\x00" * 31,
            defaults[0],
        )


def test_dom_entry_leaf_is_deterministic_and_domain_separated():
    first = dom_entry_leaf(
        "did:tas:root:test",
        "cap:exec:001",
        9,
        "2026-11-21T00:00:00Z",
        "ADMINISTRATIVE_REVOCATION",
    )
    second = dom_entry_leaf(
        "did:tas:root:test",
        "cap:exec:001",
        9,
        "2026-11-21T00:00:00Z",
        "ADMINISTRATIVE_REVOCATION",
    )
    assert first == second
    assert len(first) == 32


def test_positive_revocation_dom_entry_vector():
    issuer = "did:tas:root:test"
    capability_id = "cap:exec:001"
    value = dom_entry_leaf(
        issuer,
        capability_id,
        9,
        "2026-11-21T00:00:00Z",
        "ADMINISTRATIVE_REVOCATION",
    )
    siblings = tuple(
        hashlib.sha256(
            b"TAS-SMT-KAT-SIBLING" + depth.to_bytes(4, "big")
        ).digest()
        for depth in range(256)
    )
    proof = decode_proof(value, b"\xff" * 32, b"".join(siblings))
    verdict, root = reconstruct_root(
        issuer,
        capability_id,
        proof,
        bytes.fromhex(
            "a98718417068f3a5223fd8d1c98e274e"
            "6e2857092c2bb9ef410251972203123e"
        ),
    )
    assert verdict == "REVOKED"
    assert root.hex() == (
        "a98718417068f3a5223fd8d1c98e274e"
        "6e2857092c2bb9ef410251972203123e"
    )
