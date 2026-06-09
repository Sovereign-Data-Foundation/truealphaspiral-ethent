"""Tests for genesis_anchor.py — deterministic genesis payload derivation.

Verifies:
- Deterministic derivation of node and validator stub public keys from A_0.
- app_hash is the SHA-256 of canonical app_state JSON (upper-case hex).
- build_genesis_payload() produces a fully-populated, schema-consistent dict.
- tas_codex_rules uses integer basis-point encoding (no float strings).
- consensus_params restricts pub_key_types to ed25519 only.
- governance block is present and correctly structured in app_state.
- All monetary fields carry explicit denomination siblings.
- app_hash in the built payload matches re-derived value (self-consistency).
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from genesis_anchor import (
    derive_node_pubkey,
    derive_validator_pubkey,
    derive_app_hash,
    build_genesis_payload,
)
from tas_dna import A_0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).digest().hex()


def _canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Key derivation tests
# ---------------------------------------------------------------------------

class TestDeriveNodePubkey:
    def test_returns_64_char_hex(self):
        pk = derive_node_pubkey(0)
        assert len(pk) == 64
        int(pk, 16)  # raises ValueError if not valid hex

    def test_deterministic(self):
        assert derive_node_pubkey(0) == derive_node_pubkey(0)

    def test_different_indices_differ(self):
        assert derive_node_pubkey(0) != derive_node_pubkey(1)

    def test_matches_expected_derivation(self):
        root = A_0.lineage_hash()
        expected = hashlib.sha256(root + b"tas_node_pubkey" + b"\x00").digest().hex()
        assert derive_node_pubkey(0) == expected

    def test_index_1_matches_expected_derivation(self):
        root = A_0.lineage_hash()
        expected = hashlib.sha256(root + b"tas_node_pubkey" + b"\x01").digest().hex()
        assert derive_node_pubkey(1) == expected


class TestDeriveValidatorPubkey:
    def test_returns_64_char_hex(self):
        pk = derive_validator_pubkey(0)
        assert len(pk) == 64
        int(pk, 16)

    def test_deterministic(self):
        assert derive_validator_pubkey(0) == derive_validator_pubkey(0)

    def test_differs_from_node_key(self):
        assert derive_validator_pubkey(0) != derive_node_pubkey(0)

    def test_matches_expected_derivation(self):
        root = A_0.lineage_hash()
        expected = hashlib.sha256(root + b"tas_validator_pubkey" + b"\x00").digest().hex()
        assert derive_validator_pubkey(0) == expected


# ---------------------------------------------------------------------------
# app_hash derivation tests
# ---------------------------------------------------------------------------

class TestDeriveAppHash:
    def test_returns_64_char_upper_hex(self):
        h = derive_app_hash({"key": "value"})
        assert len(h) == 64
        assert h == h.upper()

    def test_deterministic(self):
        state = {"accounts": [], "governance": {}}
        assert derive_app_hash(state) == derive_app_hash(state)

    def test_canonical_key_order_independent(self):
        a = derive_app_hash({"b": 2, "a": 1})
        b = derive_app_hash({"a": 1, "b": 2})
        assert a == b

    def test_matches_sha256_of_canonical_json(self):
        state = {"foo": "bar", "n": 42}
        canonical = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        expected = hashlib.sha256(canonical).digest().hex().upper()
        assert derive_app_hash(state) == expected

    def test_different_states_produce_different_hashes(self):
        assert derive_app_hash({"a": 1}) != derive_app_hash({"a": 2})


# ---------------------------------------------------------------------------
# build_genesis_payload schema tests
# ---------------------------------------------------------------------------

class TestBuildGenesisPayload:
    def setup_method(self):
        self.payload = build_genesis_payload()

    # Top-level required keys
    def test_top_level_keys_present(self):
        required = {
            "chain_id", "genesis_time", "initial_height", "app_hash",
            "consensus_params", "tas_codex_rules", "app_state", "seed_validators",
        }
        assert required.issubset(self.payload.keys())

    def test_chain_id(self):
        assert self.payload["chain_id"] == "TAS-sovereign-01"

    def test_initial_height_is_string_one(self):
        assert self.payload["initial_height"] == "1"

    # app_hash
    def test_app_hash_is_64_char_upper_hex(self):
        h = self.payload["app_hash"]
        assert len(h) == 64
        assert h == h.upper()

    def test_app_hash_self_consistent(self):
        """app_hash must equal SHA-256 of the canonical app_state."""
        expected = derive_app_hash(self.payload["app_state"])
        assert self.payload["app_hash"] == expected

    # consensus_params
    def test_consensus_params_structure(self):
        cp = self.payload["consensus_params"]
        assert "block" in cp
        assert "evidence" in cp
        assert "validator" in cp

    def test_ed25519_only_no_secp256k1(self):
        pub_key_types = self.payload["consensus_params"]["validator"]["pub_key_types"]
        assert pub_key_types == ["ed25519"]
        assert "secp256k1" not in pub_key_types

    # tas_codex_rules encoding
    def test_governance_quorum_is_integer_bps(self):
        rules = self.payload["tas_codex_rules"]
        assert isinstance(rules["governance_quorum_bps"], int)
        assert rules["governance_quorum_bps"] == 6667

    def test_slashing_double_sign_is_integer_bps(self):
        rules = self.payload["tas_codex_rules"]
        assert isinstance(rules["slashing_fraction_double_sign_bps"], int)
        assert rules["slashing_fraction_double_sign_bps"] == 500

    def test_slashing_downtime_is_integer_bps(self):
        rules = self.payload["tas_codex_rules"]
        assert isinstance(rules["slashing_fraction_downtime_bps"], int)
        assert rules["slashing_fraction_downtime_bps"] == 100

    def test_no_float_string_quorum(self):
        rules = self.payload["tas_codex_rules"]
        assert "governance_quorum_percent" not in rules

    def test_base_fee_denom_present(self):
        rules = self.payload["tas_codex_rules"]
        assert rules["base_fee_denom"] == "utas"

    def test_version_semantic(self):
        version = self.payload["tas_codex_rules"]["version"]
        parts = version.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    # app_state accounts
    def test_accounts_list_non_empty(self):
        assert len(self.payload["app_state"]["accounts"]) >= 1

    def test_account_has_public_key(self):
        for acc in self.payload["app_state"]["accounts"]:
            assert "public_key" in acc
            assert len(acc["public_key"]) == 64

    def test_account_has_roles(self):
        for acc in self.payload["app_state"]["accounts"]:
            assert "roles" in acc
            assert isinstance(acc["roles"], list)
            assert len(acc["roles"]) >= 1

    def test_account_balance_denom_present(self):
        for acc in self.payload["app_state"]["accounts"]:
            assert acc["balance_denom"] == "utas"

    # app_state governance
    def test_governance_block_present(self):
        assert "governance" in self.payload["app_state"]

    def test_governance_required_keys(self):
        gov = self.payload["app_state"]["governance"]
        assert "proposal_threshold" in gov
        assert "proposal_threshold_denom" in gov
        assert "voting_period_seconds" in gov
        assert "authorized_amendment_addresses" in gov

    def test_governance_voting_period_is_7_days(self):
        gov = self.payload["app_state"]["governance"]
        assert int(gov["voting_period_seconds"]) == 7 * 24 * 3600

    def test_governance_authorized_addresses_non_empty(self):
        gov = self.payload["app_state"]["governance"]
        assert len(gov["authorized_amendment_addresses"]) >= 1

    # seed_validators
    def test_seed_validators_non_empty(self):
        assert len(self.payload["seed_validators"]) >= 1

    def test_validator_pub_key_type_ed25519(self):
        for v in self.payload["seed_validators"]:
            assert v["pub_key"]["type"] == "ed25519"

    def test_validator_pub_key_value_is_64_char_hex(self):
        for v in self.payload["seed_validators"]:
            val = v["pub_key"]["value"]
            assert len(val) == 64
            int(val, 16)

    # Determinism
    def test_payload_is_deterministic(self):
        p1 = build_genesis_payload()
        p2 = build_genesis_payload()
        assert p1 == p2

    # system_contracts
    def test_system_contracts_present(self):
        sc = self.payload["app_state"]["system_contracts"]
        assert "registry_address" in sc
        assert "bytecode_hash" in sc

    def test_bytecode_hash_length(self):
        bh = self.payload["app_state"]["system_contracts"]["bytecode_hash"]
        assert len(bh) == 64


# ---------------------------------------------------------------------------
# JSON serialisability of genesis.json on disk
# ---------------------------------------------------------------------------

class TestGenesisJsonFile:
    def test_config_genesis_json_exists(self):
        import pathlib
        path = pathlib.Path(__file__).resolve().parents[1] / "config" / "genesis.json"
        assert path.exists(), "config/genesis.json must exist"

    def test_config_genesis_json_is_valid_json(self):
        import pathlib
        path = pathlib.Path(__file__).resolve().parents[1] / "config" / "genesis.json"
        with open(path) as f:
            data = json.load(f)
        assert data["chain_id"] == "TAS-sovereign-01"

    def test_config_genesis_json_app_hash_self_consistent(self):
        """The on-disk file's app_hash must match re-derivation from its app_state."""
        import pathlib
        path = pathlib.Path(__file__).resolve().parents[1] / "config" / "genesis.json"
        with open(path) as f:
            data = json.load(f)
        expected = derive_app_hash(data["app_state"])
        assert data["app_hash"] == expected
