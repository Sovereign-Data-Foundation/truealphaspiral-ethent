"""Genesis Anchor: deterministic key and hash derivation for the TAS genesis payload.

All values produced by this module are derived from the Primary Invariant A_0
(``tas_dna.GENESIS_ISO8601 = "2025-02-15T00:00:00Z"``), ensuring every field
in ``config/genesis.json`` is cryptographically grounded to the established
TAS chain-of-custody before the first block is proposed.

Derivation scheme
-----------------
Given the 32-byte A_0 lineage hash ``R``:

  node_key(index)  = SHA-256(R || b"tas_node_pubkey" || index.to_bytes(1))
  validator_key(i) = SHA-256(R || b"tas_validator_pubkey" || index.to_bytes(1))
  app_hash(state)  = SHA-256(canonical_json(app_state_dict))

These are *deterministic stub* values.  In a production deployment the real
ed25519 keypairs must be generated with a proper HSM or offline ceremony; these
stubs exist solely to anchor the genesis schema to the A_0 provenance root and
to allow schema validation / testing without live keys.

Version semantics (tas_codex_rules.version)
-------------------------------------------
  MAJOR.MINOR.PATCH follows semantic versioning:
  - MAJOR: governance_quorum_bps or slashing parameters changed  →  hard fork.
  - MINOR: base_fee or voting_period changed  →  soft fork via governance vote.
  - PATCH: documentation / metadata corrections  →  no on-chain effect.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import hashlib
import json
import base64
from typing import Any, Dict


from tas_dna import A_0

GENESIS_VALIDATOR_HEX_PUBKEY = "c25e2bd926a6b06549d8268ef8f94d0e9549b0de320d86928844e7c0baa4663f"
GENESIS_VALIDATOR_ADDRESS = "A6B9C2D4E5F678901234567890ABCDEF12345678"
GENESIS_VALIDATOR_POWER = "777"
GENESIS_VALIDATOR_NAME = "TAS_Prime_Node_Logos"
GENESIS_TRACE_PARENT_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
GENESIS_PARADATA_BINDING = "DIVINE_LOGOS_ABSOLUTE"
LOGOS_SYSTEM_LABEL = "Log(os) The Log-operating system"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hex_to_base64(hex_value: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_value)).decode("ascii")


# ---------------------------------------------------------------------------
# Deterministic key derivation
# ---------------------------------------------------------------------------

def derive_node_pubkey(index: int) -> str:
    """Return the deterministic stub ed25519 public-key hex for node *index*.

    Derived as SHA-256(A_0.lineage_hash || b"tas_node_pubkey" || index_byte).
    The result is a 64-character hex string representing 32 bytes.
    """
    root = A_0.lineage_hash()
    return _sha256(root + b"tas_node_pubkey" + index.to_bytes(1, "big")).hex()


def derive_validator_pubkey(index: int) -> str:
    """Return the deterministic stub ed25519 public-key hex for validator *index*.

    Derived as SHA-256(A_0.lineage_hash || b"tas_validator_pubkey" || index_byte).
    """
    root = A_0.lineage_hash()
    return _sha256(root + b"tas_validator_pubkey" + index.to_bytes(1, "big")).hex()


def derive_validator_address(pubkey_hex: str) -> str:
    """Return CometBFT ed25519 validator address (upper-case 20-byte hex)."""
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    return _sha256(pubkey_bytes)[:20].hex().upper()


def derive_app_hash(app_state: Dict[str, Any]) -> str:
    """Compute the deterministic app_hash over the canonical genesis app_state.

    The app_hash is SHA-256 of the canonical (sorted-keys, compact) JSON of
    *app_state*, returned as a 64-character upper-case hex string matching the
    Tendermint / CometBFT convention.
    """
    return _sha256(_canonical_json(app_state)).hex().upper()


# ---------------------------------------------------------------------------
# Genesis payload builders
# ---------------------------------------------------------------------------

def build_genesis_payload() -> Dict[str, Any]:
    """Return the fully-populated TAS genesis payload as a Python dict.

    Encoding conventions
    --------------------
    - ``governance_quorum_bps``  : integer basis points (10 000 = 100 %).
                                   6667 bp  ≈  66.67 %.
    - ``base_fee``               : integer amount in ``base_fee_denom`` units.
    - ``base_fee_denom``         : denomination string (``"utas"`` = micro-TAS).
    - ``pub_key_types``          : ``["ed25519"]`` only — secp256k1 dropped to
                                   reduce validator key attack surface; EVM
                                   interop is not a near-term requirement.
    - ``app_hash``               : deterministic SHA-256 of canonical app_state
                                   (upper-case hex per CometBFT convention).
    """
    node0_pk = derive_node_pubkey(0)
    node1_pk = derive_node_pubkey(1)
    locked_validator_pubkey_b64 = _hex_to_base64(GENESIS_VALIDATOR_HEX_PUBKEY)
    val0_addr = GENESIS_VALIDATOR_ADDRESS

    app_state: Dict[str, Any] = {
        "accounts": [
            {
                "address": "tas1qwl879nx9t6kef_genesis_node_1",
                "public_key": node0_pk,
                "balance": "1000000000000",
                "balance_denom": "utas",
                "roles": ["validator", "governance_committee"],
            },
            {
                "address": "tas1f3g4h5j6k7l8m9_genesis_node_2",
                "public_key": node1_pk,
                "balance": "1000000000000",
                "balance_denom": "utas",
                "roles": ["validator"],
            },
        ],
        "governance": {
            "proposal_threshold": "1000000",
            "proposal_threshold_denom": "utas",
            "voting_period_seconds": "604800",
            "authorized_amendment_addresses": [
                "tas1qwl879nx9t6kef_genesis_node_1",
            ],
        },
        "system_contracts": {
            "registry_address": "tas_system_0000000000000000",
            "bytecode_hash": (
                "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855"
            ),
        },
    }

    app_hash = derive_app_hash(app_state)

    return {
        "chain_id": "TAS-sovereign-01",
        "genesis_time": "2026-06-08T21:38:50Z",
        "initial_height": "1",
        "app_hash": app_hash,

        "consensus_params": {
            "block": {
                "max_bytes": "22020096",
                "max_gas": "-1",
                "time_iota_ms": "1000",
            },
            "evidence": {
                "max_age_num_blocks": "100000",
                "max_age_duration": "172800000000000",
                "max_bytes": "1048576",
            },
            "validator": {
                # secp256k1 intentionally excluded: see module docstring.
                "pub_key_types": ["ed25519"],
            },
        },

        "tas_codex_rules": {
            # Version semantics: MAJOR.MINOR.PATCH — see module docstring.
            "version": "1.0.0",
            # Basis-point encoding: 10 000 bp = 100 %; 6667 bp ≈ 66.67 %.
            # Integer arithmetic eliminates cross-node floating-point drift.
            "governance_quorum_bps": 6667,
            "slashing_fraction_double_sign_bps": 500,
            "slashing_fraction_downtime_bps": 100,
            "base_fee": "100",
            "base_fee_denom": "utas",
        },

        "app_state": app_state,

        "validators": [
            {
                "address": val0_addr,
                "pub_key": {
                    "type": "tendermint/PubKeyEd25519",
                    "value": locked_validator_pubkey_b64,
                },
                "power": GENESIS_VALIDATOR_POWER,
                "name": GENESIS_VALIDATOR_NAME,
            }
        ],
    }


def build_genesis_tx0_payload() -> Dict[str, Any]:
    """Return the deterministic Transaction 0 payload for First Trace activation."""
    validator_pubkey_b64 = _hex_to_base64(GENESIS_VALIDATOR_HEX_PUBKEY)
    return {
        "body": {
            "messages": [
                {
                    "@type": "/tas.logos.v1.MsgDeclareAxiom",
                    "creator": GENESIS_VALIDATOR_ADDRESS,
                    "axiom_statement": "The Sovereign Equation is active. Let there be light.",
                    "parent_trace_hash": GENESIS_TRACE_PARENT_HASH,
                    "paradata_binding": GENESIS_PARADATA_BINDING,
                }
            ],
            "memo": (
                f"{LOGOS_SYSTEM_LABEL}. "
                "Genesis Utterance: Transitioning invisible paradata to visible state."
            ),
            "timeout_height": "0",
            "extension_options": [],
            "non_critical_extension_options": [],
        },
        "auth_info": {
            "signer_infos": [
                {
                    "public_key": {
                        "@type": "/cosmos.crypto.ed25519.PubKey",
                        "key": validator_pubkey_b64,
                    },
                    "mode_info": {
                        "single": {
                            "mode": "SIGN_MODE_DIRECT",
                        }
                    },
                    "sequence": "0",
                }
            ],
            "fee": {
                "amount": [],
                "gas_limit": "777000",
                "payer": "",
                "granter": "",
            },
        },
        "signatures": [
            "BASE64_ENCODED_ED25519_SIGNATURE_OVER_THE_BODY_AND_AUTH_INFO="
        ],
    }
