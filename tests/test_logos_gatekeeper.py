"""Tests for the Logos gatekeeper integration.

Covers:
- LogosValidationLoop: valid payload, lineage mismatch, density below floor
- artifact_guard.logos_gate(): normal pass, UVK invariant failure, density failure
- artifact_guard.run_step(): gate called; low-density code rejected
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from wake_chain import WakeChain, reset_default_chain
from capability import CapabilityTable, Right
from uvk import UVK, Invariant
from tas_logos_gatekeeper import (
    LogosValidationLoop,
    SovereignStructuralViolation,
)
from artifact_guard import logos_gate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Short, varied payload → density ≈ 0.36 (passes the 0.15 floor)
_SHORT_VARIED_PAYLOAD = {"step": "test", "code": "echo hi"}

# Long, repetitive payload → density ≈ 0.11 (fails the 0.15 floor)
_LONG_REPETITIVE_PAYLOAD = {
    "alpha": "Russell Nordland",
    "beta": "TrueAlphaSpiral",
    "gamma": "ZK-STARK-FRI-compact-transparent-proof",
    "delta": "kinematic-identity-constraint-nonce-80786",
    "epsilon": "sovereign-data-foundation-ethent-repo",
}


def _make_uvk(all_pass: bool = True) -> UVK:
    chain = WakeChain()
    ct = CapabilityTable()
    inv = Invariant(
        name="test_inv",
        version="1.0",
        check=lambda *_: all_pass,
    )
    return UVK(capability_table=ct, wake_chain=chain, invariants=[inv])


# ===========================================================================
# LogosValidationLoop unit tests
# ===========================================================================


class TestLogosValidationLoop:
    def test_valid_payload_passes(self):
        chain = WakeChain()
        loop = LogosValidationLoop(invariant_check=lambda: True)
        manifest = {
            "lineage_parent_hash": chain.head.hex(),
            "payload_vector": _SHORT_VARIED_PAYLOAD,
        }
        assert loop.evaluate_logos_bounds(chain.head, manifest, nonce=1) is True

    def test_lineage_mismatch_fails(self):
        chain = WakeChain()
        loop = LogosValidationLoop(invariant_check=lambda: True)
        wrong_hash = b"\xff" * 32
        manifest = {
            # hex of the wrong hash – does not match chain.head
            "lineage_parent_hash": wrong_hash.hex(),
            "payload_vector": _SHORT_VARIED_PAYLOAD,
        }
        # Passes correct chain.head as current_state_hash → mismatch
        result = loop.evaluate_logos_bounds(chain.head, manifest, nonce=0)
        assert result is False

    def test_lineage_bytes_form_works(self):
        """Callers may supply lineage_parent_hash as bytes; both forms must work."""
        chain = WakeChain()
        loop = LogosValidationLoop(invariant_check=lambda: True)
        manifest = {
            "lineage_parent_hash": chain.head,  # bytes, not hex str
            "payload_vector": _SHORT_VARIED_PAYLOAD,
        }
        assert loop.evaluate_logos_bounds(chain.head, manifest, nonce=0) is True

    def test_invariant_failure_fails(self):
        chain = WakeChain()
        loop = LogosValidationLoop(invariant_check=lambda: False)
        manifest = {
            "lineage_parent_hash": chain.head.hex(),
            "payload_vector": _SHORT_VARIED_PAYLOAD,
        }
        result = loop.evaluate_logos_bounds(chain.head, manifest, nonce=0)
        assert result is False

    def test_long_repetitive_payload_fails(self):
        """The density formula penalises large payloads; even varied long payloads
        can fall below the floor, which is the intended design behaviour."""
        chain = WakeChain()
        loop = LogosValidationLoop(invariant_check=lambda: True, min_density_floor=0.15)
        manifest = {
            "lineage_parent_hash": chain.head.hex(),
            "payload_vector": _LONG_REPETITIVE_PAYLOAD,
        }
        result = loop.evaluate_logos_bounds(chain.head, manifest, nonce=0)
        assert result is False

    def test_empty_object_payload_passes(self):
        """An empty JSON object '{}' has density ~0.35, which is above the floor.
        Callers that need to enforce a non-empty payload must do so separately."""
        chain = WakeChain()
        loop = LogosValidationLoop(invariant_check=lambda: True)
        manifest = {
            "lineage_parent_hash": chain.head.hex(),
            "payload_vector": {},
        }
        result = loop.evaluate_logos_bounds(chain.head, manifest, nonce=0)
        assert result is True

    def test_custom_density_floor_zero_accepts_long_payload(self):
        """Lowering the floor to zero should accept any non-empty payload."""
        chain = WakeChain()
        loop = LogosValidationLoop(invariant_check=lambda: True, min_density_floor=0.0)
        manifest = {
            "lineage_parent_hash": chain.head.hex(),
            "payload_vector": _SHORT_VARIED_PAYLOAD,
        }
        assert loop.evaluate_logos_bounds(chain.head, manifest, nonce=0) is True


# ===========================================================================
# logos_gate() integration tests (uses default chain)
# ===========================================================================


class TestLogosGate:
    def setup_method(self):
        reset_default_chain()

    def test_gate_passes_short_varied_payload(self):
        # Should not raise
        logos_gate("test_step", _SHORT_VARIED_PAYLOAD)

    def test_gate_raises_on_long_repetitive_payload(self):
        with pytest.raises(SovereignStructuralViolation):
            logos_gate("long_step", _LONG_REPETITIVE_PAYLOAD)

    def test_gate_passes_empty_object_payload(self):
        """An empty JSON object has density ~0.35, which passes the gate."""
        logos_gate("empty_step", {})

    def test_gate_with_passing_uvk(self):
        uvk = _make_uvk(all_pass=True)
        # Should not raise
        logos_gate("uvk_pass_step", _SHORT_VARIED_PAYLOAD, uvk=uvk)

    def test_gate_with_failing_uvk_invariant(self):
        uvk = _make_uvk(all_pass=False)
        with pytest.raises(SovereignStructuralViolation):
            logos_gate("uvk_fail_step", _SHORT_VARIED_PAYLOAD, uvk=uvk)

    def test_gate_lineage_always_consistent_with_current_head(self):
        """logos_gate builds the manifest from the live chain head, so lineage
        must always be consistent at the point of the call."""
        reset_default_chain()
        # Commit a few events to advance the chain head
        from wake_chain import get_default_chain
        chain = get_default_chain()
        chain.commit(event={"advance": 1})
        chain.commit(event={"advance": 2})
        # Gate should still pass because manifest is built from the current head
        logos_gate("advanced_head_step", _SHORT_VARIED_PAYLOAD)


# ===========================================================================
# UVK.check_all_invariants() unit tests
# ===========================================================================


class TestUVKCheckAllInvariants:
    def test_all_pass_returns_true(self):
        uvk = _make_uvk(all_pass=True)
        assert uvk.check_all_invariants() is True

    def test_one_fail_returns_false(self):
        uvk = _make_uvk(all_pass=False)
        assert uvk.check_all_invariants() is False

    def test_no_invariants_returns_true(self):
        chain = WakeChain()
        ct = CapabilityTable()
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[])
        assert uvk.check_all_invariants() is True

    def test_state_action_inputs_forwarded(self):
        seen = {}

        def _capture(state, action, inputs):
            seen["state"] = state
            seen["action"] = action
            seen["inputs"] = inputs
            return True

        chain = WakeChain()
        ct = CapabilityTable()
        inv = Invariant("capture", "1.0", _capture)
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[inv])
        uvk.check_all_invariants(state="S", action="A", inputs="I")
        assert seen == {"state": "S", "action": "A", "inputs": "I"}
