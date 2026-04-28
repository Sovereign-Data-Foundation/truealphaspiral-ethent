"""Tests for the Digital Rights Framework.

Covers:
- UnalienableRight: enum values, flag composition, ALL member
- ConsentRecord: construction, proof computation, expiry, to_dict
- ConsentLedger: recording, querying, audit trail, edge cases
- consent_holds: predicate behaviour
- make_consent_invariant: UVK-compatible invariant factory
- Integration: UVK admits/denies based on consent
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time

import pytest

from digital_rights import (
    DECLARATION_PRINCIPLES,
    UnalienableRight,
    ConsentRecord,
    ConsentLedger,
    consent_holds,
    make_consent_invariant,
)
from capability import CapabilityTable, Right
from uvk import UVK
from wake_chain import WakeChain


# ===========================================================================
# DECLARATION_PRINCIPLES constant
# ===========================================================================


class TestDeclarationPrinciples:
    def test_is_non_empty_string(self):
        assert isinstance(DECLARATION_PRINCIPLES, str)
        assert len(DECLARATION_PRINCIPLES) > 0

    def test_references_consent(self):
        assert "consent" in DECLARATION_PRINCIPLES.lower()

    def test_references_liberty(self):
        assert "Liberty" in DECLARATION_PRINCIPLES

    def test_references_accountability(self):
        assert "accountability" in DECLARATION_PRINCIPLES.lower()


# ===========================================================================
# UnalienableRight enum
# ===========================================================================


class TestUnalienableRight:
    def test_access_is_defined(self):
        assert UnalienableRight.ACCESS

    def test_liberty_is_defined(self):
        assert UnalienableRight.LIBERTY

    def test_agency_is_defined(self):
        assert UnalienableRight.AGENCY

    def test_all_combines_three(self):
        assert (UnalienableRight.ALL & UnalienableRight.ACCESS) == UnalienableRight.ACCESS
        assert (UnalienableRight.ALL & UnalienableRight.LIBERTY) == UnalienableRight.LIBERTY
        assert (UnalienableRight.ALL & UnalienableRight.AGENCY) == UnalienableRight.AGENCY

    def test_distinct_values(self):
        values = {
            UnalienableRight.ACCESS.value,
            UnalienableRight.LIBERTY.value,
            UnalienableRight.AGENCY.value,
        }
        assert len(values) == 3

    def test_flag_composition(self):
        combined = UnalienableRight.ACCESS | UnalienableRight.LIBERTY
        assert (combined & UnalienableRight.ACCESS) == UnalienableRight.ACCESS
        assert (combined & UnalienableRight.LIBERTY) == UnalienableRight.LIBERTY
        assert (combined & UnalienableRight.AGENCY) != UnalienableRight.AGENCY


# ===========================================================================
# ConsentRecord
# ===========================================================================


class TestConsentRecord:
    def _make_record(self, **kwargs) -> ConsentRecord:
        """Helper: build a ConsentRecord with sensible defaults."""
        base = ConsentRecord(
            subject_id="user_1",
            rights_granted=UnalienableRight.AGENCY,
            governance_act="data_export",
            timestamp=1_000_000.0,
            expiry=None,
            proof="",
        )
        proof = base.compute_proof()
        defaults = dict(
            subject_id="user_1",
            rights_granted=UnalienableRight.AGENCY,
            governance_act="data_export",
            timestamp=1_000_000.0,
            expiry=None,
            proof=proof,
        )
        defaults.update(kwargs)
        return ConsentRecord(**defaults)

    def test_compute_proof_is_64_char_hex(self):
        rec = self._make_record()
        assert len(rec.compute_proof()) == 64

    def test_is_valid_proof_true_for_fresh_record(self):
        rec = self._make_record()
        assert rec.is_valid_proof()

    def test_is_valid_proof_false_for_tampered_proof(self):
        rec = self._make_record(proof="0" * 64)
        assert not rec.is_valid_proof()

    def test_is_expired_false_when_no_expiry(self):
        rec = self._make_record()
        assert not rec.is_expired()

    def test_is_expired_false_before_expiry(self):
        rec = self._make_record(expiry=9_999_999.0)
        assert not rec.is_expired(at=1_000_000.0)

    def test_is_expired_true_after_expiry(self):
        rec = self._make_record(expiry=500.0)
        assert rec.is_expired(at=1_000.0)

    def test_is_expired_false_at_exact_expiry(self):
        rec = self._make_record(expiry=1_000.0)
        assert not rec.is_expired(at=1_000.0)

    def test_to_dict_has_correct_keys(self):
        rec = self._make_record()
        d = rec.to_dict()
        for key in ("subject_id", "rights_granted", "governance_act",
                    "timestamp", "expiry", "proof"):
            assert key in d

    def test_to_dict_rights_granted_is_integer(self):
        rec = self._make_record()
        assert isinstance(rec.to_dict()["rights_granted"], int)

    def test_record_is_immutable(self):
        rec = self._make_record()
        with pytest.raises(Exception):
            rec.subject_id = "evil"  # type: ignore[misc]

    def test_proof_changes_when_content_changes(self):
        rec_a = self._make_record(governance_act="act_a")
        rec_b = self._make_record(governance_act="act_b")
        assert rec_a.compute_proof() != rec_b.compute_proof()


# ===========================================================================
# ConsentLedger
# ===========================================================================


class TestConsentLedger:
    def test_starts_empty(self):
        ledger = ConsentLedger()
        assert len(ledger) == 0

    def test_record_consent_appends(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.ACCESS, "login")
        assert len(ledger) == 1

    def test_multiple_records_tracked(self):
        ledger = ConsentLedger()
        for i in range(5):
            ledger.record_consent(f"u{i}", UnalienableRight.AGENCY, "act")
        assert len(ledger) == 5

    def test_records_property_returns_snapshot(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.LIBERTY, "audit")
        snap = ledger.records
        assert len(snap) == 1
        # Mutating snapshot should not affect ledger
        snap.clear()
        assert len(ledger) == 1

    def test_recorded_record_has_valid_proof(self):
        ledger = ConsentLedger()
        rec = ledger.record_consent("u1", UnalienableRight.AGENCY, "export")
        assert rec.is_valid_proof()

    def test_find_consent_returns_record(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.AGENCY, "export")
        result = ledger.find_consent("u1", UnalienableRight.AGENCY)
        assert result is not None

    def test_find_consent_none_for_unknown_subject(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.AGENCY, "export")
        assert ledger.find_consent("unknown", UnalienableRight.AGENCY) is None

    def test_find_consent_none_when_expired(self):
        ledger = ConsentLedger()
        ledger.record_consent(
            "u1",
            UnalienableRight.AGENCY,
            "export",
            expiry=100.0,
            timestamp=50.0,
        )
        assert ledger.find_consent("u1", UnalienableRight.AGENCY, at=200.0) is None

    def test_find_consent_valid_before_expiry(self):
        ledger = ConsentLedger()
        ledger.record_consent(
            "u1",
            UnalienableRight.AGENCY,
            "export",
            expiry=1_000.0,
            timestamp=1.0,
        )
        assert ledger.find_consent("u1", UnalienableRight.AGENCY, at=500.0) is not None

    def test_find_consent_none_insufficient_rights(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.ACCESS, "login")
        # Subject only consented to ACCESS; asking for AGENCY should fail
        assert ledger.find_consent("u1", UnalienableRight.AGENCY) is None

    def test_find_consent_subset_rights_accepted(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.ALL, "full_consent")
        # ALL covers ACCESS; finding a record for ACCESS should succeed
        assert ledger.find_consent("u1", UnalienableRight.ACCESS) is not None

    def test_find_consent_none_for_wrong_governance_act(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.AGENCY, "act_a")
        # Consent for act_a must not satisfy a query for act_b (cross-act replay)
        assert ledger.find_consent("u1", UnalienableRight.AGENCY, governance_act="act_b") is None

    def test_find_consent_matches_correct_governance_act(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.AGENCY, "act_a")
        result = ledger.find_consent("u1", UnalienableRight.AGENCY, governance_act="act_a")
        assert result is not None
        assert result.governance_act == "act_a"

    def test_find_consent_returns_most_recent(self):
        ledger = ConsentLedger()
        ledger.record_consent(
            "u1", UnalienableRight.AGENCY, "first_act", timestamp=1.0
        )
        ledger.record_consent(
            "u1", UnalienableRight.AGENCY, "second_act", timestamp=2.0
        )
        result = ledger.find_consent("u1", UnalienableRight.AGENCY)
        assert result is not None
        assert result.governance_act == "second_act"

    def test_find_consent_skips_tampered_records(self):
        ledger = ConsentLedger()
        # Manually inject a tampered record (bad proof)
        tampered = ConsentRecord(
            subject_id="u1",
            rights_granted=UnalienableRight.AGENCY,
            governance_act="tampered",
            timestamp=1.0,
            proof="0" * 64,
        )
        ledger._records.append(tampered)
        assert ledger.find_consent("u1", UnalienableRight.AGENCY) is None

    def test_record_consent_uses_custom_timestamp(self):
        ledger = ConsentLedger()
        rec = ledger.record_consent(
            "u1", UnalienableRight.LIBERTY, "act", timestamp=42.0
        )
        assert rec.timestamp == 42.0


# ===========================================================================
# consent_holds predicate
# ===========================================================================


class TestConsentHolds:
    def test_true_when_valid_consent_exists(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.AGENCY, "export")
        assert consent_holds(ledger, "u1", UnalienableRight.AGENCY)

    def test_false_when_no_consent_recorded(self):
        ledger = ConsentLedger()
        assert not consent_holds(ledger, "u1", UnalienableRight.AGENCY)

    def test_false_when_consent_expired(self):
        ledger = ConsentLedger()
        ledger.record_consent(
            "u1", UnalienableRight.AGENCY, "export",
            expiry=100.0, timestamp=1.0,
        )
        assert not consent_holds(ledger, "u1", UnalienableRight.AGENCY, at=200.0)

    def test_false_when_insufficient_rights(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.ACCESS, "login")
        assert not consent_holds(ledger, "u1", UnalienableRight.LIBERTY)

    def test_true_for_partial_rights_covered_by_all(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.ALL, "full")
        assert consent_holds(ledger, "u1", UnalienableRight.ACCESS)
        assert consent_holds(ledger, "u1", UnalienableRight.LIBERTY)
        assert consent_holds(ledger, "u1", UnalienableRight.AGENCY)

    def test_false_for_wrong_governance_act(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.AGENCY, "export")
        # Consent for "export" must not satisfy a check against "import"
        assert not consent_holds(ledger, "u1", UnalienableRight.AGENCY,
                                 governance_act="import")

    def test_true_for_matching_governance_act(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.AGENCY, "export")
        assert consent_holds(ledger, "u1", UnalienableRight.AGENCY,
                             governance_act="export")


# ===========================================================================
# make_consent_invariant
# ===========================================================================


class TestMakeConsentInvariant:
    def _make_invariant(self, ledger: ConsentLedger, subject_id: str,
                        right: UnalienableRight, governance_act: str = "test_act"):
        def extractor(_s, _a, _u):
            return subject_id, right, governance_act

        return make_consent_invariant(ledger, extractor)

    def test_invariant_name(self):
        ledger = ConsentLedger()
        inv = self._make_invariant(ledger, "u1", UnalienableRight.AGENCY)
        assert inv.name == "digital_rights:consent_required"

    def test_invariant_default_version(self):
        ledger = ConsentLedger()
        inv = self._make_invariant(ledger, "u1", UnalienableRight.AGENCY)
        assert inv.version == "1.0.0"

    def test_invariant_custom_version(self):
        ledger = ConsentLedger()
        inv = make_consent_invariant(
            ledger,
            lambda *_: ("u1", UnalienableRight.AGENCY, "test_act"),
            version="2.0.0",
        )
        assert inv.version == "2.0.0"

    def test_invariant_passes_when_consent_exists(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.AGENCY, "export")
        inv = self._make_invariant(ledger, "u1", UnalienableRight.AGENCY, "export")
        assert inv.check(None, None, None) is True

    def test_invariant_fails_when_no_consent(self):
        ledger = ConsentLedger()
        inv = self._make_invariant(ledger, "u1", UnalienableRight.AGENCY)
        assert inv.check(None, None, None) is False

    def test_invariant_fails_when_consent_expired(self):
        ledger = ConsentLedger()
        ledger.record_consent(
            "u1", UnalienableRight.AGENCY, "export",
            expiry=100.0, timestamp=1.0,
        )
        inv = self._make_invariant(ledger, "u1", UnalienableRight.AGENCY, "export")
        # The invariant calls consent_holds with current time, which is > 100.0
        assert inv.check(None, None, None) is False

    def test_invariant_fails_for_wrong_governance_act(self):
        ledger = ConsentLedger()
        ledger.record_consent("u1", UnalienableRight.AGENCY, "export")
        # Extractor requests "import" but consent is only on record for "export"
        inv = self._make_invariant(ledger, "u1", UnalienableRight.AGENCY, "import")
        assert inv.check(None, None, None) is False

    def test_invariant_uses_injected_clock_before_expiry(self):
        ledger = ConsentLedger()
        ledger.record_consent(
            "u1", UnalienableRight.AGENCY, "export",
            expiry=500.0, timestamp=1.0,
        )
        # Injected clock returns a time before expiry → consent is valid
        inv = make_consent_invariant(
            ledger,
            lambda *_: ("u1", UnalienableRight.AGENCY, "export"),
            clock=lambda: 250.0,
        )
        assert inv.check(None, None, None) is True

    def test_invariant_uses_injected_clock_after_expiry(self):
        ledger = ConsentLedger()
        ledger.record_consent(
            "u1", UnalienableRight.AGENCY, "export",
            expiry=500.0, timestamp=1.0,
        )
        # Injected clock returns a time after expiry → consent is invalid
        inv = make_consent_invariant(
            ledger,
            lambda *_: ("u1", UnalienableRight.AGENCY, "export"),
            clock=lambda: 600.0,
        )
        assert inv.check(None, None, None) is False


# ===========================================================================
# Integration: Digital Rights Invariant + UVK
# ===========================================================================


class TestDigitalRightsUVKIntegration:
    def test_uvk_admits_when_consent_exists(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("personal_data", Right.READ | Right.EXECUTE | Right.MINT)

        ledger = ConsentLedger()
        ledger.record_consent("user_a", UnalienableRight.AGENCY, "personal_data_read")

        inv = make_consent_invariant(
            ledger,
            lambda *_: ("user_a", UnalienableRight.AGENCY, "personal_data_read"),
        )
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[inv])
        result = uvk.admit(cap, Right.READ, action="read_personal_data")
        assert result.admitted

    def test_uvk_denies_when_no_consent(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("personal_data", Right.READ | Right.EXECUTE | Right.MINT)

        ledger = ConsentLedger()  # empty – no consent recorded

        inv = make_consent_invariant(
            ledger,
            lambda *_: ("user_b", UnalienableRight.AGENCY, "personal_data_read"),
        )
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[inv])
        result = uvk.admit(cap, Right.READ, action="read_without_consent")
        assert not result.admitted
        assert "digital_rights:consent_required" in result.failed_invariants

    def test_uvk_denies_after_consent_expires(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("resource", Right.EXECUTE | Right.MINT)

        ledger = ConsentLedger()
        # Record a consent that has already expired at a past timestamp
        ledger.record_consent(
            "user_c",
            UnalienableRight.ACCESS,
            "expired_act",
            expiry=1.0,       # far in the past
            timestamp=0.5,
        )

        inv = make_consent_invariant(
            ledger,
            lambda *_: ("user_c", UnalienableRight.ACCESS, "expired_act"),
        )
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[inv])
        result = uvk.admit(cap, Right.EXECUTE, action="expired_consent_action")
        assert not result.admitted
        assert "digital_rights:consent_required" in result.failed_invariants

    def test_uvk_denies_when_governance_act_mismatched(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("resource", Right.READ | Right.MINT)

        ledger = ConsentLedger()
        ledger.record_consent("user_d", UnalienableRight.AGENCY, "export_act")

        # Invariant requests consent for "import_act"; cross-act replay must fail
        inv = make_consent_invariant(
            ledger,
            lambda *_: ("user_d", UnalienableRight.AGENCY, "import_act"),
        )
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[inv])
        result = uvk.admit(cap, Right.READ, action="cross_act_attempt")
        assert not result.admitted
        assert "digital_rights:consent_required" in result.failed_invariants

    def test_multiple_subjects_independent_consent(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap_a = ct.retype("resource_a", Right.READ | Right.MINT)
        cap_b = ct.retype("resource_b", Right.READ | Right.MINT)

        ledger = ConsentLedger()
        ledger.record_consent("alice", UnalienableRight.LIBERTY, "alice_read")
        # bob has NOT consented

        inv_alice = make_consent_invariant(
            ledger,
            lambda *_: ("alice", UnalienableRight.LIBERTY, "alice_read"),
        )
        inv_bob = make_consent_invariant(
            ledger,
            lambda *_: ("bob", UnalienableRight.LIBERTY, "bob_read"),
        )

        uvk_alice = UVK(
            capability_table=ct,
            wake_chain=WakeChain(),
            invariants=[inv_alice],
        )
        uvk_bob = UVK(
            capability_table=ct,
            wake_chain=WakeChain(),
            invariants=[inv_bob],
        )

        assert uvk_alice.admit(cap_a, Right.READ, action="alice_action").admitted
        assert not uvk_bob.admit(cap_b, Right.READ, action="bob_action").admitted
