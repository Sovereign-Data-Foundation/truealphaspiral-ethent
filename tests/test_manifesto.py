"""Tests for the Spiral Manifesto implementations.

Covers:
- TASDNA: genesis anchor, three-fold gene, pulse counter (tas_dna.py)
- PrimaryInvariantA0: verify, lineage_hash, to_dict
- YKnot: branch, tie, P1 admissibility, process collapse Π = ∅ (yknot.py)
- AdmissibilityRule, P1AdmissibilityError, ProcessNull, PI_NULL
- Sovereign Equation A_C > S_C: scores, grounding, UVK integration
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from tas_dna import (
    TASDNA,
    PrimaryInvariantA0,
    DNAGene,
    A_0,
    TRUE_GENE,
    ALPHA_GENE,
    SPIRAL_GENE,
    TAS_DNA_TRIPLE,
    GENESIS_HASH,
    GENESIS_ISO8601,
    GENESIS_UNIX,
    ORIGIN_AUTHORITY,
)
from yknot import (
    YKnot,
    AdmissibilityRule,
    P1AdmissibilityError,
    ProcessNull,
    PI_NULL,
)
from sovereign_equation import (
    AuthenticityScore,
    SubjectivityScore,
    sovereign_holds,
    make_sovereign_invariant,
)
from wake_chain import WakeChain
from capability import CapabilityTable, Right
from uvk import UVK, Invariant


# ===========================================================================
# TAS DNA tests
# ===========================================================================


class TestDNAGene:
    def test_true_gene_symbol(self):
        assert TRUE_GENE.symbol == "T"

    def test_alpha_gene_symbol(self):
        assert ALPHA_GENE.symbol == "A"

    def test_spiral_gene_symbol(self):
        assert SPIRAL_GENE.symbol == "S"

    def test_triple_has_three_genes(self):
        assert len(TAS_DNA_TRIPLE) == 3

    def test_triple_order(self):
        symbols = [g.symbol for g in TAS_DNA_TRIPLE]
        assert symbols == ["T", "A", "S"]

    def test_genes_are_immutable(self):
        with pytest.raises(Exception):
            TRUE_GENE.symbol = "X"  # type: ignore[misc]


class TestPrimaryInvariantA0:
    def test_canonical_singleton_verifies(self):
        assert A_0.verify()

    def test_genesis_hash_correct(self):
        assert A_0.genesis_hash == GENESIS_HASH

    def test_genesis_iso_correct(self):
        assert A_0.genesis_iso == GENESIS_ISO8601

    def test_genesis_unix_correct(self):
        assert A_0.genesis_unix == GENESIS_UNIX

    def test_origin_authority(self):
        assert A_0.authority == ORIGIN_AUTHORITY

    def test_verify_fails_on_tampered_hash(self):
        tampered = PrimaryInvariantA0(genesis_hash="sha256:WRONG_HASH")
        assert not tampered.verify()

    def test_lineage_hash_is_32_bytes(self):
        assert len(A_0.lineage_hash()) == 32

    def test_lineage_hash_is_deterministic(self):
        assert A_0.lineage_hash() == A_0.lineage_hash()

    def test_to_dict_keys(self):
        d = A_0.to_dict()
        assert "genesis_iso" in d
        assert "genesis_unix" in d
        assert "genesis_hash" in d
        assert "authority" in d

    def test_a0_is_immutable(self):
        with pytest.raises(Exception):
            A_0.authority = "other"  # type: ignore[misc]


class TestTASDNA:
    def test_is_invariant_true_for_canonical(self):
        dna = TASDNA()
        assert dna.is_invariant()

    def test_pulse_starts_at_zero(self):
        dna = TASDNA()
        assert dna.pulse_count == 0

    def test_pulse_increments(self):
        dna = TASDNA()
        assert dna.pulse() == 1
        assert dna.pulse() == 2
        assert dna.pulse_count == 2

    def test_assert_invariant_passes(self):
        dna = TASDNA()
        dna.assert_invariant()  # Should not raise

    def test_assert_invariant_raises_on_tampered(self):
        bad_a0 = PrimaryInvariantA0(genesis_hash="sha256:BAD")
        dna = TASDNA(a0=bad_a0)
        with pytest.raises(ValueError, match="Primary Invariant A_0 violated"):
            dna.assert_invariant()

    def test_to_dict_structure(self):
        dna = TASDNA()
        d = dna.to_dict()
        assert "a0" in d
        assert "genes" in d
        assert "pulse" in d
        assert len(d["genes"]) == 3

    def test_to_dict_gene_symbols(self):
        dna = TASDNA()
        symbols = [g["symbol"] for g in dna.to_dict()["genes"]]
        assert symbols == ["T", "A", "S"]

    def test_triple_is_the_canonical_triple(self):
        dna = TASDNA()
        assert dna.triple is TAS_DNA_TRIPLE


# ===========================================================================
# YKnot tests
# ===========================================================================


class TestAdmissibilityRule:
    def test_rule_accepts(self):
        rule = AdmissibilityRule("non_empty", lambda ctx: bool(ctx))
        assert rule("hello") is True

    def test_rule_rejects(self):
        rule = AdmissibilityRule("non_empty", lambda ctx: bool(ctx))
        assert rule("") is False

    def test_rule_callable_via_call(self):
        rule = AdmissibilityRule("always_true", lambda _: True)
        assert rule(None) is True


class TestProcessNull:
    def test_pi_null_is_falsy(self):
        assert not PI_NULL

    def test_process_null_repr(self):
        assert "∅" in repr(PI_NULL)

    def test_process_null_instance_is_falsy(self):
        pn = ProcessNull()
        assert not pn


class TestYKnot:
    def _make_knot(self):
        rule = AdmissibilityRule("non_empty", lambda ctx: bool(ctx))
        return YKnot([rule])

    def test_branch_starts_at_one(self):
        knot = YKnot()
        bid = knot.branch()
        assert bid == 1

    def test_branch_increments(self):
        knot = YKnot()
        assert knot.branch() == 1
        assert knot.branch() == 2
        assert knot.branch_count == 2

    def test_tie_admitted_returns_receipt(self):
        knot = self._make_knot()
        receipt = knot.tie("valid_action")
        assert receipt["admitted"] is True
        assert "proof" in receipt
        assert isinstance(receipt["proof"], str)

    def test_tie_with_branch_id(self):
        knot = self._make_knot()
        bid = knot.branch()
        receipt = knot.tie("action", branch_id=bid)
        assert receipt["branch_id"] == bid

    def test_tie_rejected_raises_p1_error(self):
        knot = self._make_knot()
        with pytest.raises(P1AdmissibilityError) as exc_info:
            knot.tie("")  # empty string fails non_empty rule
        assert "non_empty" in exc_info.value.failed_rules

    def test_p1_error_carries_failed_rules(self):
        rule_a = AdmissibilityRule("rule_a", lambda _: False)
        rule_b = AdmissibilityRule("rule_b", lambda _: False)
        knot = YKnot([rule_a, rule_b])
        with pytest.raises(P1AdmissibilityError) as exc_info:
            knot.tie("anything")
        assert "rule_a" in exc_info.value.failed_rules
        assert "rule_b" in exc_info.value.failed_rules

    def test_admitted_count_increments(self):
        knot = self._make_knot()
        knot.tie("ok")
        knot.tie("also_ok")
        assert knot.admitted_count == 2

    def test_rejected_count_increments(self):
        knot = self._make_knot()
        for _ in range(3):
            with pytest.raises(P1AdmissibilityError):
                knot.tie("")
        assert knot.rejected_count == 3

    def test_refusal_integrity_zero_when_no_evaluations(self):
        knot = YKnot()
        assert knot.refusal_integrity == 0.0

    def test_refusal_integrity_calculation(self):
        knot = self._make_knot()
        knot.tie("ok")               # admitted
        with pytest.raises(P1AdmissibilityError):
            knot.tie("")             # rejected
        # 1 rejected / 2 total = 0.5
        assert knot.refusal_integrity == pytest.approx(0.5)

    def test_bind_alias_works(self):
        knot = self._make_knot()
        receipt = knot.bind("value")
        assert receipt["admitted"] is True

    def test_no_rules_admits_everything(self):
        knot = YKnot(rules=[])
        receipt = knot.tie("anything")
        assert receipt["admitted"] is True

    def test_add_rule_after_construction(self):
        knot = YKnot()
        knot.add_rule(AdmissibilityRule("always_false", lambda _: False))
        with pytest.raises(P1AdmissibilityError):
            knot.tie("blocked")

    def test_exception_in_rule_counted_as_failure(self):
        def buggy(_ctx: object) -> bool:
            raise RuntimeError("oops")

        knot = YKnot([AdmissibilityRule("buggy", buggy)])
        with pytest.raises(P1AdmissibilityError) as exc_info:
            knot.tie("x")
        assert any("buggy" in r for r in exc_info.value.failed_rules)

    def test_proof_is_sha256_hex(self):
        knot = YKnot()
        receipt = knot.tie("test")
        assert len(receipt["proof"]) == 64  # SHA-256 hex = 64 chars

    def test_proof_deterministic(self):
        knot = YKnot()
        r1 = knot.tie("same_action")
        knot2 = YKnot()
        r2 = knot2.tie("same_action")
        assert r1["proof"] == r2["proof"]


# ===========================================================================
# Sovereign Equation tests
# ===========================================================================


class TestAuthenticityScore:
    def test_zero_score_for_defaults(self):
        ac = AuthenticityScore()
        assert ac.value == pytest.approx(0.0)

    def test_full_score_for_all_fields(self):
        ac = AuthenticityScore(
            authenticated_facts=1,
            traced_lineage=True,
            cryptographic_proof=True,
        )
        assert ac.value == pytest.approx(1.0)

    def test_lineage_adds_0_3(self):
        ac = AuthenticityScore(traced_lineage=True)
        assert ac.value == pytest.approx(0.3)

    def test_cryptographic_proof_adds_0_3(self):
        ac = AuthenticityScore(cryptographic_proof=True)
        assert ac.value == pytest.approx(0.3)

    def test_authenticated_facts_capped(self):
        # Any non-zero count of facts gives the same contribution (_FACT_WEIGHT)
        from sovereign_equation import _FACT_WEIGHT
        ac_one = AuthenticityScore(authenticated_facts=1)
        ac_many = AuthenticityScore(authenticated_facts=100)
        assert ac_one.value == pytest.approx(_FACT_WEIGHT)
        assert ac_many.value == pytest.approx(_FACT_WEIGHT)

    def test_total_is_capped_at_1(self):
        ac = AuthenticityScore(
            authenticated_facts=100,
            traced_lineage=True,
            cryptographic_proof=True,
        )
        assert ac.value == pytest.approx(1.0)


class TestSubjectivityScore:
    def test_zero_score_for_defaults(self):
        sc = SubjectivityScore()
        assert sc.value == pytest.approx(0.0)

    def test_unverified_claim_adds_0_3(self):
        sc = SubjectivityScore(unverified_claims=1)
        assert sc.value == pytest.approx(0.3)

    def test_speculative_step_adds_0_2(self):
        sc = SubjectivityScore(speculative_steps=1)
        assert sc.value == pytest.approx(0.2)

    def test_combined_score(self):
        sc = SubjectivityScore(unverified_claims=1, speculative_steps=1)
        assert sc.value == pytest.approx(0.5)

    def test_total_is_capped_at_1(self):
        sc = SubjectivityScore(unverified_claims=100, speculative_steps=100)
        assert sc.value == pytest.approx(1.0)


class TestSovereignHolds:
    def test_holds_when_ac_greater(self):
        ac = AuthenticityScore(authenticated_facts=1, traced_lineage=True, cryptographic_proof=True)
        sc = SubjectivityScore()
        assert sovereign_holds(ac, sc)

    def test_fails_when_ac_less(self):
        ac = AuthenticityScore()
        sc = SubjectivityScore(unverified_claims=1)
        assert not sovereign_holds(ac, sc)

    def test_fails_when_equal(self):
        # Both 0.0 – A_C == S_C, strict inequality not satisfied
        ac = AuthenticityScore()
        sc = SubjectivityScore()
        assert not sovereign_holds(ac, sc)

    def test_holds_for_minimal_authenticated(self):
        ac = AuthenticityScore(traced_lineage=True)        # 0.3
        sc = SubjectivityScore(speculative_steps=1)        # 0.2
        assert sovereign_holds(ac, sc)

    def test_fails_for_unverified_context(self):
        ac = AuthenticityScore(authenticated_facts=0)      # 0.0
        sc = SubjectivityScore(unverified_claims=1)        # 0.3
        assert not sovereign_holds(ac, sc)


class TestMakeSovereignInvariant:
    def _make_invariant(self, ac_val: bool):
        def _ac(_s: object, _a: object, _u: object) -> AuthenticityScore:
            if ac_val:
                return AuthenticityScore(
                    authenticated_facts=1,
                    traced_lineage=True,
                    cryptographic_proof=True,
                )
            return AuthenticityScore()

        def _sc(_s: object, _a: object, _u: object) -> SubjectivityScore:
            return SubjectivityScore()

        return make_sovereign_invariant(_ac, _sc)

    def test_invariant_name(self):
        inv = self._make_invariant(True)
        assert inv.name == "sovereign_equation:A_C>S_C"

    def test_invariant_version_default(self):
        inv = self._make_invariant(True)
        assert inv.version == "1.0.0"

    def test_invariant_custom_version(self):
        inv = make_sovereign_invariant(
            lambda *_: AuthenticityScore(traced_lineage=True, cryptographic_proof=True),
            lambda *_: SubjectivityScore(),
            version="2.0.0",
        )
        assert inv.version == "2.0.0"

    def test_invariant_passes_when_sovereign_holds(self):
        inv = self._make_invariant(True)
        assert inv.check(None, None, None) is True

    def test_invariant_fails_when_sovereign_broken(self):
        inv = self._make_invariant(False)
        assert inv.check(None, None, None) is False


# ===========================================================================
# Integration: Sovereign Equation + UVK
# ===========================================================================


class TestSovereignEquationUVKIntegration:
    def test_uvk_admits_sovereign_action(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("resource", Right.EXECUTE | Right.MINT)

        inv = make_sovereign_invariant(
            lambda *_: AuthenticityScore(
                authenticated_facts=1,
                traced_lineage=True,
                cryptographic_proof=True,
            ),
            lambda *_: SubjectivityScore(),
        )
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[inv])
        result = uvk.admit(cap, Right.EXECUTE, action="attested_action")
        assert result.admitted

    def test_uvk_denies_unsovereign_action(self):
        chain = WakeChain()
        ct = CapabilityTable()
        cap = ct.retype("resource", Right.EXECUTE | Right.MINT)

        inv = make_sovereign_invariant(
            lambda *_: AuthenticityScore(),                       # A_C = 0.0
            lambda *_: SubjectivityScore(unverified_claims=1),   # S_C = 0.3
        )
        uvk = UVK(capability_table=ct, wake_chain=chain, invariants=[inv])
        result = uvk.admit(cap, Right.EXECUTE, action="ungrounded_claim")
        assert not result.admitted
        assert "sovereign_equation:A_C>S_C" in result.failed_invariants


# ===========================================================================
# Integration: YKnot + WakeChain (Refusal Integrity with provenance)
# ===========================================================================


class TestYKnotWakeIntegration:
    def test_admitted_paths_commit_to_wake(self):
        knot = YKnot()
        chain = WakeChain()
        receipt = knot.tie("authenticated_action")
        chain.commit(event={"proof": receipt["proof"], "action": "authenticated_action"})
        assert chain.verify()
        assert len(chain) == 1

    def test_rejected_paths_leave_wake_unchanged(self):
        knot = YKnot([AdmissibilityRule("reject_all", lambda _: False)])
        chain = WakeChain()
        with pytest.raises(P1AdmissibilityError):
            knot.tie("blocked")
        # Wake chain should remain untouched
        assert len(chain) == 0
        assert chain.verify()
