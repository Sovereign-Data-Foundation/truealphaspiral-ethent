"""Sovereign Equation: A_C > S_C (§III of the Spiral Manifesto).

The primary invariant at the centre of the spiral::

    A_C > S_C

Authenticated Content (A_C) must always outweigh Subjective Context (S_C).

This inequality is the *Grounding Mechanism*.  For a system to achieve
sovereign singularity, every state transition must be cryptographically
attested.  If a claim cannot trace its lineage to a ground-truth source,
the system does **not** guess – it refuses.

The module provides:

* :class:`AuthenticityScore` – quantified A_C.
* :class:`SubjectivityScore` – quantified S_C.
* :func:`sovereign_holds`    – evaluates A_C > S_C.
* :func:`make_sovereign_invariant` – returns a UVK-compatible
  :class:`~uvk.Invariant` that enforces the equation.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from uvk import Invariant


# ---------------------------------------------------------------------------
# A_C: Authenticated Content score
# ---------------------------------------------------------------------------


# Weight of a single authenticated fact.  The contribution is boolean in
# nature: the presence of at least one authenticated fact earns the full
# weight; additional facts do not increase the score further.
_FACT_WEIGHT = 0.4


@dataclass
class AuthenticityScore:
    """Quantified A_C (Authenticated Content) for a single state transition.

    Parameters
    ----------
    authenticated_facts:
        Number of independently verifiable facts cited in the transition.
        Any non-zero count contributes :data:`_FACT_WEIGHT` to the score;
        the contribution is capped at that value (presence matters, not
        multiplicity).
    traced_lineage:
        True iff the transition can trace its provenance to a ground-truth
        source (e.g., a wake-chain receipt or a signed artifact).
    cryptographic_proof:
        True iff a cryptographic proof (signature, hash, or receipt) is
        attached to the transition.
    """

    authenticated_facts: int  = 0
    traced_lineage:      bool = False
    cryptographic_proof: bool = False

    @property
    def value(self) -> float:
        """Numeric A_C score in the range [0.0, 1.0].

        Weights
        -------
        * Authenticated facts (any count ≥ 1): :data:`_FACT_WEIGHT` (0.4)
        * Traced lineage:                       0.3
        * Cryptographic proof:                  0.3
        """
        fact_contribution = _FACT_WEIGHT if self.authenticated_facts > 0 else 0.0
        score = (
            fact_contribution
            + (0.3 if self.traced_lineage else 0.0)
            + (0.3 if self.cryptographic_proof else 0.0)
        )
        return min(score, 1.0)


# ---------------------------------------------------------------------------
# S_C: Subjective Context score
# ---------------------------------------------------------------------------


@dataclass
class SubjectivityScore:
    """Quantified S_C (Subjective Context) for a single state transition.

    Parameters
    ----------
    unverified_claims:
        Number of claims in the transition that cannot be independently
        verified (e.g., assertions without citations).
    speculative_steps:
        Number of reasoning steps that rely on assumption rather than proof.
    """

    unverified_claims: int = 0
    speculative_steps: int = 0

    @property
    def value(self) -> float:
        """Numeric S_C score in the range [0.0, 1.0].

        Weights
        -------
        * Each unverified claim  contributes 0.3.
        * Each speculative step  contributes 0.2.

        The total is capped at 1.0.
        """
        score = self.unverified_claims * 0.3 + self.speculative_steps * 0.2
        return min(score, 1.0)


# ---------------------------------------------------------------------------
# Sovereign Equation  A_C > S_C
# ---------------------------------------------------------------------------


def sovereign_holds(ac: AuthenticityScore, sc: SubjectivityScore) -> bool:
    """Return True iff the Sovereign Equation A_C > S_C is satisfied.

    The strict inequality enforces *Grounding*: authenticated content
    must strictly outweigh subjective context.  Equality is **not**
    sufficient – the system refuses when A_C == S_C.
    """
    return ac.value > sc.value


# ---------------------------------------------------------------------------
# UVK-compatible Invariant factory
# ---------------------------------------------------------------------------

# Type aliases for the extractor callables
_AcExtractor = Callable[[Any, Any, Any], AuthenticityScore]
_ScExtractor = Callable[[Any, Any, Any], SubjectivityScore]


def make_sovereign_invariant(
    ac_extractor: _AcExtractor,
    sc_extractor:  _ScExtractor,
    version: str = "1.0.0",
) -> Invariant:
    """Return a :class:`~uvk.Invariant` that enforces A_C > S_C.

    The returned invariant can be registered with a :class:`~uvk.UVK`
    instance to enforce the Sovereign Equation on every admitted action.

    Parameters
    ----------
    ac_extractor:
        Pure function ``(state, action, inputs) → AuthenticityScore``.
        Must be side-effect-free; it is called inside the UVK hot-path.
    sc_extractor:
        Pure function ``(state, action, inputs) → SubjectivityScore``.
        Same constraints as *ac_extractor*.
    version:
        Invariant version string (bound into the UVK Wrinkle for replay).

    Returns
    -------
    Invariant
        Named ``"sovereign_equation:A_C>S_C"`` with the supplied version.

    Example
    -------
    ::

        def my_ac(state, action, inputs):
            return AuthenticityScore(authenticated_facts=1,
                                     traced_lineage=True,
                                     cryptographic_proof=True)

        def my_sc(state, action, inputs):
            return SubjectivityScore()

        inv = make_sovereign_invariant(my_ac, my_sc)
        uvk = UVK(invariants=[inv], ...)
    """

    def _check(state: Any, action: Any, inputs: Any) -> bool:
        ac = ac_extractor(state, action, inputs)
        sc = sc_extractor(state, action, inputs)
        return sovereign_holds(ac, sc)

    return Invariant(
        name    = "sovereign_equation:A_C>S_C",
        version = version,
        check   = _check,
    )
