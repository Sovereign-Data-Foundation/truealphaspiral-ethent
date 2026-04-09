"""Y-Knot Boundary Operator (§IV of the Spiral Manifesto).

Implements Refusal Integrity at the execution layer:

    Branching (Y):  The open action space of potential intelligence –
                    all candidate paths that could be taken.
    Tying (Knot):   The moment a specific path is bound to proof –
                    the P1 admissibility gate.

If a candidate path fails *P1 Admissibility*, the process collapses::

    Π = ∅

The system is therefore defined not by what it *can* generate, but by
what it has the power to *reject* (Refusal Integrity).

Usage::

    knot = YKnot([AdmissibilityRule("non_empty", lambda ctx: bool(ctx))])
    bid  = knot.branch()
    try:
        receipt = knot.tie("my action", branch_id=bid)
    except P1AdmissibilityError as err:
        # path collapsed → Π = ∅
        ...
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional


# ---------------------------------------------------------------------------
# P1 Admissibility rule
# ---------------------------------------------------------------------------

AdmissibilityFn = Callable[[Any], bool]
"""Predicate (context) → bool.  Must be pure and side-effect-free."""


@dataclass
class AdmissibilityRule:
    """A named P1 admissibility predicate.

    Parameters
    ----------
    name:
        Human-readable identifier for this rule.
    check:
        Pure function (context) → bool.  Returns True iff the context
        satisfies this admissibility condition.
    """

    name:  str
    check: AdmissibilityFn

    def __call__(self, context: Any) -> bool:
        return self.check(context)


# ---------------------------------------------------------------------------
# Process collapse sentinel  Π = ∅
# ---------------------------------------------------------------------------


class P1AdmissibilityError(Exception):
    """Raised when a path fails P1 Admissibility (Π = ∅).

    Attributes
    ----------
    failed_rules:
        Names of the rules that rejected the candidate path.
    """

    def __init__(self, failed_rules: List[str]) -> None:
        self.failed_rules = failed_rules
        super().__init__(
            f"Path inadmissible – Π = ∅  (failed rules: {failed_rules})"
        )


class ProcessNull:
    """Represents the collapsed process (Π = ∅).

    This sentinel is returned when a path collapses without raising
    (i.e., when the caller inspects the result rather than catching the
    exception).  It is always falsy.
    """

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "Π=∅"


PI_NULL = ProcessNull()


# ---------------------------------------------------------------------------
# YKnot
# ---------------------------------------------------------------------------


class YKnot:
    """Y-Knot Boundary Operator.

    Enforces Refusal Integrity by running every candidate path through a
    set of P1 admissibility rules before binding it to proof.

    Parameters
    ----------
    rules:
        Initial list of :class:`AdmissibilityRule` predicates.

    Typical workflow
    ----------------
    1. Register :class:`AdmissibilityRule` instances via the constructor or
       :meth:`add_rule`.
    2. Call :meth:`branch` to open a candidate path.
    3. Call :meth:`tie` to attempt to bind the path to proof.

       * If all P1 rules pass, a proof-binding receipt dict is returned.
       * If any rule fails, :class:`P1AdmissibilityError` is raised and
         the path collapses (Π = ∅).
    """

    def __init__(self, rules: Optional[List[AdmissibilityRule]] = None) -> None:
        self._rules:    List[AdmissibilityRule] = list(rules or [])
        self._branches: int                     = 0
        self._admitted: int                     = 0
        self._rejected: int                     = 0

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, rule: AdmissibilityRule) -> None:
        """Register an additional P1 admissibility rule."""
        self._rules.append(rule)

    # ------------------------------------------------------------------
    # Branching (Y)
    # ------------------------------------------------------------------

    def branch(self) -> int:
        """Open a new candidate path.

        Returns
        -------
        int
            A monotone branch identifier (starts at 1).
        """
        self._branches += 1
        return self._branches

    # ------------------------------------------------------------------
    # Tying (The Knot) = P1 gate
    # ------------------------------------------------------------------

    def tie(self, context: Any, branch_id: Optional[int] = None) -> Dict[str, Any]:
        """Attempt to bind *context* to proof via all registered P1 rules.

        Parameters
        ----------
        context:
            The candidate action or claim to evaluate.
        branch_id:
            The branch identifier returned by :meth:`branch` (informational).

        Returns
        -------
        dict
            Receipt with keys ``admitted``, ``branch_id``, and ``proof``
            (SHA-256 hex digest of the canonicalised context).

        Raises
        ------
        P1AdmissibilityError
            If any P1 rule rejects *context* (Π = ∅).
        """
        failed: List[str] = []
        for rule in self._rules:
            try:
                if not rule(context):
                    failed.append(rule.name)
            except Exception as exc:
                failed.append(f"{rule.name}[error:{exc}]")

        if failed:
            self._rejected += 1
            raise P1AdmissibilityError(failed)

        self._admitted += 1
        try:
            canonical = json.dumps(context, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            canonical = str(context)
        proof = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return {
            "admitted":  True,
            "branch_id": branch_id,
            "proof":     proof,
        }

    def bind(self, context: Any, branch_id: Optional[int] = None) -> Dict[str, Any]:
        """Convenience alias for :meth:`tie`."""
        return self.tie(context, branch_id)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    @property
    def branch_count(self) -> int:
        """Total number of candidate paths opened via :meth:`branch`."""
        return self._branches

    @property
    def admitted_count(self) -> int:
        """Number of paths admitted through the knot."""
        return self._admitted

    @property
    def rejected_count(self) -> int:
        """Number of paths that collapsed (Π = ∅)."""
        return self._rejected

    @property
    def refusal_integrity(self) -> float:
        """Fraction of evaluated paths that were rejected.

        A system with strong Refusal Integrity will have a non-zero
        rejection rate when presented with inadmissible paths.
        Returns 0.0 when no paths have been evaluated.
        """
        total = self._admitted + self._rejected
        return self._rejected / total if total else 0.0
