# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0
"""
Y-Knot Boundary Operator (§IV of the Spiral Manifesto).

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

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class P1AdmissibilityError(Exception):
    """Raised when a candidate path fails the P1 admissibility gate.

    The path has collapsed: Π = ∅.
    """


# ---------------------------------------------------------------------------
# AdmissibilityRule
# ---------------------------------------------------------------------------


@dataclass
class AdmissibilityRule:
    """A named, single-predicate admissibility gate.

    Attributes:
        name:      Human-readable identifier for this rule.
        predicate: Callable that receives a context object and returns
                   ``True`` iff the candidate path is admissible under this
                   rule.
    """

    name: str
    predicate: Callable[[Any], bool]

    def check(self, ctx: Any) -> bool:
        """Evaluate *predicate* against *ctx*.

        Args:
            ctx: The context object to evaluate.

        Returns:
            ``True`` if the path is admissible under this rule.
        """
        return bool(self.predicate(ctx))


# ---------------------------------------------------------------------------
# YKnot
# ---------------------------------------------------------------------------


class YKnot:
    """Y-Knot Boundary Operator – applies P1 admissibility gates to candidate paths.

    Args:
        rules: Initial list of :class:`AdmissibilityRule` objects.  Additional
               rules may be added later via :meth:`add_rule`.
    """

    def __init__(self, rules: Optional[List[AdmissibilityRule]] = None) -> None:
        self._rules: List[AdmissibilityRule] = list(rules) if rules else []
        self._branch_counter: int = 0
        self._admitted: int = 0
        self._rejected: int = 0

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def add_rule(self, rule: AdmissibilityRule) -> None:
        """Append *rule* to the set of P1 admissibility gates.

        Args:
            rule: The :class:`AdmissibilityRule` to add.
        """
        self._rules.append(rule)

    # ------------------------------------------------------------------
    # Branching
    # ------------------------------------------------------------------

    def branch(self) -> int:
        """Open a new candidate path and return its monotone branch ID.

        Branch IDs start at 1 and increment with each call.

        Returns:
            A positive integer uniquely identifying this candidate path.
        """
        self._branch_counter += 1
        return self._branch_counter

    # ------------------------------------------------------------------
    # Tying
    # ------------------------------------------------------------------

    def tie(self, action: Any, branch_id: int, ctx: Any = None) -> Dict[str, Any]:
        """Bind *action* to proof by running all P1 admissibility gates.

        The context evaluated by each rule is *ctx* when provided, otherwise
        *action* is used directly.

        Args:
            action:    The candidate action to bind.
            branch_id: Branch identifier returned by a prior :meth:`branch` call.
            ctx:       Explicit context for rule evaluation.  Defaults to
                       *action* when ``None``.

        Returns:
            A receipt dict with keys: ``branch_id``, ``action``,
            ``admitted=True``, ``rules_passed`` (list of rule names).

        Raises:
            P1AdmissibilityError: If any rule's predicate returns ``False``.
                                  The candidate path has collapsed: Π = ∅.
        """
        eval_ctx = ctx if ctx is not None else action
        failed_rules: List[str] = []
        passed_rules: List[str] = []

        for rule in self._rules:
            if rule.check(eval_ctx):
                passed_rules.append(rule.name)
            else:
                failed_rules.append(rule.name)

        if failed_rules:
            self._rejected += 1
            raise P1AdmissibilityError(
                f"P1 admissibility failed for branch {branch_id!r} "
                f"on rules: {failed_rules!r} – path collapsed: Π = ∅"
            )

        self._admitted += 1
        return {
            "branch_id": branch_id,
            "action": action,
            "admitted": True,
            "rules_passed": passed_rules,
        }

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def refusal_integrity(self) -> float:
        """Fraction of evaluated paths (tie calls) that were rejected.

        Returns ``0.0`` when no paths have been evaluated yet.
        """
        total = self._admitted + self._rejected
        if total == 0:
            return 0.0
        return self._rejected / total

    @property
    def branches(self) -> int:
        """Total number of candidate paths opened via :meth:`branch`."""
        return self._branch_counter

    @property
    def admitted(self) -> int:
        """Total number of paths that passed all P1 admissibility gates."""
        return self._admitted

    @property
    def rejected(self) -> int:
        """Total number of paths that failed at least one P1 admissibility gate."""
        return self._rejected
