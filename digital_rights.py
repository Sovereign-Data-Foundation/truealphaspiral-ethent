# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0
"""
Digital rights framework.

Provides a minimal but complete framework for recording and querying subject
consent in alignment with the TrueAlphaSpiral (TAS) accountability model.
Rights are represented as :class:`UnalienableRight` flag values and consent
records are maintained in a :class:`ConsentLedger`.

An :class:`uvk.Invariant` factory (:func:`make_consent_invariant`) allows
consent checks to be composed directly into the UVK admission pipeline.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Flag, auto
from typing import Callable, Dict, List, Optional, Tuple

from uvk import Invariant


# ---------------------------------------------------------------------------
# Preamble
# ---------------------------------------------------------------------------

PREAMBLE: str = (
    "Every individual retains inalienable digital rights: the right to privacy "
    "in their data, transparency in how it is used, meaningful consent over its "
    "collection and processing, portability to move it freely, redress when it is "
    "misused, and autonomy to govern their own digital identity. "
    "The TrueAlphaSpiral accountability framework commits to upholding these "
    "rights in every operation, audit trail, and governance decision."
)


# ---------------------------------------------------------------------------
# Rights
# ---------------------------------------------------------------------------


class UnalienableRight(Flag):
    """Inalienable digital rights that subjects may grant or withhold.

    Attributes:
        PRIVACY:      Right to privacy in personal data.
        TRANSPARENCY: Right to know how data is used.
        CONSENT:      Right to meaningful informed consent.
        PORTABILITY:  Right to move data freely across systems.
        REDRESS:      Right to seek remedy for misuse.
        AUTONOMY:     Right to govern one's own digital identity.
    """

    PRIVACY = auto()
    TRANSPARENCY = auto()
    CONSENT = auto()
    PORTABILITY = auto()
    REDRESS = auto()
    AUTONOMY = auto()


# ---------------------------------------------------------------------------
# ConsentRecord
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConsentRecord:
    """An immutable record of a subject's consent grant.

    Attributes:
        subject_id:     Opaque identifier for the consenting subject.
        rights_granted: The :class:`UnalienableRight` flags covered by this
                        consent.
        governance_act: Optional reference to the governing policy or law.
        granted_at:     Unix epoch when consent was granted.
        expires_at:     Optional Unix epoch when consent expires.  ``None``
                        means the consent does not expire.
    """

    subject_id: str
    rights_granted: UnalienableRight
    governance_act: Optional[str] = None
    granted_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None

    def is_valid(self, at: Optional[float] = None) -> bool:
        """Return ``True`` if this record has not yet expired.

        Args:
            at: Optional timestamp to check against.  Defaults to
                ``time.time()``.
        """
        check_time = at if at is not None else time.time()
        if self.expires_at is not None and check_time > self.expires_at:
            return False
        return True


# ---------------------------------------------------------------------------
# ConsentLedger
# ---------------------------------------------------------------------------


class ConsentLedger:
    """Mutable store of :class:`ConsentRecord` objects.

    Records may be granted, revoked (removed), or queried.  Revocation removes
    all matching records for a subject's specified rights so that subsequent
    queries return ``None``.
    """

    def __init__(self) -> None:
        self._records: List[ConsentRecord] = []

    def grant(
        self,
        subject_id: str,
        rights: UnalienableRight,
        governance_act: Optional[str] = None,
        expires_at: Optional[float] = None,
    ) -> ConsentRecord:
        """Record a new consent grant and return the created :class:`ConsentRecord`.

        Args:
            subject_id:      Subject granting consent.
            rights:          :class:`UnalienableRight` flags being granted.
            governance_act:  Optional policy or law reference.
            expires_at:      Optional expiry timestamp.
        """
        record = ConsentRecord(
            subject_id=subject_id,
            rights_granted=rights,
            governance_act=governance_act,
            expires_at=expires_at,
        )
        self._records.append(record)
        return record

    def revoke(self, subject_id: str, rights: UnalienableRight) -> None:
        """Remove all records for *subject_id* that cover *rights*.

        Args:
            subject_id: Subject whose consent is being revoked.
            rights:     :class:`UnalienableRight` flags to revoke.
        """
        self._records = [
            r
            for r in self._records
            if not (r.subject_id == subject_id and bool(r.rights_granted & rights))
        ]

    def query(
        self,
        subject_id: str,
        rights: UnalienableRight,
        at: Optional[float] = None,
    ) -> Optional[ConsentRecord]:
        """Return a valid :class:`ConsentRecord` that covers *rights* for *subject_id*.

        The first matching, non-expired record is returned.  Returns ``None``
        if no such record exists.

        Args:
            subject_id: Subject to query for.
            rights:     Required :class:`UnalienableRight` flags.
            at:         Optional timestamp for expiry checking.
        """
        for record in self._records:
            if (
                record.subject_id == subject_id
                and bool(record.rights_granted & rights)
                and record.is_valid(at)
            ):
                return record
        return None

    @property
    def records(self) -> List[ConsentRecord]:
        """Snapshot copy of all records in this ledger."""
        return list(self._records)


# ---------------------------------------------------------------------------
# Consent check helper
# ---------------------------------------------------------------------------


def consent_holds(
    ledger: ConsentLedger,
    subject_id: str,
    required_rights: UnalienableRight,
    governance_act: Optional[str] = None,
    at: Optional[float] = None,
) -> bool:
    """Return ``True`` if a valid consent record covering *required_rights* exists.

    Args:
        ledger:          The :class:`ConsentLedger` to query.
        subject_id:      Subject whose consent is being checked.
        required_rights: :class:`UnalienableRight` flags that must be granted.
        governance_act:  If provided, the record must also reference this act.
        at:              Optional timestamp for expiry checking.
    """
    record = ledger.query(subject_id, required_rights, at=at)
    if record is None:
        return False
    if governance_act is not None and record.governance_act != governance_act:
        return False
    return True


# ---------------------------------------------------------------------------
# UVK-compatible Invariant factory
# ---------------------------------------------------------------------------

_SubjectExtractor = Callable[[object, object, object], Tuple[str, UnalienableRight, str]]
"""Type alias for callables that extract ``(subject_id, required_rights, governance_act)``
from the ``(state, action, inputs)`` triple passed to a UVK invariant predicate."""


def make_consent_invariant(
    ledger: ConsentLedger,
    extractor: _SubjectExtractor,
    name: str = "consent_invariant",
) -> Invariant:
    """Create a :class:`uvk.Invariant` that enforces consent via *ledger*.

    The returned invariant's predicate calls
    ``extractor(state, action, inputs)`` to obtain a
    ``(subject_id, required_rights, governance_act)`` triple, then delegates
    to :func:`consent_holds`.

    Args:
        ledger:    :class:`ConsentLedger` used for consent lookups.
        extractor: Callable that maps ``(state, action, inputs)`` to
                   ``(subject_id, required_rights, governance_act)``.
        name:      Human-readable name for the resulting invariant.

    Returns:
        An :class:`uvk.Invariant` ready to be registered with a :class:`uvk.UVK`.
    """

    def _predicate(state: object, action: object, inputs: object) -> bool:
        subject_id, required_rights, governance_act = extractor(state, action, inputs)
        return consent_holds(
            ledger,
            subject_id=subject_id,
            required_rights=required_rights,
            governance_act=governance_act or None,
        )

    return Invariant(name=name, predicate=_predicate)
