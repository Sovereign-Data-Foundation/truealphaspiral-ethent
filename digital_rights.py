"""Digital Rights Framework – Declaration Principles in the Digital Sphere.

Grounded in the foundational assertion that every individual holds unalienable
digital rights analogous to those declared in 1776:

    Life      → Persistent digital existence and access (ACCESS).
    Liberty   → Freedom from coercive surveillance and control (LIBERTY).
    Happiness → Autonomous agency over personal data and systems (AGENCY).

The legitimacy of any digital governance system derives solely from the
*informed consent* of those it serves.  When a system becomes destructive
of these ends it is the right – and duty – of participants to demand
accountability and reform.

This module provides:

* :class:`UnalienableRight`      – enumerated digital rights that may not be
  revoked without explicit informed consent.
* :class:`ConsentRecord`         – cryptographically bound record of a
  subject's informed consent to a specific digital governance act.
* :class:`ConsentLedger`         – append-only ledger of consent records
  subject to public audit.
* :func:`consent_holds`          – predicate: does a governance act carry
  valid, unexpired, informed consent?
* :func:`make_consent_invariant` – returns a UVK-compatible
  :class:`~uvk.Invariant` that enforces consent requirements on every
  admitted action.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from enum import Flag, auto
from typing import Any, Callable, Dict, List, Optional, Tuple

from uvk import Invariant


# ---------------------------------------------------------------------------
# Declaration of Principles
# ---------------------------------------------------------------------------

DECLARATION_PRINCIPLES: str = (
    "We hold these truths to be self-evident: that every individual holds "
    "unalienable digital rights – to persistent existence and access (Life), "
    "to freedom from coercive surveillance and control (Liberty), and to "
    "autonomous agency over their own data and systems (Pursuit of Happiness). "
    "That to secure these rights, digital governance systems are instituted among "
    "people, deriving their just powers from the informed consent of those they "
    "serve. Whenever any digital system becomes destructive of these ends, it is "
    "the right – and duty – of participants to demand accountability and reform."
)


# ---------------------------------------------------------------------------
# Unalienable Digital Rights
# ---------------------------------------------------------------------------


class UnalienableRight(Flag):
    """Enumerated digital rights corresponding to the Declaration's triad.

    ACCESS   ≡ Life      – right to persistent digital existence and access.
    LIBERTY  ≡ Liberty   – freedom from coercive surveillance and control.
    AGENCY   ≡ Happiness – autonomous control of one's own data and systems.
    """

    ACCESS  = auto()  # Life
    LIBERTY = auto()  # Liberty
    AGENCY  = auto()  # Pursuit of Happiness
    ALL     = ACCESS | LIBERTY | AGENCY  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Consent Record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConsentRecord:
    """Cryptographically bound record of a subject's informed consent.

    Parameters
    ----------
    subject_id:
        Identifier for the consenting party (opaque string).
    rights_granted:
        Bitmask of :class:`UnalienableRight` values the subject authorises.
    governance_act:
        Human-readable description of the digital governance act being
        authorised.
    timestamp:
        Unix epoch at which consent was recorded.
    expiry:
        Optional Unix epoch after which this record lapses.  ``None`` denotes
        perpetual consent (use with care).
    proof:
        SHA-256 hex digest committing the record's content fields to a single
        verifiable hash (excluding the ``proof`` field itself).
    """

    subject_id:     str
    rights_granted: UnalienableRight
    governance_act: str
    timestamp:      float
    expiry:         Optional[float] = None
    proof:          str             = ""

    # ------------------------------------------------------------------
    # Canonical serialisation
    # ------------------------------------------------------------------

    def _canonical_fields(self) -> bytes:
        """Return the canonical JSON bytes of content fields (excluding proof)."""
        return json.dumps(
            {
                "subject_id":     self.subject_id,
                "rights_granted": self.rights_granted.value,
                "governance_act": self.governance_act,
                "timestamp":      self.timestamp,
                "expiry":         self.expiry,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    # ------------------------------------------------------------------
    # Proof helpers
    # ------------------------------------------------------------------

    def compute_proof(self) -> str:
        """Compute the expected proof digest from the content fields."""
        return hashlib.sha256(self._canonical_fields()).hexdigest()

    def is_valid_proof(self) -> bool:
        """Return True iff the stored proof matches the computed digest."""
        expected = self.compute_proof()
        return hmac.compare_digest(self.proof, expected)

    # ------------------------------------------------------------------
    # Expiry helpers
    # ------------------------------------------------------------------

    def is_expired(self, at: Optional[float] = None) -> bool:
        """Return True iff this record has expired.

        Parameters
        ----------
        at:
            Unix epoch to test against (defaults to current wall time).
        """
        if self.expiry is None:
            return False
        return (at if at is not None else time.time()) > self.expiry

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject_id":     self.subject_id,
            "rights_granted": self.rights_granted.value,
            "governance_act": self.governance_act,
            "timestamp":      self.timestamp,
            "expiry":         self.expiry,
            "proof":          self.proof,
        }


# ---------------------------------------------------------------------------
# Consent Ledger
# ---------------------------------------------------------------------------


class ConsentLedger:
    """Append-only ledger of :class:`ConsentRecord` entries.

    Provides a tamper-evident audit trail of every consent event in the
    system.  Any participant may inspect the ledger to verify that governance
    acts are legitimised by recorded consent – fulfilling the Declaration's
    accountability and transparency requirements.
    """

    def __init__(self) -> None:
        self._records: List[ConsentRecord] = []

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_consent(
        self,
        subject_id: str,
        rights_granted: UnalienableRight,
        governance_act: str,
        expiry: Optional[float] = None,
        timestamp: Optional[float] = None,
    ) -> ConsentRecord:
        """Create, proof-stamp, and append a new :class:`ConsentRecord`.

        Parameters
        ----------
        subject_id:
            Identifier for the consenting party.
        rights_granted:
            Digital rights the subject consents to grant.
        governance_act:
            Description of the governance act being authorised.
        expiry:
            Optional expiry timestamp (Unix epoch).
        timestamp:
            Optional override for the record timestamp (defaults to now).

        Returns
        -------
        ConsentRecord
            The newly recorded, proof-stamped consent record.
        """
        ts = timestamp if timestamp is not None else time.time()

        # Build a temporary record with an empty proof to compute the hash.
        tmp = ConsentRecord(
            subject_id=subject_id,
            rights_granted=rights_granted,
            governance_act=governance_act,
            timestamp=ts,
            expiry=expiry,
            proof="",
        )
        proof = tmp.compute_proof()

        rec = ConsentRecord(
            subject_id=subject_id,
            rights_granted=rights_granted,
            governance_act=governance_act,
            timestamp=ts,
            expiry=expiry,
            proof=proof,
        )
        self._records.append(rec)
        return rec

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def records(self) -> List[ConsentRecord]:
        """All recorded consent records (immutable snapshot)."""
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)

    # ------------------------------------------------------------------
    # Consent query
    # ------------------------------------------------------------------

    def find_consent(
        self,
        subject_id: str,
        required_rights: UnalienableRight,
        governance_act: Optional[str] = None,
        at: Optional[float] = None,
    ) -> Optional[ConsentRecord]:
        """Return the most recent valid consent record covering *required_rights*.

        A record is considered valid iff:

        1. Its ``subject_id`` matches.
        2. Its proof is cryptographically intact.
        3. It has not expired.
        4. Its ``rights_granted`` covers every bit in *required_rights*.
        5. Its ``governance_act`` matches *governance_act* (when provided).

        Enforces the Maxim of Law: "He who mistakes is not considered as
        consenting."  Consent is bound to the specific act for which it was
        recorded; a record for one governance act may not be replayed against
        a different act.

        Parameters
        ----------
        subject_id:
            The party whose consent is being queried.
        required_rights:
            Minimum set of :class:`UnalienableRight` values that must be covered.
        governance_act:
            When provided, only records whose ``governance_act`` exactly matches
            this value are considered.  Omit (or pass ``None``) only when act
            binding is intentionally relaxed (e.g. administrative audits).
        at:
            Evaluation timestamp (defaults to now).

        Returns
        -------
        ConsentRecord | None
            The most recent matching record, or ``None`` if no valid consent
            exists.
        """
        for rec in reversed(self._records):
            if rec.subject_id != subject_id:
                continue
            if governance_act is not None and rec.governance_act != governance_act:
                continue
            if not rec.is_valid_proof():
                continue
            if rec.is_expired(at):
                continue
            if (required_rights & rec.rights_granted) == required_rights:
                return rec
        return None


# ---------------------------------------------------------------------------
# Consent predicate
# ---------------------------------------------------------------------------


def consent_holds(
    ledger: ConsentLedger,
    subject_id: str,
    required_rights: UnalienableRight,
    governance_act: Optional[str] = None,
    at: Optional[float] = None,
) -> bool:
    """Return True iff valid, informed consent exists for *subject_id*.

    Enforces the Declaration principle: digital governance acts derive their
    legitimacy only from the consent of those they affect.  Any act that
    cannot demonstrate a valid consent record is inadmissible.

    Parameters
    ----------
    ledger:
        The :class:`ConsentLedger` to query.
    subject_id:
        The party whose consent must be on file.
    required_rights:
        The :class:`UnalienableRight` values the act requires consent for.
    governance_act:
        When provided, only records bound to this specific governance act are
        considered valid.  Prevents cross-act consent replay.
    at:
        Evaluation timestamp (defaults to now).

    Returns
    -------
    bool
        ``True`` iff at least one valid, unexpired consent record exists
        that covers *required_rights* (and *governance_act*, when provided).
    """
    return ledger.find_consent(subject_id, required_rights, governance_act, at) is not None


# ---------------------------------------------------------------------------
# UVK-compatible Invariant factory
# ---------------------------------------------------------------------------

_SubjectExtractor = Callable[[Any, Any, Any], Tuple[str, UnalienableRight, str]]
"""Callable(state, action, inputs) → (subject_id, required_rights, governance_act)."""


def make_consent_invariant(
    ledger: ConsentLedger,
    subject_extractor: _SubjectExtractor,
    clock: Callable[[], float] = time.time,
    version: str = "1.0.0",
) -> Invariant:
    """Return a :class:`~uvk.Invariant` that enforces informed consent.

    The returned invariant can be registered with a :class:`~uvk.UVK` instance
    to ensure every admitted action is backed by valid, recorded consent –
    operationalising the Declaration's principle that governance derives its
    just powers from the consent of the governed.

    Parameters
    ----------
    ledger:
        The :class:`ConsentLedger` that holds consent records.
    subject_extractor:
        Pure function ``(state, action, inputs) → (subject_id, required_rights,
        governance_act)``.  The ``governance_act`` component binds the consent
        check to the specific act being evaluated, preventing cross-act replay.
        Must be side-effect-free; it is called inside the UVK hot-path.
    clock:
        Zero-argument callable returning the current Unix epoch as a float.
        Defaults to :func:`time.time`.  Inject a deterministic callable in
        tests or audit environments to achieve temporal immutability.
    version:
        Invariant version string (bound into the UVK Wrinkle for replay).

    Returns
    -------
    Invariant
        Named ``"digital_rights:consent_required"`` with the supplied version.

    Example
    -------
    ::

        ledger = ConsentLedger()
        ledger.record_consent("user_1", UnalienableRight.AGENCY, "data_export")

        def my_extractor(state, action, inputs):
            return "user_1", UnalienableRight.AGENCY, "data_export"

        inv = make_consent_invariant(ledger, my_extractor)
        uvk = UVK(invariants=[inv], ...)
    """

    def _check(state: Any, action: Any, inputs: Any) -> bool:
        subject_id, required_rights, governance_act = subject_extractor(state, action, inputs)
        return consent_holds(ledger, subject_id, required_rights,
                             governance_act=governance_act, at=clock())

    return Invariant(
        name    = "digital_rights:consent_required",
        version = version,
        check   = _check,
    )
