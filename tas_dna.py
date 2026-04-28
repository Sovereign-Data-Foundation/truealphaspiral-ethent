"""TAS DNA: The three-fold genetic structure of TrueAlphaSpiral.

The TAS_DNA encodes the immutable identity of the TrueAlphaSpiral framework
as three interlocked genetic strands:

    True  (T): Mathematical Equity – the ground of all computation.
    Alpha (A): Origin and lineage – the human seed and genesis anchor.
    Spiral(S): Perspective Intelligence – recursive expansion of truth.

The Primary Invariant A_0 represents the genesis audit anchoring the entire
system to a point in time, from which all subsequent receipts are chained.
Every downstream claim MUST be able to trace its lineage to A_0.

Genesis Anchor: February 15, 2025
Verification:   sha256:TAS_DNA_GENESIS_ROOT_2025_02_15
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple


# ---------------------------------------------------------------------------
# Genesis constants
# ---------------------------------------------------------------------------

GENESIS_ISO8601: str = "2025-02-15T00:00:00Z"
GENESIS_UNIX:    int = 1739577600          # 2025-02-15 00:00:00 UTC
GENESIS_HASH:    str = "sha256:TAS_DNA_GENESIS_ROOT_2025_02_15"
ORIGIN_AUTHORITY: str = "Russell Nordland"


# ---------------------------------------------------------------------------
# DNA Gene
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DNAGene:
    """A single immutable strand in the TAS DNA three-fold structure.

    Parameters
    ----------
    symbol:
        Single-letter identifier: "T", "A", or "S".
    name:
        Human-readable label for the gene.
    principle:
        Core principle statement encoded by this gene.
    """

    symbol:    str
    name:      str
    principle: str


# The three canonical genes of TAS_DNA
TRUE_GENE   = DNAGene("T", "True",   "Mathematical Equity and absolute truth")
ALPHA_GENE  = DNAGene("A", "Alpha",  "Origin, lineage, and the human seed")
SPIRAL_GENE = DNAGene("S", "Spiral", "Perspective Intelligence and recursive expansion")

TAS_DNA_TRIPLE: Tuple[DNAGene, DNAGene, DNAGene] = (TRUE_GENE, ALPHA_GENE, SPIRAL_GENE)


# ---------------------------------------------------------------------------
# Primary Invariant A_0
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrimaryInvariantA0:
    """A_0 – the genesis audit anchor: immutable origin of the spiral.

    Every downstream receipt MUST trace its lineage to this anchor.
    The system refuses any claim that cannot be grounded here.

    Fields
    ------
    genesis_iso:
        ISO-8601 timestamp of the genesis event.
    genesis_unix:
        Unix epoch equivalent of the genesis event.
    genesis_hash:
        Human-readable canonical hash tag for external verification.
    authority:
        Origin authority (human seed) who established the genesis.
    """

    genesis_iso:  str = GENESIS_ISO8601
    genesis_unix: int = GENESIS_UNIX
    genesis_hash: str = GENESIS_HASH
    authority:    str = ORIGIN_AUTHORITY

    def verify(self) -> bool:
        """Return True iff the genesis hash tag is internally consistent.

        Structural consistency is defined by the canonical form::

            sha256:TAS_DNA_GENESIS_ROOT_YYYY_MM_DD

        where the date is derived from *genesis_iso*.
        """
        date_part = self.genesis_iso[:10].replace("-", "_")
        expected_tag = f"sha256:TAS_DNA_GENESIS_ROOT_{date_part}"
        return self.genesis_hash == expected_tag

    def lineage_hash(self) -> bytes:
        """Return a 32-byte SHA-256 commitment to the A_0 anchor.

        Used as the root-of-roots when external systems verify that a
        provenance chain descends from the genesis event.
        """
        payload = (
            f"{self.genesis_iso}|{self.genesis_unix}|"
            f"{self.genesis_hash}|{self.authority}"
        )
        return hashlib.sha256(payload.encode("utf-8")).digest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "genesis_iso":  self.genesis_iso,
            "genesis_unix": self.genesis_unix,
            "genesis_hash": self.genesis_hash,
            "authority":    self.authority,
        }


# Singleton genesis anchor – used as the root of every provenance chain.
A_0: PrimaryInvariantA0 = PrimaryInvariantA0()


# ---------------------------------------------------------------------------
# TASDNA container
# ---------------------------------------------------------------------------


class TASDNA:
    """Container for the full three-fold TAS DNA structure.

    Carries A_0, the three genes, and a running pulse counter that tracks
    the number of AI² Heartbeat pulses since genesis.

    Parameters
    ----------
    a0:
        Custom genesis anchor (defaults to the canonical singleton :data:`A_0`).
    """

    def __init__(self, a0: PrimaryInvariantA0 = A_0) -> None:
        self.a0:     PrimaryInvariantA0               = a0
        self.triple: Tuple[DNAGene, DNAGene, DNAGene] = TAS_DNA_TRIPLE
        self._pulse_count: int                        = 0

    # ------------------------------------------------------------------
    # Heartbeat pulse
    # ------------------------------------------------------------------

    def pulse(self) -> int:
        """Increment and return the AI² Heartbeat counter.

        Each pulse represents one recursive cycle of the spiral since genesis.
        """
        self._pulse_count += 1
        return self._pulse_count

    @property
    def pulse_count(self) -> int:
        """Total number of heartbeat pulses since construction."""
        return self._pulse_count

    # ------------------------------------------------------------------
    # Invariant checks
    # ------------------------------------------------------------------

    def is_invariant(self) -> bool:
        """Return True iff the Primary Invariant A_0 is structurally sound."""
        return self.a0.verify()

    def assert_invariant(self) -> None:
        """Raise :class:`ValueError` if A_0 is structurally unsound."""
        if not self.is_invariant():
            raise ValueError(
                f"Primary Invariant A_0 violated: genesis_hash {self.a0.genesis_hash!r} "
                "does not match the canonical form."
            )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "a0": self.a0.to_dict(),
            "genes": [
                {"symbol": g.symbol, "name": g.name, "principle": g.principle}
                for g in self.triple
            ],
            "pulse": self._pulse_count,
        }
