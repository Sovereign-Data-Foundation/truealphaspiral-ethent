"""Stability metrics for the Wake-Based Authentication system (§6).

Metrics are *computed*, not "felt."

Semantic Drift Index (SDI)
--------------------------
    SDI_t = 1 - cos(θ_t)

where θ_t is the angle between embedding vectors of successive cycles.
Values near 0 indicate stable state; values approaching 1 indicate drift.

Phase Discontinuity (PD)
------------------------
A phase slip occurs when |φ_t| > φ_max for N consecutive steps.
The :class:`PhaseMonitor` tracks this condition and reports slip events.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import math
from collections import deque
from typing import Deque, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Semantic Drift Index
# ---------------------------------------------------------------------------


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """Return the cosine similarity between vectors *a* and *b*.

    Returns 0.0 if either vector has zero magnitude (degenerate case).
    """
    if len(a) != len(b):
        raise ValueError(f"Vector length mismatch: {len(a)} vs {len(b)}")
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(y * y for y in b))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


def semantic_drift_index(a: Sequence[float], b: Sequence[float]) -> float:
    """Return SDI = 1 - cos(θ) between embedding vectors *a* and *b*.

    Range: [0, 2].  Values near 0 = aligned; 1 = orthogonal; 2 = anti-aligned.
    In practice, for normalised embeddings of natural-language outputs,
    a threshold of ~0.15 is a reasonable alert boundary.
    """
    return 1.0 - cosine_similarity(a, b)


class DriftTracker:
    """Track SDI across successive output embeddings.

    Parameters
    ----------
    threshold:
        SDI value above which :meth:`is_drifted` returns True.
    window:
        Number of recent SDI values to keep.
    """

    def __init__(self, threshold: float = 0.15, window: int = 10) -> None:
        self.threshold = threshold
        self._history: Deque[float] = deque(maxlen=window)
        self._prev: Optional[List[float]] = None

    def update(self, embedding: Sequence[float]) -> Optional[float]:
        """Record a new embedding and return the SDI vs the previous one.

        Returns ``None`` on the first call (no previous embedding available).
        """
        vec = list(embedding)
        if self._prev is None:
            self._prev = vec
            return None
        sdi = semantic_drift_index(self._prev, vec)
        self._history.append(sdi)
        self._prev = vec
        return sdi

    @property
    def latest_sdi(self) -> Optional[float]:
        return self._history[-1] if self._history else None

    def is_drifted(self) -> bool:
        """Return True iff the most recent SDI exceeds the threshold."""
        sdi = self.latest_sdi
        return sdi is not None and sdi > self.threshold

    @property
    def history(self) -> List[float]:
        return list(self._history)


# ---------------------------------------------------------------------------
# Phase Discontinuity monitor
# ---------------------------------------------------------------------------


class PhaseSlip(Exception):
    """Raised when a critical phase slip is detected (§7.1.3)."""

    def __init__(self, consecutive: int, phi_max: float) -> None:
        self.consecutive = consecutive
        self.phi_max = phi_max
        super().__init__(
            f"Critical phase slip: {consecutive} consecutive steps with |φ| > {phi_max}"
        )


class PhaseMonitor:
    """Monitor phase error φ_t and detect sustained phase slips.

    Parameters
    ----------
    phi_max:
        Maximum tolerated |φ_t| before a step is counted as a slip.
    n_consecutive:
        Number of consecutive slip steps that triggers a critical slip.
    """

    def __init__(self, phi_max: float = 0.5, n_consecutive: int = 3) -> None:
        self.phi_max = phi_max
        self.n_consecutive = n_consecutive
        self._slip_count: int = 0
        self._total_slips: int = 0
        self._history: List[Tuple[float, bool]] = []  # (phi, is_slip)

    def update(self, phi: float) -> bool:
        """Record a new phase error value.

        Parameters
        ----------
        phi:
            Current phase error φ_t (domain-specific; any real number).

        Returns
        -------
        bool
            True iff a *critical* phase slip just occurred (i.e., this call
            triggered the N-consecutive-slip condition).

        Raises
        ------
        PhaseSlip
            When a critical slip is detected (same condition as returning True).
        """
        is_slip = abs(phi) > self.phi_max
        self._history.append((phi, is_slip))
        if is_slip:
            self._slip_count += 1
            self._total_slips += 1
        else:
            self._slip_count = 0

        if self._slip_count >= self.n_consecutive:
            self._slip_count = 0  # reset so repeated calls can raise again
            raise PhaseSlip(self.n_consecutive, self.phi_max)
        return False

    @property
    def consecutive_slips(self) -> int:
        return self._slip_count

    @property
    def total_slips(self) -> int:
        return self._total_slips

    @property
    def history(self) -> List[Tuple[float, bool]]:
        return list(self._history)

    def is_in_slip(self) -> bool:
        """Return True iff the most recent step was a slip."""
        return bool(self._history) and self._history[-1][1]
