# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0
"""
Stability metrics for the TAS agent (§6).

This module provides lightweight, pure-Python tools for tracking semantic
drift and phase stability of TAS agent state vectors.  No external
dependencies are required.

Key concepts
------------
* **Semantic Drift Index (SDI)**: measures how far the current embedding has
  drifted from a baseline using ``1 - cosine_similarity``.  SDI = 0 means no
  drift; SDI = 2 is maximum (anti-parallel).
* **DriftTracker**: maintains a rolling window of SDI samples and exposes the
  current rolling mean.
* **PhaseMonitor**: enforces a maximum phase bound φ_max; raises
  :class:`PhaseSlip` when exceeded.
"""

from __future__ import annotations

import math
from collections import deque
from typing import Deque, List


# ---------------------------------------------------------------------------
# Cosine similarity
# ---------------------------------------------------------------------------


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Return the cosine similarity between vectors *a* and *b*.

    Returns 0.0 when either vector is the zero vector (to avoid division by
    zero), which represents maximum uncertainty rather than a spurious value.

    Args:
        a: First real-valued vector.
        b: Second real-valued vector (must have the same length as *a*).

    Returns:
        A float in ``[-1.0, 1.0]``, or ``0.0`` for zero-length inputs.
    """
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Semantic Drift Index
# ---------------------------------------------------------------------------


def semantic_drift_index(baseline: List[float], current: List[float]) -> float:
    """Compute the Semantic Drift Index (SDI) between *baseline* and *current*.

    SDI is defined as ``1 - cosine_similarity(baseline, current)``.

    * ``SDI = 0``: no drift (identical direction).
    * ``SDI = 1``: orthogonal (maximum uncertainty).
    * ``SDI = 2``: anti-parallel (maximum drift).

    Args:
        baseline: Reference embedding vector.
        current:  Current embedding vector.

    Returns:
        A float in ``[0.0, 2.0]``.
    """
    return 1.0 - cosine_similarity(baseline, current)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PhaseSlip(Exception):
    """Raised by :class:`PhaseMonitor` when the observed phase exceeds φ_max."""


# ---------------------------------------------------------------------------
# DriftTracker
# ---------------------------------------------------------------------------


class DriftTracker:
    """Rolling-window accumulator for SDI samples.

    Args:
        window: Maximum number of samples retained.  Older samples are
                discarded once the window is full.
    """

    def __init__(self, window: int = 10) -> None:
        self._window: int = window
        self._samples: Deque[float] = deque(maxlen=window)

    def update(self, drift_value: float) -> float:
        """Add *drift_value* to the window and return the updated rolling mean.

        Args:
            drift_value: New SDI sample to record.

        Returns:
            The current rolling mean over the window.
        """
        self._samples.append(drift_value)
        return self.mean

    @property
    def mean(self) -> float:
        """Rolling mean of the current window, or ``0.0`` if empty."""
        if not self._samples:
            return 0.0
        return sum(self._samples) / len(self._samples)

    @property
    def samples(self) -> List[float]:
        """Snapshot copy of the current window contents."""
        return list(self._samples)


# ---------------------------------------------------------------------------
# PhaseMonitor
# ---------------------------------------------------------------------------


class PhaseMonitor:
    """Enforces a maximum phase bound φ_max on observed phase values.

    Args:
        phi_max: Maximum allowed absolute phase.  Defaults to ``0.5``.
    """

    def __init__(self, phi_max: float = 0.5) -> None:
        self._phi_max: float = phi_max

    @property
    def phi_max(self) -> float:
        """The configured maximum phase threshold."""
        return self._phi_max

    def check(self, phi: float) -> None:
        """Assert that *phi* is within the allowed range.

        Args:
            phi: Observed phase value.

        Raises:
            PhaseSlip: If ``|phi| > phi_max``.
        """
        if abs(phi) > self._phi_max:
            raise PhaseSlip(
                f"Phase slip detected: |{phi}| > phi_max={self._phi_max}"
            )
