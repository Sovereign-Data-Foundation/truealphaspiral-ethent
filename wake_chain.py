# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0
"""
Wake-Based Authentication chain – tamper-evident provenance ledger (§5).

A :class:`WakeChain` maintains an ordered sequence of
:class:`ProvenanceMark` entries where each mark cryptographically commits to
all previous marks via its ``prev_digest`` and ``digest`` fields.  This
provides a tamper-evident audit trail that can be verified and partially
replayed.

Anti-replay protection is enforced by rejecting duplicate nonces within a
chain instance.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_GENESIS_DIGEST: str = "0" * 64


def _sha256_hex(data: str) -> str:
    """Return the hex-encoded SHA-256 digest of *data*."""
    return hashlib.sha256(data.encode()).hexdigest()


def _compute_digest(
    index: int,
    timestamp: float,
    actor: str,
    action: str,
    state_snapshot: Dict[str, Any],
    nonce: str,
    prev_digest: str,
    key: bytes,
) -> str:
    """Deterministically compute the digest for a :class:`ProvenanceMark`."""
    payload = json.dumps(
        {
            "index": index,
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "state_snapshot": state_snapshot,
            "nonce": nonce,
            "prev_digest": prev_digest,
        },
        sort_keys=True,
    )
    return hashlib.sha256(key + payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ProvenanceMark:
    """An immutable, cryptographically-chained record of a single TAS event.

    Attributes:
        index:          Zero-based position of this mark in the chain.
        timestamp:      Unix epoch at the time of commitment.
        actor:          Identifier of the entity performing *action*.
        action:         Human-readable description of the action taken.
        state_snapshot: Optional key/value snapshot of relevant system state.
        nonce:          A unique token used for anti-replay protection.
        prev_digest:    Digest of the immediately preceding mark
                        (``"0" * 64`` for the genesis mark).
        digest:         SHA-256 HMAC over all other fields + the chain key.
    """

    index: int
    timestamp: float
    actor: str
    action: str
    state_snapshot: Dict[str, Any]
    nonce: str
    prev_digest: str
    digest: str


# ---------------------------------------------------------------------------
# Chain
# ---------------------------------------------------------------------------

_DEFAULT_KEY: bytes = b"tas-wake-default-key"


class WakeChain:
    """Ordered, tamper-evident provenance ledger.

    Each :class:`ProvenanceMark` cryptographically commits to its predecessor
    so that any modification of a historical mark is detectable via
    :meth:`verify`.

    Args:
        key: HMAC key used when computing per-mark digests.  Defaults to
             :data:`_DEFAULT_KEY`.
    """

    def __init__(self, key: bytes = _DEFAULT_KEY) -> None:
        self._key: bytes = key
        self._marks: List[ProvenanceMark] = []
        self._seen_nonces: set[str] = set()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def head_digest(self) -> str:
        """Digest of the most-recently committed mark, or the genesis sentinel."""
        if not self._marks:
            return _GENESIS_DIGEST
        return self._marks[-1].digest

    @property
    def marks(self) -> List[ProvenanceMark]:
        """Shallow copy of the internal mark list."""
        return list(self._marks)

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def commit(
        self,
        actor: str,
        action: str,
        state_snapshot: Optional[Dict[str, Any]] = None,
        nonce: Optional[str] = None,
    ) -> ProvenanceMark:
        """Append a new :class:`ProvenanceMark` to the chain.

        Args:
            actor:          Identifier of the acting entity.
            action:         Description of the action performed.
            state_snapshot: Optional dict snapshot of system state.
            nonce:          Unique token; auto-generated when ``None``.

        Returns:
            The newly created and committed :class:`ProvenanceMark`.

        Raises:
            ValueError: If *nonce* has already been used in this chain
                        (anti-replay protection).
        """
        if nonce is None:
            nonce = str(uuid.uuid4())
        if nonce in self._seen_nonces:
            raise ValueError(f"Duplicate nonce detected – replay rejected: {nonce!r}")

        snapshot: Dict[str, Any] = state_snapshot or {}
        index = len(self._marks)
        timestamp = time.time()
        prev = self.head_digest

        digest = _compute_digest(
            index, timestamp, actor, action, snapshot, nonce, prev, self._key
        )

        mark = ProvenanceMark(
            index=index,
            timestamp=timestamp,
            actor=actor,
            action=action,
            state_snapshot=snapshot,
            nonce=nonce,
            prev_digest=prev,
            digest=digest,
        )
        self._marks.append(mark)
        self._seen_nonces.add(nonce)
        return mark

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> bool:
        """Verify the integrity of every mark in the chain.

        Returns:
            ``True`` if all marks are internally consistent and properly
            linked; ``False`` if any tampering is detected.
        """
        prev = _GENESIS_DIGEST
        for mark in self._marks:
            expected = _compute_digest(
                mark.index,
                mark.timestamp,
                mark.actor,
                mark.action,
                mark.state_snapshot,
                mark.nonce,
                mark.prev_digest,
                self._key,
            )
            if mark.digest != expected:
                return False
            if mark.prev_digest != prev:
                return False
            prev = mark.digest
        return True

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    def replay(self, up_to_index: int) -> "WakeChain":
        """Return a new :class:`WakeChain` containing marks ``0..up_to_index``.

        The replayed chain is constructed by re-committing each mark's data in
        order so that the result is a fully self-consistent chain (with a fresh
        key equal to *this* chain's key).

        Args:
            up_to_index: Inclusive upper bound (zero-based) of marks to replay.

        Returns:
            A new :class:`WakeChain` instance.

        Raises:
            IndexError: If *up_to_index* is out of range.
        """
        if up_to_index < 0 or up_to_index >= len(self._marks):
            raise IndexError(
                f"up_to_index {up_to_index} out of range [0, {len(self._marks) - 1}]"
            )
        new_chain = WakeChain(key=self._key)
        for mark in self._marks[: up_to_index + 1]:
            new_chain.commit(
                actor=mark.actor,
                action=mark.action,
                state_snapshot=dict(mark.state_snapshot),
                nonce=mark.nonce,
            )
        return new_chain


# ---------------------------------------------------------------------------
# Module-level default chain
# ---------------------------------------------------------------------------

_DEFAULT_CHAIN: WakeChain = WakeChain()


def get_default_chain() -> WakeChain:
    """Return the module-level default :class:`WakeChain` instance."""
    return _DEFAULT_CHAIN


def reset_default_chain() -> None:
    """Reset the module-level default chain to a fresh :class:`WakeChain`."""
    global _DEFAULT_CHAIN
    _DEFAULT_CHAIN = WakeChain()
