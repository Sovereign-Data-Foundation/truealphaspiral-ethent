"""Wake-Based Authentication: provenance-linked receipt chain.

A *wake* is an append-only, cryptographically-linked trajectory of receipts
that bind inputs → constraints → execution → outputs for every state
transition.  Each receipt is called a :class:`ProvenanceMark` (PM).

Wake-head invariant::

    wake_head_t = SHA-256(wake_head_{t-1} || bytes(R_t))

Admissibility condition (§5.1):
    A transition is valid iff its receipt is (a) present, (b) correctly
    chained, (c) correctly signed, and (d) replay-verifiable.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


_GENESIS_HASH = bytes(32)  # 32 zero bytes – well-known genesis anchor


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _canonical_json(obj: Any) -> bytes:
    """Deterministic JSON serialisation (sorted keys, no extra whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class ProvenanceMark:
    """Packed provenance-mark structure (§5.2).

    Fields
    ------
    id          UUID – session / trajectory identifier.
    seq         Monotone sequence number (anti-replay).
    prev        32-byte hash of the preceding receipt (genesis = 0x00…).
    key_commit  32-byte commitment to a future reveal (optional, zeros if unused).
    event_hash  32-byte hash of the canonicalized event payload.
    info        "Wrinkle" dict: inputs, constraints, proof refs, tool/model IDs.
    sig         HMAC-SHA-256 over all preceding fields (authenticates the PM).
    """

    id: str
    seq: int
    prev: bytes
    key_commit: bytes
    event_hash: bytes
    info: Dict[str, Any]
    sig: bytes = field(default_factory=lambda: bytes(32))

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def _unsigned_bytes(self) -> bytes:
        """Canonical byte representation of all fields *except* sig."""
        header = {
            "id": self.id,
            "seq": self.seq,
            "prev": self.prev.hex(),
            "key_commit": self.key_commit.hex(),
            "event_hash": self.event_hash.hex(),
            "info": self.info,
        }
        return _canonical_json(header)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "seq": self.seq,
            "prev": self.prev.hex(),
            "key_commit": self.key_commit.hex(),
            "event_hash": self.event_hash.hex(),
            "info": self.info,
            "sig": self.sig.hex(),
        }

    def receipt_hash(self) -> bytes:
        """SHA-256 of the fully-signed PM (used as ``prev`` in the next PM)."""
        return _sha256(_canonical_json(self.to_dict()))

    # ------------------------------------------------------------------
    # Signing / verification
    # ------------------------------------------------------------------

    def sign(self, key: bytes) -> "ProvenanceMark":
        """Return a new PM with ``sig`` set to HMAC-SHA-256(key, unsigned_bytes)."""
        mac = hmac.new(key, self._unsigned_bytes(), hashlib.sha256).digest()
        return ProvenanceMark(
            id=self.id,
            seq=self.seq,
            prev=self.prev,
            key_commit=self.key_commit,
            event_hash=self.event_hash,
            info=self.info,
            sig=mac,
        )

    def verify_sig(self, key: bytes) -> bool:
        """Return True iff the PM signature is valid under *key*."""
        expected = hmac.new(key, self._unsigned_bytes(), hashlib.sha256).digest()
        return hmac.compare_digest(expected, self.sig)


class WakeChain:
    """Append-only, hash-chained sequence of :class:`ProvenanceMark` receipts.

    Parameters
    ----------
    session_id:
        UUID string identifying this wake (trajectory).
    uvk_key:
        Symmetric key used by the UVK to sign receipts (HMAC-SHA-256).
        In production this would be an asymmetric keypair; the HMAC
        approach is used here for simplicity without external dependencies.
    """

    def __init__(self, session_id: Optional[str] = None, uvk_key: Optional[bytes] = None) -> None:
        self.session_id: str = session_id or str(uuid.uuid4())
        self._key: bytes = uvk_key or _sha256(self.session_id.encode())
        self._receipts: List[ProvenanceMark] = []
        self._wake_head: bytes = _GENESIS_HASH

    # ------------------------------------------------------------------
    # Chain accessors
    # ------------------------------------------------------------------

    @property
    def head(self) -> bytes:
        """Current wake-head hash."""
        return self._wake_head

    @property
    def receipts(self) -> List[ProvenanceMark]:
        return list(self._receipts)

    def __len__(self) -> int:
        return len(self._receipts)

    # ------------------------------------------------------------------
    # Commitment
    # ------------------------------------------------------------------

    def commit(
        self,
        event: Any,
        info: Optional[Dict[str, Any]] = None,
        key_commit: Optional[bytes] = None,
    ) -> ProvenanceMark:
        """Create, sign, and append a new :class:`ProvenanceMark`.

        Parameters
        ----------
        event:
            Any JSON-serialisable object representing the event payload.
            The PM stores its canonical SHA-256 hash.
        info:
            "Wrinkle" dict – tool inputs/outputs, invariant versions,
            protocol snapshot, model identities, proof IDs.
        key_commit:
            Optional 32-byte forward commitment; zeros when unused.

        Returns
        -------
        ProvenanceMark
            The newly committed receipt (already appended to the chain).
        """
        event_bytes = _canonical_json(event)
        event_hash = _sha256(event_bytes)

        # prev is the hash of the immediately preceding receipt (§5.2),
        # which is distinct from wake_head (the running chain accumulation).
        prev = self._receipts[-1].receipt_hash() if self._receipts else _GENESIS_HASH

        pm = ProvenanceMark(
            id=self.session_id,
            seq=len(self._receipts),
            prev=prev,
            key_commit=key_commit or bytes(32),
            event_hash=event_hash,
            info=info or {},
        ).sign(self._key)

        self._receipts.append(pm)
        self._wake_head = _sha256(self._wake_head + pm.receipt_hash())
        return pm

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> bool:
        """Return True iff the entire chain is self-consistent.

        Checks:
        1. Each PM signature is valid.
        2. Sequence numbers are strictly monotone (0, 1, 2, …).
        3. Each PM's ``prev`` equals the receipt_hash of its predecessor
           (or the genesis hash for seq == 0).
        4. The recorded wake-head matches a full replay.
        """
        replayed_head = _GENESIS_HASH
        for i, pm in enumerate(self._receipts):
            if pm.seq != i:
                return False
            if not pm.verify_sig(self._key):
                return False
            expected_prev = _GENESIS_HASH if i == 0 else self._receipts[i - 1].receipt_hash()
            if pm.prev != expected_prev:
                return False
            replayed_head = _sha256(replayed_head + pm.receipt_hash())

        return replayed_head == self._wake_head

    def replay_from(self, seq: int) -> "WakeChain":
        """Return a new WakeChain replayed from receipt *seq* onward (dry-dock).

        This implements the Phoenix re-verify step (§7.2.3).
        """
        if seq < 0 or seq >= len(self._receipts):
            raise IndexError(f"seq {seq} out of range [0, {len(self._receipts)})")

        new_chain = WakeChain(session_id=self.session_id, uvk_key=self._key)
        # Rebuild the wake_head up to (but not including) seq so that
        # subsequent commits in new_chain are properly anchored.
        replayed_head = _GENESIS_HASH
        for pm in self._receipts[:seq]:
            replayed_head = _sha256(replayed_head + pm.receipt_hash())
        new_chain._wake_head = replayed_head

        # Also populate new_chain._receipts with the pre-seq receipts so
        # that the first re-committed receipt gets the correct prev link.
        for pm in self._receipts[:seq]:
            new_chain._receipts.append(pm)

        # re-commit events from seq onward
        for pm in self._receipts[seq:]:
            new_chain.commit(
                event={"replayed_event_hash": pm.event_hash.hex()},
                info=pm.info,
                key_commit=pm.key_commit if pm.key_commit != bytes(32) else None,
            )
        return new_chain


# ---------------------------------------------------------------------------
# Module-level singleton chain (used by artifact_guard when no chain is given)
# ---------------------------------------------------------------------------

_default_chain: Optional[WakeChain] = None


def get_default_chain() -> WakeChain:
    """Return the process-level default :class:`WakeChain`, creating it lazily."""
    global _default_chain
    if _default_chain is None:
        _default_chain = WakeChain()
    return _default_chain


def reset_default_chain(session_id: Optional[str] = None, uvk_key: Optional[bytes] = None) -> WakeChain:
    """Replace the default chain (useful for testing or process restart)."""
    global _default_chain
    _default_chain = WakeChain(session_id=session_id, uvk_key=uvk_key)
    return _default_chain
