"""Capability model – kernel-checked unforgeable tokens of reference + rights.

Enforces the Principle of Least Authority (POLA) as specified in §3 of the
Wake-Based Authentication spec.

Kernel primitives
-----------------
Retype  : f(U) → {O_i}    Convert raw resources into kernel objects.
Mint    : g(C, R_sub) → C_new   Derive a new capability with a *subset* of rights.
Revoke  : ∀ C_d ∈ CDT: delete(C_d)  Remove delegated authority.
Invoke  : h(C, Msg) → Result   Deterministic object operation.
Move    : m(S_A, S_B) → S_B    Atomic capability transfer between subjects.

Security property: any action without the required capability is
*non-admissible* (§3).
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass, field
from enum import Flag, auto
from typing import Any, Dict, Optional, Set


# ---------------------------------------------------------------------------
# Rights bitfield
# ---------------------------------------------------------------------------


class Right(Flag):
    """Available rights that may be granted to a capability."""
    READ    = auto()
    WRITE   = auto()
    EXECUTE = auto()
    MINT    = auto()   # may derive child capabilities
    REVOKE  = auto()   # may revoke delegated capabilities
    MOVE    = auto()   # may transfer the capability atomically


ALL_RIGHTS: Right = Right.READ | Right.WRITE | Right.EXECUTE | Right.MINT | Right.REVOKE | Right.MOVE


# ---------------------------------------------------------------------------
# Capability token
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Capability:
    """An unforgeable token binding a *resource* name to a set of *rights*.

    Capabilities are immutable once created.  Tokens are identified by a UUID
    and carry a short HMAC tag so that the UVK can verify they were issued by
    the authorised kernel.

    Parameters
    ----------
    cap_id:
        Unique identifier for this capability token.
    resource:
        Name of the resource (object) this capability refers to.
    rights:
        Bitmask of permitted operations.
    parent_id:
        ``cap_id`` of the capability from which this one was derived
        (``None`` for root capabilities).
    tag:
        HMAC-SHA-256 authenticator computed over (cap_id, resource, rights,
        parent_id) – set by :meth:`CapabilityTable.retype` and
        :meth:`CapabilityTable.mint`.
    """

    cap_id: str
    resource: str
    rights: Right
    parent_id: Optional[str] = None
    tag: bytes = field(default=bytes(32))

    def has_right(self, right: Right) -> bool:
        return right in self.rights

    def _signable(self) -> bytes:
        parts = f"{self.cap_id}|{self.resource}|{self.rights.value}|{self.parent_id or ''}"
        return parts.encode("utf-8")

    def verify_tag(self, kernel_key: bytes) -> bool:
        expected = hmac.new(kernel_key, self._signable(), hashlib.sha256).digest()
        return hmac.compare_digest(expected, self.tag)


# ---------------------------------------------------------------------------
# Capability Derivation Table (CDT) + kernel operations
# ---------------------------------------------------------------------------


class CapabilityError(Exception):
    """Raised when a capability operation violates security invariants."""


class CapabilityTable:
    """Kernel-managed store of live capabilities (the CDT).

    Parameters
    ----------
    kernel_key:
        Secret key used to authenticate capability tags.  In a real system
        this would be the UVK's private signing key.
    """

    def __init__(self, kernel_key: Optional[bytes] = None) -> None:
        self._key: bytes = kernel_key or hashlib.sha256(b"uvk-cap-kernel-key").digest()
        # cap_id → Capability (live entries only)
        self._live: Dict[str, Capability] = {}
        # cap_id → set of derived cap_ids (for cascade revocation)
        self._children: Dict[str, Set[str]] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _tag(self, cap: Capability) -> bytes:
        return hmac.new(self._key, cap._signable(), hashlib.sha256).digest()

    def _register(self, cap: Capability) -> Capability:
        """Add *cap* to the live table; return it."""
        self._live[cap.cap_id] = cap
        if cap.parent_id:
            self._children.setdefault(cap.parent_id, set()).add(cap.cap_id)
        return cap

    # ------------------------------------------------------------------
    # Kernel primitive: Retype  f(U) → {O_i}
    # ------------------------------------------------------------------

    def retype(self, resource: str, rights: Right = ALL_RIGHTS) -> Capability:
        """Convert a raw resource name into a root kernel capability object."""
        cap_id = str(uuid.uuid4())
        cap = Capability(
            cap_id=cap_id,
            resource=resource,
            rights=rights,
            parent_id=None,
            tag=bytes(32),  # placeholder so _signable is stable
        )
        signed_cap = Capability(
            cap_id=cap.cap_id,
            resource=cap.resource,
            rights=cap.rights,
            parent_id=cap.parent_id,
            tag=self._tag(cap),
        )
        return self._register(signed_cap)

    # ------------------------------------------------------------------
    # Kernel primitive: Mint  g(C, R_sub) → C_new
    # ------------------------------------------------------------------

    def mint(self, parent: Capability, rights_subset: Right) -> Capability:
        """Derive a new capability with a *subset* of *parent*'s rights.

        Raises :class:`CapabilityError` if:
        - The parent capability is not live (revoked or unknown).
        - The parent tag is invalid (forgery attempt).
        - *rights_subset* is not a proper subset of parent rights.
        - The parent does not hold the MINT right.
        """
        self._check_live(parent)
        if not parent.has_right(Right.MINT):
            raise CapabilityError(f"Capability {parent.cap_id!r} does not hold MINT right")
        if not (rights_subset & parent.rights) == rights_subset:
            raise CapabilityError(
                f"rights_subset {rights_subset!r} exceeds parent rights {parent.rights!r}"
            )

        cap_id = str(uuid.uuid4())
        child = Capability(
            cap_id=cap_id,
            resource=parent.resource,
            rights=rights_subset,
            parent_id=parent.cap_id,
            tag=bytes(32),
        )
        signed_child = Capability(
            cap_id=child.cap_id,
            resource=child.resource,
            rights=child.rights,
            parent_id=child.parent_id,
            tag=self._tag(child),
        )
        return self._register(signed_child)

    # ------------------------------------------------------------------
    # Kernel primitive: Revoke  ∀ C_d ∈ CDT: delete(C_d)
    # ------------------------------------------------------------------

    def revoke(self, cap: Capability) -> int:
        """Remove *cap* and all capabilities derived from it.

        Returns the number of capability entries deleted.
        """
        self._check_live(cap)
        return self._cascade_revoke(cap.cap_id)

    def _cascade_revoke(self, cap_id: str) -> int:
        count = 0
        for child_id in list(self._children.pop(cap_id, set())):
            count += self._cascade_revoke(child_id)
        if cap_id in self._live:
            del self._live[cap_id]
            count += 1
        return count

    # ------------------------------------------------------------------
    # Kernel primitive: Invoke  h(C, Msg) → Result
    # ------------------------------------------------------------------

    def invoke(self, cap: Capability, right: Right, msg: Any = None) -> Dict[str, Any]:
        """Assert that *cap* is live and holds *right*, then return a result stub.

        In a real kernel this would dispatch to the capability's object handler.
        Here it validates admissibility and returns metadata.

        Raises :class:`CapabilityError` if the capability is invalid or
        does not hold the required right.
        """
        self._check_live(cap)
        if not cap.has_right(right):
            raise CapabilityError(
                f"Capability {cap.cap_id!r} does not hold required right {right!r}"
            )
        return {
            "cap_id": cap.cap_id,
            "resource": cap.resource,
            "right": right.name,
            "msg": msg,
            "admitted": True,
        }

    # ------------------------------------------------------------------
    # Kernel primitive: Move  m(S_A, S_B) → S_B
    # ------------------------------------------------------------------

    def move(self, cap: Capability, new_resource: str) -> Capability:
        """Atomically transfer *cap* to refer to *new_resource*.

        The old capability is revoked and a new one is issued with the same
        rights, fulfilling the atomic-transfer semantic.

        Raises :class:`CapabilityError` if the capability does not hold MOVE.
        """
        self._check_live(cap)
        if not cap.has_right(Right.MOVE):
            raise CapabilityError(f"Capability {cap.cap_id!r} does not hold MOVE right")
        self._cascade_revoke(cap.cap_id)
        return self.retype(new_resource, cap.rights)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_live(self, cap: Capability) -> None:
        if cap.cap_id not in self._live:
            raise CapabilityError(f"Capability {cap.cap_id!r} is not live (revoked or unknown)")
        if not cap.verify_tag(self._key):
            raise CapabilityError(f"Capability {cap.cap_id!r} tag verification failed (forgery?)")

    def is_live(self, cap: Capability) -> bool:
        """Return True iff *cap* is present in the live table and tag-valid."""
        return cap.cap_id in self._live and cap.verify_tag(self._key)

    @property
    def live_count(self) -> int:
        return len(self._live)
