# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0
"""
Capability-based access control (§3).

Capabilities are unforgeable tokens that grant a named *owner* a set of
:class:`Right` flags over a named *resource*.  All capability lifecycle
operations (mint, revoke, retype, invoke, move) are mediated by a
:class:`CapabilityTable`.

This module deliberately contains no implicit authority: callers must
present a valid, non-revoked capability with the required right to perform
any operation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Flag, auto
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Rights
# ---------------------------------------------------------------------------


class Right(Flag):
    """Atomic rights that may be bundled into a :class:`Capability`.

    Attributes:
        READ:   Read or observe the resource.
        WRITE:  Mutate or persist to the resource.
        INVOKE: Execute an operation against the resource.
        MINT:   Create new capabilities for the resource.
        REVOKE: Invalidate existing capabilities for the resource.
        MOVE:   Transfer ownership of a capability.
    """

    READ = auto()
    WRITE = auto()
    INVOKE = auto()
    MINT = auto()
    REVOKE = auto()
    MOVE = auto()


#: Convenience constant representing all defined rights.
ALL_RIGHTS: Right = (
    Right.READ | Right.WRITE | Right.INVOKE | Right.MINT | Right.REVOKE | Right.MOVE
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CapabilityError(Exception):
    """Raised when a capability operation cannot be completed safely."""


# ---------------------------------------------------------------------------
# Capability dataclass
# ---------------------------------------------------------------------------


@dataclass
class Capability:
    """An unforgeable token granting *owner* specific *rights* over *resource*.

    Attributes:
        resource: The name or identifier of the protected resource.
        rights:   The set of :class:`Right` flags granted by this capability.
        owner:    The entity that currently holds this capability.
        cap_id:   Unique identifier (UUID4 string) for this capability.
        revoked:  ``True`` once :meth:`CapabilityTable.revoke` has been called.
    """

    resource: str
    rights: Right
    owner: str
    cap_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    revoked: bool = False

    def has_right(self, right: Right) -> bool:
        """Return ``True`` if this capability includes *right*.

        Args:
            right: The :class:`Right` to test.
        """
        return bool(self.rights & right)


# ---------------------------------------------------------------------------
# CapabilityTable
# ---------------------------------------------------------------------------


class CapabilityTable:
    """Mutable registry that manages the full lifecycle of :class:`Capability` objects.

    All mutation methods are O(1) on the cap_id index.
    """

    def __init__(self) -> None:
        self._table: Dict[str, Capability] = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _require(self, cap_id: str) -> Capability:
        cap = self._table.get(cap_id)
        if cap is None:
            raise CapabilityError(f"Unknown capability: {cap_id!r}")
        return cap

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def mint(self, resource: str, rights: Right, owner: str) -> Capability:
        """Create and register a new :class:`Capability`.

        Args:
            resource: Protected resource identifier.
            rights:   Rights to grant.
            owner:    Identity receiving the capability.

        Returns:
            The newly minted :class:`Capability`.
        """
        cap = Capability(resource=resource, rights=rights, owner=owner)
        self._table[cap.cap_id] = cap
        return cap

    def revoke(self, cap_id: str) -> None:
        """Mark a capability as revoked, preventing future invocations.

        Args:
            cap_id: Identifier of the capability to revoke.

        Raises:
            CapabilityError: If *cap_id* is not found in this table.
        """
        cap = self._require(cap_id)
        cap.revoked = True

    def retype(self, cap_id: str, new_rights: Right) -> Capability:
        """Replace the rights on an existing, live capability.

        Args:
            cap_id:     Identifier of the capability to retype.
            new_rights: New right set to assign.

        Returns:
            The updated :class:`Capability`.

        Raises:
            CapabilityError: If *cap_id* is unknown or the capability is revoked.
        """
        cap = self._require(cap_id)
        if cap.revoked:
            raise CapabilityError(f"Cannot retype a revoked capability: {cap_id!r}")
        cap.rights = new_rights
        return cap

    def invoke(self, cap_id: str, required_right: Right) -> Capability:
        """Assert that the named capability grants *required_right*.

        Args:
            cap_id:         Capability to check.
            required_right: The right that must be present.

        Returns:
            The :class:`Capability` if the check passes.

        Raises:
            CapabilityError: If the capability is unknown, revoked, or does not
                             grant *required_right*.
        """
        cap = self._require(cap_id)
        if cap.revoked:
            raise CapabilityError(f"Capability revoked: {cap_id!r}")
        if not cap.has_right(required_right):
            raise CapabilityError(
                f"Capability {cap_id!r} does not grant {required_right!r}"
            )
        return cap

    def move(self, cap_id: str, new_owner: str) -> Capability:
        """Transfer ownership of a capability to *new_owner*.

        Args:
            cap_id:    Capability to transfer.
            new_owner: Identity of the new owner.

        Returns:
            The updated :class:`Capability`.

        Raises:
            CapabilityError: If *cap_id* is unknown or revoked.
        """
        cap = self._require(cap_id)
        if cap.revoked:
            raise CapabilityError(f"Cannot move a revoked capability: {cap_id!r}")
        cap.owner = new_owner
        return cap

    def get(self, cap_id: str) -> Optional[Capability]:
        """Return the :class:`Capability` for *cap_id*, or ``None``.

        Args:
            cap_id: Capability identifier.
        """
        return self._table.get(cap_id)

    def list_for(self, owner: str) -> List[Capability]:
        """Return all live (non-revoked) capabilities belonging to *owner*.

        Args:
            owner: Identity to filter by.
        """
        return [
            cap
            for cap in self._table.values()
            if cap.owner == owner and not cap.revoked
        ]
