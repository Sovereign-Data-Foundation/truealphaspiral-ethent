"""Human API Key bridge: scoped delegation with receipt-bearing execution.

The bridge turns an authenticated human intent label into a bounded machine
capability.  It does not store or expose provider API keys.  Instead, it records
what authority was delegated, refuses commands outside that scope, and emits a
wake-linked receipt for each admitted or refused transition.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Iterable, Mapping, Sequence

from capability import Capability, CapabilityTable, Right
from wake_chain import ProvenanceMark, WakeChain


DEFAULT_BRIDGE_INTENT = "tas-clean-stack-day-one-bridge"
DEFAULT_RELEASE_COMMAND = "gh workflow run release-docker.yml --ref main"
BRIDGE_NAME = "Human API Key"


def _canonical_json(payload: object) -> str:
    """Return deterministic JSON text for hashing and replay."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class HumanIntent:
    """Authenticated steward intent that seeds delegated authority."""

    steward_label: str
    intent: str = DEFAULT_BRIDGE_INTENT
    issued_at_utc: str = ""

    def fingerprint(self) -> str:
        """Hash the human seed without exposing any provider secret."""
        return _sha256_text(_canonical_json(asdict(self)))


@dataclass(frozen=True)
class DelegatedAuthority:
    """A narrowed command scope derived from the human intent."""

    intent_hash: str
    allowed_commands: tuple[str, ...]
    resource: str = "tas-bridge"

    @classmethod
    def from_intent(
        cls,
        intent: HumanIntent,
        allowed_commands: Iterable[str],
        resource: str = "tas-bridge",
    ) -> "DelegatedAuthority":
        commands = tuple(dict.fromkeys(allowed_commands))
        if not commands:
            raise ValueError("bridge delegation requires at least one allowed command")
        return cls(intent_hash=intent.fingerprint(), allowed_commands=commands, resource=resource)

    def scope_hash(self) -> str:
        """Hash the exact delegated command surface for replay."""
        return _sha256_text(_canonical_json(asdict(self)))

    def permits(self, command: str) -> bool:
        return command in self.allowed_commands


class BridgeDecision(str, Enum):
    """Decision classes emitted by the bridge."""

    RECEIPT = "receipt"
    REFUSAL = "refusal"


@dataclass(frozen=True)
class BridgeReceipt:
    """Replayable proof for an admitted command or a held boundary."""

    decision: BridgeDecision
    command: str
    intent_hash: str
    scope_hash: str
    command_hash: str
    reason: str
    wake_seq: int
    wake_receipt_hash: str
    timestamp_utc: str

    def replay_material(self) -> Mapping[str, object]:
        """Return the canonical receipt fields used by independent replay."""
        payload = asdict(self)
        payload["decision"] = self.decision.value
        return payload

    def receipt_hash(self) -> str:
        """Hash this bridge-level proof, separate from the wake receipt hash."""
        return _sha256_text(_canonical_json(self.replay_material()))


class HumanApiBridge:
    """Bridge steward intent to machine authority with refusal boundaries.

    A root authority is retyped by the capability kernel, then narrowed to an
    EXECUTE-only child capability.  Commands outside ``DelegatedAuthority`` are
    never sent to a shell; they produce a refusal receipt instead.
    """

    def __init__(
        self,
        authority: DelegatedAuthority,
        capability_table: CapabilityTable | None = None,
        wake_chain: WakeChain | None = None,
    ) -> None:
        self.authority = authority
        self.capability_table = capability_table or CapabilityTable()
        self.wake_chain = wake_chain or WakeChain()
        root = self.capability_table.retype(authority.resource, Right.EXECUTE | Right.MINT | Right.REVOKE)
        self.capability: Capability = self.capability_table.mint(root, Right.EXECUTE)

    def decide(self, command: str) -> BridgeReceipt:
        """Admit an in-scope command or return a refusal receipt.

        This method is intentionally non-executing.  The returned receipt is the
        authorization artifact an outer runner can inspect before invoking any
        irreversible tool surface.
        """
        if not self.authority.permits(command):
            return self._commit(BridgeDecision.REFUSAL, command, "command outside delegated scope")

        try:
            self.capability_table.invoke(self.capability, Right.EXECUTE, msg=command)
        except Exception as exc:  # capability errors become boundary proofs
            return self._commit(BridgeDecision.REFUSAL, command, f"capability rejected command: {exc}")

        return self._commit(BridgeDecision.RECEIPT, command, "command admitted by human-scoped bridge")

    def _commit(self, decision: BridgeDecision, command: str, reason: str) -> BridgeReceipt:
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        event = {
            "bridge": BRIDGE_NAME,
            "decision": decision.value,
            "command_hash": _sha256_text(command),
            "intent_hash": self.authority.intent_hash,
            "scope_hash": self.authority.scope_hash(),
        }
        provenance: ProvenanceMark = self.wake_chain.commit(
            event=event,
            info={
                "reason": reason,
                "resource": self.authority.resource,
                "allowed_commands": list(self.authority.allowed_commands),
                "timestamp_utc": timestamp,
            },
        )
        return BridgeReceipt(
            decision=decision,
            command=command,
            intent_hash=self.authority.intent_hash,
            scope_hash=self.authority.scope_hash(),
            command_hash=_sha256_text(command),
            reason=reason,
            wake_seq=provenance.seq,
            wake_receipt_hash=provenance.receipt_hash().hex(),
            timestamp_utc=timestamp,
        )

    def replay(self, receipts: Sequence[BridgeReceipt]) -> bool:
        """Verify receipt fields and wake-chain continuity after the fact."""
        if not self.wake_chain.verify():
            return False
        wake_receipts = self.wake_chain.receipts
        if len(receipts) > len(wake_receipts):
            return False
        for receipt in receipts:
            if receipt.intent_hash != self.authority.intent_hash:
                return False
            if receipt.scope_hash != self.authority.scope_hash():
                return False
            if receipt.wake_seq < 0:
                return False
            if receipt.wake_seq >= len(wake_receipts):
                return False
            if receipt.command_hash != _sha256_text(receipt.command):
                return False
            expected_event_hash = _sha256_text(
                _canonical_json(
                    {
                        "bridge": BRIDGE_NAME,
                        "decision": receipt.decision.value,
                        "command_hash": receipt.command_hash,
                        "intent_hash": receipt.intent_hash,
                        "scope_hash": receipt.scope_hash,
                    }
                )
            )
            if wake_receipts[receipt.wake_seq].event_hash.hex() != expected_event_hash:
                return False
            if wake_receipts[receipt.wake_seq].receipt_hash().hex() != receipt.wake_receipt_hash:
                return False
        return True


def build_day_one_bridge(steward_label: str = "HumanAPI Key 001") -> HumanApiBridge:
    """Construct the Day One bridge for the deterministic release workflow."""
    intent = HumanIntent(
        steward_label=steward_label,
        issued_at_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
    authority = DelegatedAuthority.from_intent(intent, [DEFAULT_RELEASE_COMMAND])
    return HumanApiBridge(authority)
