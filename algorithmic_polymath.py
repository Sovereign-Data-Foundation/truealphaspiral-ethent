"""Algorithmic Polymath – cursive computation engine and paradata synthesizer.

In a decentralized environment, nodes operate independently, which typically
creates fragmentation.  The Algorithmic Polymath bridges isolated execution
environments by ensuring that the mathematical operating system's rules
regarding execution and legitimacy are universally applied without requiring
a central coordinator.

Three interlocking responsibilities
------------------------------------
1. **Cursive Computation** – every operation is wrapped in a continuous,
   unbroken stroke.  As computation moves from node to node the stroke is
   never lifted: the state, the exact mathematical transformations applied,
   and the identity of the sovereign actor are structurally bound to the
   operation at each step.

2. **Paradata Synthesis** – the trace simultaneously calculates its own
   proof of legitimacy — the *paradata* — recording what cryptographic
   boundaries were respected and whether the Sovereign Equation A_C > S_C
   was satisfied.  Paradata is fused to the payload, producing a unified
   construct for cross-node transmission.

3. **Cross-Node Verification** – any receiving node can independently
   recompute the expected stroke_head from the embedded paradata.  If a
   node alters the data or breaks the cursive computation the stroke_head
   will not align with the paradata; the network rejects the invalid trace
   through objective mathematics rather than subjective trust.

Public API
----------
* :class:`TransformRecord`     – immutable record of a single transformation step.
* :class:`Paradata`            – self-contained, SHA-256-proofed legitimacy record.
* :class:`CursiveTrace`        – mutable in-progress trace; sealed for transmission.
* :class:`AlgorithmicPolymath` – the synthesizer: begin / apply / seal / verify.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from sovereign_equation import AuthenticityScore, SubjectivityScore, sovereign_holds
from tas_dna import A_0
from wake_chain import WakeChain, get_default_chain

# ---------------------------------------------------------------------------
# Module-level genesis root
# ---------------------------------------------------------------------------

#: SHA-256 commitment to A_0 — the immutable baseline every trace is anchored to.
GENESIS_ROOT_HEX: str = A_0.lineage_hash().hex()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _recompute_stroke_head(
    actor_id: str,
    capability_id: str,
    genesis_root_hex: str,
    transform_log: Tuple["TransformRecord", ...],
) -> str:
    """Deterministically recompute the stroke_head from paradata fields.

    This is the cross-node verification anchor: any node that receives a
    :class:`CursiveTrace` can reproduce this value from the embedded
    :class:`Paradata` alone, without trusting the sender.

    The stroke is seeded with the sovereign identity triple
    ``(actor_id, capability_id, genesis_root_hex)`` and then extended by
    each :class:`TransformRecord` in order::

        stroke_0 = SHA-256(actor_id | capability_id | genesis_root_hex)
        stroke_i = SHA-256(stroke_{i-1} | transform_name | output_hash)
    """
    seed = f"{actor_id}|{capability_id}|{genesis_root_hex}"
    stroke = _sha256_hex(seed.encode("utf-8"))
    for record in transform_log:
        stroke_input = f"{stroke}|{record.name}|{record.output_hash}"
        stroke = _sha256_hex(stroke_input.encode("utf-8"))
    return stroke


# ---------------------------------------------------------------------------
# TransformRecord
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransformRecord:
    """Immutable record of a single transformation applied during cursive computation.

    Parameters
    ----------
    name:
        Human-readable identifier for the transformation (e.g.
        ``"normalize_input"`` or ``"apply_sovereign_filter"``).
    output_hash:
        SHA-256 hex digest of the canonical JSON of the transformation's
        output payload.  Commits the exact result into the stroke without
        transmitting the full payload at every step.
    """

    name: str
    output_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "output_hash": self.output_hash}


# ---------------------------------------------------------------------------
# Paradata
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Paradata:
    """Self-contained, SHA-256-proofed legitimacy record fused to an execution.

    Paradata is the definitive proof of how data was handled, which
    cryptographic boundaries were respected, and whether the Sovereign
    Equation A_C > S_C held throughout the operation.  Because it is
    committed into a :class:`~wake_chain.WakeChain` receipt and
    cryptographically sealed into the :class:`CursiveTrace`, a central
    entity cannot inject phantom data or manipulate the outcome — the
    unbroken chain of paradata would immediately expose the tampering.

    Parameters
    ----------
    actor_id:
        Identifier of the sovereign actor who initiated the operation.
    capability_id:
        UUID of the :class:`~capability.Capability` token authorising the
        operation (Deterministic Agency — authority is mathematically
        inherent, not granted from above).
    genesis_root_hex:
        SHA-256 hex commitment to :data:`tas_dna.A_0` — the cryptographic
        root that anchors the trace to the immutable TAS genesis vintage.
    wake_receipt_hash:
        Hex hash of the :class:`~wake_chain.ProvenanceMark` committed to
        the :class:`~wake_chain.WakeChain` at seal time.
    sovereign_equation_held:
        ``True`` iff A_C > S_C was satisfied at the time the trace was
        sealed — the equal-button guarantee encoded into the execution layer.
    ac_value:
        Numeric A_C (Authenticated Content) score at seal time.
    sc_value:
        Numeric S_C (Subjective Context) score at seal time.
    transform_log:
        Ordered tuple of :class:`TransformRecord` entries — the complete
        history of transformations applied during cursive computation.
    sealed_at:
        Unix epoch at which the trace was sealed.
    proof:
        SHA-256 hex digest committing all fields above (excluding ``proof``
        itself) to a single verifiable hash.
    """

    actor_id:                str
    capability_id:           str
    genesis_root_hex:        str
    wake_receipt_hash:       str
    sovereign_equation_held: bool
    ac_value:                float
    sc_value:                float
    transform_log:           Tuple[TransformRecord, ...]
    sealed_at:               float
    proof:                   str = ""

    # ------------------------------------------------------------------
    # Canonical serialisation
    # ------------------------------------------------------------------

    def _canonical_fields(self) -> bytes:
        return _canonical_json({
            "actor_id":                self.actor_id,
            "capability_id":           self.capability_id,
            "genesis_root_hex":        self.genesis_root_hex,
            "wake_receipt_hash":       self.wake_receipt_hash,
            "sovereign_equation_held": self.sovereign_equation_held,
            "ac_value":                self.ac_value,
            "sc_value":                self.sc_value,
            "transform_log":           [r.to_dict() for r in self.transform_log],
            "sealed_at":               self.sealed_at,
        })

    # ------------------------------------------------------------------
    # Proof helpers
    # ------------------------------------------------------------------

    def compute_proof(self) -> str:
        """Compute the expected proof digest from the content fields."""
        return _sha256_hex(self._canonical_fields())

    def is_valid_proof(self) -> bool:
        """Return ``True`` iff the stored proof matches the computed digest."""
        return hmac.compare_digest(self.proof, self.compute_proof())

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor_id":                self.actor_id,
            "capability_id":           self.capability_id,
            "genesis_root_hex":        self.genesis_root_hex,
            "wake_receipt_hash":       self.wake_receipt_hash,
            "sovereign_equation_held": self.sovereign_equation_held,
            "ac_value":                self.ac_value,
            "sc_value":                self.sc_value,
            "transform_log":           [r.to_dict() for r in self.transform_log],
            "sealed_at":               self.sealed_at,
            "proof":                   self.proof,
        }


# ---------------------------------------------------------------------------
# CursiveTrace
# ---------------------------------------------------------------------------


class CursiveTrace:
    """Mutable in-progress trace; sealed into a unified payload + paradata construct.

    During active computation on Node A the trace accumulates transforms and
    updates its ``stroke_head`` — the running cryptographic accumulator that
    proves the stroke was never lifted.  When :meth:`AlgorithmicPolymath.seal`
    is called, the trace is frozen: :attr:`paradata` is bound and the trace
    becomes ready for cross-node transmission.

    Node B receives the sealed trace and calls :meth:`verify` (or
    :meth:`AlgorithmicPolymath.verify_inbound`) to independently confirm:

    1. The paradata proof is cryptographically intact.
    2. The trace descends from the expected genesis root.
    3. The stroke_head matches a recomputation from the paradata.
    4. The Sovereign Equation A_C > S_C held at seal time.

    Parameters
    ----------
    trace_id:
        UUID for this trace.
    payload:
        The execution payload (updated in-place by each transform).
    actor_id:
        Sovereign actor identifier.
    capability_id:
        Capability token UUID.
    genesis_root_hex:
        SHA-256 genesis root hex this trace is anchored to.
    stroke_head:
        Initial stroke_head derived from the sovereign identity triple.
    """

    def __init__(
        self,
        trace_id: str,
        payload: Any,
        actor_id: str,
        capability_id: str,
        genesis_root_hex: str,
        stroke_head: str,
    ) -> None:
        self.trace_id:        str            = trace_id
        self.payload:         Any            = payload
        self.actor_id:        str            = actor_id
        self.capability_id:   str            = capability_id
        self.genesis_root_hex: str           = genesis_root_hex
        self.stroke_head:     str            = stroke_head
        self.paradata:        Optional[Paradata] = None

        # Internal mutable state — managed by AlgorithmicPolymath
        self._transform_log: List[TransformRecord]    = []
        self._latest_ac:     Optional[AuthenticityScore] = None
        self._latest_sc:     Optional[SubjectivityScore] = None
        self._sealed:        bool                     = False

    # ------------------------------------------------------------------
    # State accessor
    # ------------------------------------------------------------------

    @property
    def is_sealed(self) -> bool:
        """``True`` once :meth:`AlgorithmicPolymath.seal` has been called."""
        return self._sealed

    # ------------------------------------------------------------------
    # Cross-node verification
    # ------------------------------------------------------------------

    def verify(self, expected_genesis_root_hex: str) -> bool:
        """Trustless cross-node verification of this sealed trace.

        A receiving node calls this method after transmission to confirm
        that:

        1. The :attr:`paradata` proof digest is intact (tamper detection).
        2. The trace is anchored to the expected genesis root (prevents
           spoofing via a forged genesis vintage).
        3. The :attr:`stroke_head` matches the value deterministically
           recomputed from the paradata fields alone (proves cursive
           continuity — the stroke was never lifted).
        4. The ac_value and sc_value stored in paradata are internally
           consistent with the ``sovereign_equation_held`` flag.
        5. The Sovereign Equation A_C > S_C held at seal time.

        Parameters
        ----------
        expected_genesis_root_hex:
            The SHA-256 hex of :data:`tas_dna.A_0` that the receiving node
            independently derives — the immutable cryptographic root.

        Returns
        -------
        bool
            ``True`` iff all five checks pass; ``False`` otherwise.
        """
        if self.paradata is None:
            return False

        # 1. Paradata proof integrity
        if not self.paradata.is_valid_proof():
            return False

        # 2. Genesis root anchoring
        if self.paradata.genesis_root_hex != expected_genesis_root_hex:
            return False

        # 3. Stroke head recomputation
        expected_stroke = _recompute_stroke_head(
            self.paradata.actor_id,
            self.paradata.capability_id,
            self.paradata.genesis_root_hex,
            self.paradata.transform_log,
        )
        if not hmac.compare_digest(self.stroke_head, expected_stroke):
            return False

        # 4. Internal consistency: stored boolean must match stored scores
        scores_consistent = (
            self.paradata.sovereign_equation_held ==
            (self.paradata.ac_value > self.paradata.sc_value)
        )
        if not scores_consistent:
            return False

        # 5. Sovereign Equation A_C > S_C must have held
        return self.paradata.sovereign_equation_held

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Return a fully serialisable representation for cross-node transmission."""
        return {
            "trace_id":         self.trace_id,
            "payload":          self.payload,
            "actor_id":         self.actor_id,
            "capability_id":    self.capability_id,
            "genesis_root_hex": self.genesis_root_hex,
            "stroke_head":      self.stroke_head,
            "paradata":         self.paradata.to_dict() if self.paradata else None,
            "sealed":           self._sealed,
        }


# ---------------------------------------------------------------------------
# SovereignStructuralViolation (local alias — avoids circular import from
# tas_logos_gatekeeper which also declares this exception)
# ---------------------------------------------------------------------------


class PolymathViolation(Exception):
    """Raised when the Algorithmic Polymath detects a structural integrity breach."""


# ---------------------------------------------------------------------------
# AlgorithmicPolymath
# ---------------------------------------------------------------------------


class AlgorithmicPolymath:
    """Structural synthesizer: cursive computation, paradata, cross-node verification.

    The Algorithmic Polymath orchestrates sovereign execution across a
    decentralized network without requiring a central coordinator.  It
    achieves this by ensuring that the Sovereign Equation A_C > S_C, the
    cryptographic genesis root, and the continuous execution stroke are all
    structurally bound to every operation — making each trace self-verifying
    by objective mathematics.

    Parameters
    ----------
    wake_chain:
        The :class:`~wake_chain.WakeChain` to which sealed traces are
        committed.  Defaults to the process-level default chain.
    actor_id:
        Identifier for the sovereign actor operating this Polymath instance.
    genesis_root_hex:
        SHA-256 hex of the genesis root.  Defaults to
        :data:`GENESIS_ROOT_HEX` (derived from :data:`tas_dna.A_0`).
    """

    def __init__(
        self,
        actor_id: str,
        wake_chain: Optional[WakeChain] = None,
        genesis_root_hex: Optional[str] = None,
    ) -> None:
        self._actor_id        = actor_id
        self._wake            = wake_chain if wake_chain is not None else get_default_chain()
        self._genesis_root    = genesis_root_hex or GENESIS_ROOT_HEX

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def begin_stroke(self, capability_id: str, initial_payload: Any) -> CursiveTrace:
        """Open a new cursive trace — the stroke begins here.

        Seeds the ``stroke_head`` by committing the sovereign identity
        triple ``(actor_id, capability_id, genesis_root_hex)`` into a
        SHA-256 hash.  This anchors every subsequent transform to both the
        individual's authority *and* the immutable genesis root.

        Parameters
        ----------
        capability_id:
            UUID string of the :class:`~capability.Capability` token
            authorising this operation.
        initial_payload:
            The starting execution payload.

        Returns
        -------
        CursiveTrace
            An unsealed trace ready to receive transforms.
        """
        trace_id = str(uuid.uuid4())
        seed = f"{self._actor_id}|{capability_id}|{self._genesis_root}"
        stroke_head = _sha256_hex(seed.encode("utf-8"))
        return CursiveTrace(
            trace_id=trace_id,
            payload=initial_payload,
            actor_id=self._actor_id,
            capability_id=capability_id,
            genesis_root_hex=self._genesis_root,
            stroke_head=stroke_head,
        )

    def apply_transform(
        self,
        trace: CursiveTrace,
        transform_fn: Callable[[Any], Any],
        transform_name: str,
        ac: AuthenticityScore,
        sc: SubjectivityScore,
    ) -> CursiveTrace:
        """Apply a sovereign transformation — the stroke continues unbroken.

        The transformation function is applied to the current payload and
        the result is folded into the running ``stroke_head``::

            output_hash   = SHA-256(canonical_json(new_payload))
            stroke_head_i = SHA-256(stroke_head_{i-1} | name | output_hash)

        A :class:`TransformRecord` capturing ``name`` and ``output_hash``
        is appended to the trace's internal log.  The latest
        :class:`~sovereign_equation.AuthenticityScore` and
        :class:`~sovereign_equation.SubjectivityScore` are retained for use
        at seal time.

        Parameters
        ----------
        trace:
            The active :class:`CursiveTrace` to extend.
        transform_fn:
            Pure function ``(payload) → new_payload``.  Must be
            side-effect-free and return a JSON-serialisable value.
        transform_name:
            Human-readable name recorded in the :class:`TransformRecord`.
        ac:
            :class:`~sovereign_equation.AuthenticityScore` for this step.
        sc:
            :class:`~sovereign_equation.SubjectivityScore` for this step.

        Returns
        -------
        CursiveTrace
            The same trace object with updated payload and stroke_head.

        Raises
        ------
        PolymathViolation
            If the trace is already sealed.
        """
        if trace.is_sealed:
            raise PolymathViolation(
                f"Cannot apply transform '{transform_name}' to a sealed trace "
                f"(trace_id={trace.trace_id!r})."
            )

        new_payload   = transform_fn(trace.payload)
        output_hash   = _sha256_hex(_canonical_json(new_payload))
        stroke_input  = f"{trace.stroke_head}|{transform_name}|{output_hash}"
        new_stroke    = _sha256_hex(stroke_input.encode("utf-8"))

        trace._transform_log.append(
            TransformRecord(name=transform_name, output_hash=output_hash)
        )
        trace._latest_ac  = ac
        trace._latest_sc  = sc
        trace.payload     = new_payload
        trace.stroke_head = new_stroke
        return trace

    def seal(
        self,
        trace: CursiveTrace,
        ac: Optional[AuthenticityScore] = None,
        sc: Optional[SubjectivityScore] = None,
    ) -> CursiveTrace:
        """Seal the trace: commit to wake chain, bind paradata, close the stroke.

        Sealing produces the unified ``payload + paradata`` construct ready
        for cross-node transmission.  After sealing:

        * No further transforms may be applied.
        * :attr:`~CursiveTrace.paradata` carries a SHA-256 proof commitment
          over all legitimacy fields.
        * A :class:`~wake_chain.ProvenanceMark` is committed to the wake
          chain, making the seal event tamper-evident and replayable.

        Parameters
        ----------
        trace:
            The active :class:`CursiveTrace` to seal.
        ac:
            Override :class:`~sovereign_equation.AuthenticityScore` for the
            final seal evaluation.  Falls back to the score supplied at the
            last :meth:`apply_transform` call, or a zero-scored default if
            no transforms were applied.
        sc:
            Override :class:`~sovereign_equation.SubjectivityScore` — same
            fallback logic as *ac*.

        Returns
        -------
        CursiveTrace
            The same trace object, now sealed with :attr:`~CursiveTrace.paradata`
            bound.

        Raises
        ------
        PolymathViolation
            If the trace is already sealed.
        """
        if trace.is_sealed:
            raise PolymathViolation(
                f"Trace is already sealed (trace_id={trace.trace_id!r})."
            )

        final_ac = ac if ac is not None else (trace._latest_ac or AuthenticityScore())
        final_sc = sc if sc is not None else (trace._latest_sc or SubjectivityScore())
        eq_held  = sovereign_holds(final_ac, final_sc)

        # Commit a wake receipt — the seal event enters the provenance chain
        payload_hash = _sha256_hex(_canonical_json(trace.payload))
        wake_receipt = self._wake.commit(
            event={
                "trace_id":    trace.trace_id,
                "actor_id":    trace.actor_id,
                "stroke_head": trace.stroke_head,
                "payload_hash": payload_hash,
            },
            info={
                "polymath":              "AlgorithmicPolymath",
                "transform_count":       len(trace._transform_log),
                "sovereign_eq_held":     eq_held,
                "genesis_root_hex":      trace.genesis_root_hex,
            },
        )

        sealed_at = time.time()

        # Build Paradata with a placeholder proof, then compute and seal
        tmp = Paradata(
            actor_id=trace.actor_id,
            capability_id=trace.capability_id,
            genesis_root_hex=trace.genesis_root_hex,
            wake_receipt_hash=wake_receipt.receipt_hash().hex(),
            sovereign_equation_held=eq_held,
            ac_value=final_ac.value,
            sc_value=final_sc.value,
            transform_log=tuple(trace._transform_log),
            sealed_at=sealed_at,
            proof="",
        )

        trace.paradata = Paradata(
            actor_id=tmp.actor_id,
            capability_id=tmp.capability_id,
            genesis_root_hex=tmp.genesis_root_hex,
            wake_receipt_hash=tmp.wake_receipt_hash,
            sovereign_equation_held=tmp.sovereign_equation_held,
            ac_value=tmp.ac_value,
            sc_value=tmp.sc_value,
            transform_log=tmp.transform_log,
            sealed_at=tmp.sealed_at,
            proof=tmp.compute_proof(),
        )
        trace._sealed = True
        return trace

    # ------------------------------------------------------------------
    # Cross-node verification (static — any node can call this)
    # ------------------------------------------------------------------

    @staticmethod
    def verify_inbound(
        trace: CursiveTrace,
        expected_genesis_root_hex: str = GENESIS_ROOT_HEX,
    ) -> bool:
        """Trustless verification of an inbound :class:`CursiveTrace`.

        Any node that receives a sealed trace from another node calls this
        method to confirm legitimacy without trusting the sender.  The
        method delegates to :meth:`CursiveTrace.verify`, which recomputes
        the ``stroke_head`` from the embedded :class:`Paradata` and checks
        all five integrity conditions.

        Parameters
        ----------
        trace:
            The inbound :class:`CursiveTrace` to verify.
        expected_genesis_root_hex:
            SHA-256 hex of :data:`tas_dna.A_0` as independently derived by
            the receiving node.  Defaults to :data:`GENESIS_ROOT_HEX`.

        Returns
        -------
        bool
            ``True`` iff the trace passes all integrity checks.
        """
        return trace.verify(expected_genesis_root_hex)
# Nonce: 81042
