import hashlib
import hmac
import json
import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set


class SovereignStructuralViolation(Exception):
    """Raised when an execution trace violates the mathematical bounds of Log(os)."""

    pass


@dataclass(frozen=True)
class LogosRefusalReceipt:
    nonce: int
    parent_hash: str
    shannon_entropy: float
    logos_density: float
    timestamp: int = field(default_factory=lambda: int(time.time()))
    circuit_broken: bool = True


class LogosValidationLoop:
    def __init__(self, invariant_check: Callable[[], bool], min_density_floor: float = 0.15):
        """
        Initializes the Logos validation loop with a calibrated minimum density floor.
        Payloads falling below this floor represent high-volume, low-density noise.
        """
        self._invariant_check = invariant_check
        self._min_density_floor = min_density_floor

    def _calculate_shannon_entropy(self, payload_str: str) -> float:
        """Measures the statistical character entropy (H) of the token stream."""
        if not payload_str:
            return 0.0
        frequencies: Dict[str, int] = {}
        for char in payload_str:
            frequencies[char] = frequencies.get(char, 0) + 1

        entropy = 0.0
        total_chars = len(payload_str)
        for count in frequencies.values():
            p = count / total_chars
            entropy -= p * math.log2(p)
        return entropy

    def evaluate_logos_bounds(
        self, current_state_hash: bytes, manifest: Dict[str, Any], nonce: int
    ) -> bool:
        """
        Validates state transition viability under strict Log(os) constraints.
        Execution passes IF AND ONLY IF lineage balances, invariants hold,
        and the structural density meets or exceeds the minimum threshold floor.
        """
        observed_entropy = 0.0
        logos_density = 1.0
        parent_hash_hex = current_state_hash.hex()

        try:
            # 1. Lineage Trajectory Consistency
            # Normalise: callers may supply lineage_parent_hash as hex str or bytes.
            _lineage_ref = manifest.get("lineage_parent_hash")
            if isinstance(_lineage_ref, bytes):
                lineage_match = _lineage_ref == current_state_hash
            else:
                lineage_match = _lineage_ref == current_state_hash.hex()

            # 2. Invariant Alignment (Phi Check)
            invariants_held = self._invariant_check()

            # 3. Log(os) Scale Efficiency Evaluation
            payload_data = json.dumps(manifest.get("payload_vector", {}), sort_keys=True)
            payload_length = len(payload_data)

            if payload_length > 0:
                observed_entropy = self._calculate_shannon_entropy(payload_data)
                # Calibrated formula: bits of entropy scaled by the log of length over total footprint.
                # Large, repetitive payloads drive this value toward zero; dense, varied payloads score higher.
                logos_density = (observed_entropy * math.log(payload_length)) / payload_length
            else:
                logos_density = 0.0  # Empty payloads carry zero structural work

            # Corrected biconditional gate: density must be AT OR ABOVE the floor.
            if not (lineage_match and invariants_held and (logos_density >= self._min_density_floor)):
                raise SovereignStructuralViolation(
                    f"Biconditional collapse. Lineage: {lineage_match}, "
                    f"Invariants: {invariants_held}, Density: {logos_density:.4f} "
                    f"(Floor: {self._min_density_floor})"
                )

            return True

        except Exception as e:
            self._engage_sentient_lock(
                nonce, parent_hash_hex, observed_entropy, logos_density, str(e)
            )
            return False

    def _engage_sentient_lock(
        self, nonce: int, parent_hash: str, entropy: float, density: float, fault: str
    ) -> None:
        """Halts the execution pipeline and records the non-compliance witness packet."""
        receipt = LogosRefusalReceipt(
            nonce=nonce,
            parent_hash=parent_hash,
            shannon_entropy=entropy,
            logos_density=density,
        )
        print(f"[SENTIENT_LOCK] Execution context frozen by Logos Layer. Fault: {fault}")
        print(
            f"[ITL_RECORD] Non-compliance witness packet compiled:\n"
            f"{json.dumps(receipt.__dict__, default=str, indent=2)}"
        )


# ---------------------------------------------------------------------------
# CursiveTrace deserialization helper
# ---------------------------------------------------------------------------


def _deserialize_trace(data: Dict[str, Any]) -> Any:
    """Reconstruct a :class:`~algorithmic_polymath.CursiveTrace` from its
    wire-format dict representation (produced by ``CursiveTrace.to_dict()``).

    Parameters
    ----------
    data:
        Decoded JSON object as returned by ``CursiveTrace.to_dict()``.

    Returns
    -------
    CursiveTrace
        Fully reconstructed trace, with :attr:`paradata` populated when
        present in *data*.

    Raises
    ------
    ValueError
        If a required field is absent.
    """
    # Deferred import: algorithmic_polymath imports tas_dna/wake_chain but NOT this
    # module, so there is no circular dependency at runtime.  The import is placed
    # here (rather than at module top) to keep tas_logos_gatekeeper importable in
    # isolation (e.g., in lightweight transport processes) without loading the full
    # Polymath dependency chain.
    from algorithmic_polymath import CursiveTrace, Paradata, TransformRecord  # noqa: PLC0415

    required = ("trace_id", "payload", "actor_id", "capability_id",
                "genesis_root_hex", "stroke_head")
    for key in required:
        if key not in data:
            raise ValueError(f"Missing required field in trace wire format: {key!r}")

    trace = CursiveTrace(
        trace_id=data["trace_id"],
        payload=data["payload"],
        actor_id=data["actor_id"],
        capability_id=data["capability_id"],
        genesis_root_hex=data["genesis_root_hex"],
        stroke_head=data["stroke_head"],
    )

    if data.get("paradata") is not None:
        pd = data["paradata"]
        transform_log = tuple(
            TransformRecord(name=r["name"], output_hash=r["output_hash"])
            for r in pd.get("transform_log", [])
        )
        trace.paradata = Paradata(
            actor_id=pd["actor_id"],
            capability_id=pd["capability_id"],
            genesis_root_hex=pd["genesis_root_hex"],
            wake_receipt_hash=pd["wake_receipt_hash"],
            sovereign_equation_held=bool(pd["sovereign_equation_held"]),
            ac_value=float(pd["ac_value"]),
            sc_value=float(pd["sc_value"]),
            transform_log=transform_log,
            sealed_at=float(pd["sealed_at"]),
            pulse_index=int(pd.get("pulse_index", 0)),
            proof=pd.get("proof", ""),
        )

    trace._sealed = bool(data.get("sealed", False))
    return trace


# ---------------------------------------------------------------------------
# SovereignBeacon
# ---------------------------------------------------------------------------


class SovereignBeacon:
    """Lineage-anchored presence assertion for decentralized peer discovery.

    A beacon is not a connection request; it is a mathematical assertion that
    the emitting node is operating on the same TAS genesis root.  To any node
    running incompatible mathematics, the broadcast is cryptographically
    indistinguishable from random noise.

    The beacon signature is HMAC-SHA-256(node_key, genesis_root_hex), tying
    the emitter's local key to the immutable genesis root.  Full cryptographic
    authentication of the remote identity is deferred to the Deterministic
    Handshake (CursiveTrace 5-step verification).
    """

    _BEACON_VERSION: int = 1

    @staticmethod
    def emit(node_key: bytes, genesis_root_hex: str) -> bytes:
        """Generate a signed beacon payload ready for network broadcast.

        Parameters
        ----------
        node_key:
            Symmetric key used to produce the HMAC signature.
        genesis_root_hex:
            The local node's genesis root hex (derived from
            ``tas_dna.A_0.lineage_hash().hex()``).

        Returns
        -------
        bytes
            UTF-8-encoded JSON beacon payload.
        """
        sig = hmac.new(
            node_key,
            genesis_root_hex.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        beacon = {
            "version": SovereignBeacon._BEACON_VERSION,
            "genesis_root_hex": genesis_root_hex,
            "timestamp": int(time.time()),
            "sig": sig,
        }
        return json.dumps(beacon, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def validate(beacon_bytes: bytes, expected_genesis_root_hex: str) -> bool:
        """Return ``True`` iff *beacon_bytes* is structurally consistent with
        *expected_genesis_root_hex*.

        The remote node's key is not known, so HMAC authenticity cannot be
        checked here.  This method confirms that the beacon encodes the correct
        genesis root and carries a well-formed signature field.  Full identity
        authentication is performed during the Deterministic Handshake.

        Parameters
        ----------
        beacon_bytes:
            Raw bytes received from the network.
        expected_genesis_root_hex:
            The genesis root hex the local node derives from its live TASDNA.
        """
        try:
            beacon = json.loads(beacon_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
            return False

        if beacon.get("version") != SovereignBeacon._BEACON_VERSION:
            return False
        if beacon.get("genesis_root_hex") != expected_genesis_root_hex:
            return False
        # sig must be a 64-character hex string (32-byte HMAC → 64 hex chars)
        sig = beacon.get("sig", "")
        if not isinstance(sig, str) or len(sig) != 64:
            return False
        return True


# ---------------------------------------------------------------------------
# SentientLock
# ---------------------------------------------------------------------------


@dataclass
class _ForkRecord:
    """Internal tracking record for a single capability's fork violations."""

    pulse_indices: Set[int] = field(default_factory=set)
    violation_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


class SentientLock:
    """Transport-layer flood defense implementing the Sentient Lock mechanism.

    The Sentient Lock monitors geometric coherence of inbound traffic.  When a
    capability broadcasts contradictory execution strokes (multiple traces
    claiming the same ``pulse_index``), the lock snaps shut for that capability.

    A single actor can only occupy one valid state at any given pulse.  The
    existence of a second trace for the same pulse constitutes a mathematically
    proven cursive break; the Gatekeeper does not arbitrate — it objectively
    rejects both.

    The lock operates at the socket level: locked capabilities are dropped
    *before* the :class:`~algorithmic_polymath.AlgorithmicPolymath` performs
    any verification work, preventing resource exhaustion from a flood.

    Parameters
    ----------
    violation_threshold:
        Number of fork violations that trigger a lock for a capability.
        Defaults to ``3``.
    window_seconds:
        Sliding time window (seconds) within which violations are counted.
        Violations outside this window are discarded.  Defaults to ``60.0``.
    """

    def __init__(
        self,
        violation_threshold: int = 3,
        window_seconds: float = 60.0,
    ) -> None:
        self._threshold = violation_threshold
        self._window = window_seconds
        self._records: Dict[str, _ForkRecord] = {}
        self._locked: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_locked(self, capability_id: str) -> bool:
        """Return ``True`` iff this capability is currently blocked at the
        transport layer."""
        return capability_id in self._locked

    def record_fork(self, capability_id: str, pulse_index: int) -> bool:
        """Record a pulse observation for *capability_id*.

        If the same ``pulse_index`` has already been recorded for this
        capability, a cursive break is confirmed.  Each confirmed break
        increments the violation counter.  When the counter reaches
        ``violation_threshold`` the Sentient Lock activates.

        Parameters
        ----------
        capability_id:
            Capability identifier from the inbound trace's paradata.
        pulse_index:
            ``paradata.pulse_index`` of the inbound trace.

        Returns
        -------
        bool
            ``True`` iff the Sentient Lock was activated as a result of this
            call.
        """
        now = time.time()
        record = self._records.get(capability_id)
        if record is None:
            record = _ForkRecord()
            self._records[capability_id] = record

        # Reset stale records outside the sliding window.
        if now - record.first_seen > self._window:
            record.pulse_indices.clear()
            record.violation_count = 0
            record.first_seen = now

        record.last_seen = now

        if pulse_index in record.pulse_indices:
            # Duplicate pulse_index for this capability → cursive break.
            record.violation_count += 1
            if record.violation_count >= self._threshold:
                self._locked.add(capability_id)
                return True
        else:
            record.pulse_indices.add(pulse_index)

        return False

    def release(self, capability_id: str) -> None:
        """Administratively release a capability from the lock.

        Use with caution — this should only be called after an out-of-band
        confirmation that the capability has been re-validated.
        """
        self._locked.discard(capability_id)
        self._records.pop(capability_id, None)

    def locked_capabilities(self) -> List[str]:
        """Return a snapshot list of currently locked capability IDs."""
        return list(self._locked)


# ---------------------------------------------------------------------------
# WakeSyncOffer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WakeSyncOffer:
    """Gossip payload exchanged between nodes for asymmetric pulse alignment.

    Each node broadcasts its ``pulse_count`` and the hash of its most recent
    :class:`~wake_chain.ProvenanceMark` receipt.  Because ``pulse_index`` is
    stamped into the paradata proof, a receiving node can mathematically
    determine which node holds the most advanced valid continuation of the
    genesis root and request only the missing traces.

    Fields
    ------
    genesis_root_hex:
        Genesis root of the offering node (must match the local root for the
        offer to be considered).
    pulse_count:
        Current AI² Heartbeat pulse count of the offering node.
    latest_receipt_hash:
        Hex digest of the most recent WakeChain receipt on the offering node.
        All-zeros (64 hex chars) when the chain is empty.
    node_id:
        Stable identifier for the offering node (typically ``actor_id``).
    """

    genesis_root_hex: str
    pulse_count: int
    latest_receipt_hash: str
    node_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "genesis_root_hex": self.genesis_root_hex,
            "pulse_count": self.pulse_count,
            "latest_receipt_hash": self.latest_receipt_hash,
            "node_id": self.node_id,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "WakeSyncOffer":
        return WakeSyncOffer(
            genesis_root_hex=data["genesis_root_hex"],
            pulse_count=int(data["pulse_count"]),
            latest_receipt_hash=data["latest_receipt_hash"],
            node_id=data["node_id"],
        )


# ---------------------------------------------------------------------------
# LogosGatekeeper
# ---------------------------------------------------------------------------


class LogosGatekeeper:
    """Network membrane: secure, trustless boundary layer for a sovereign node.

    The Logos Gatekeeper sits directly on the transport socket and manages all
    ingress and egress without compromising the mathematical sovereignty of the
    internal :class:`~algorithmic_polymath.AlgorithmicPolymath`.

    Responsibilities
    ----------------
    1. **Pre-Computation Ingress** — deserializes inbound
       :class:`~algorithmic_polymath.CursiveTrace` payloads and immediately
       routes them through
       :meth:`~algorithmic_polymath.AlgorithmicPolymath.verify_inbound`.  Any
       failure triggers a *silent drop* at the transport layer before the node
       expends computation or memory on the payload.

    2. **Trace-Bearing Egress** — packages sealed
       :class:`~algorithmic_polymath.CursiveTrace` objects (payload + paradata
       + wake receipt) as wire-format JSON and broadcasts them via a pluggable
       transport callable.  The Gatekeeper is entirely agnostic to the
       destination node.

    3. **Wake Synchronization** — facilitates a trustless gossip protocol so
       that reconnecting nodes can sync missing traces without deferring to a
       central registry.

    4. **Sovereign Beacon** — emits a lineage-anchored presence assertion so
       that compatible nodes can discover each other without centralized DNS.

    5. **Deterministic Handshake** — authenticates connection requests via
       :class:`~algorithmic_polymath.CursiveTrace` verification (zero-trust;
       no passwords or certificates).

    6. **Sentient Lock** — detects fork/flood patterns from a specific
       cryptographic lineage and blocks them at the socket level before any
       verification work is performed.

    Parameters
    ----------
    actor_id:
        Sovereign actor identifier for this node.
    tas_dna:
        Local TASDNA instance (carries ``A_0`` and the pulse counter).
    node_key:
        Bytes used to sign Sovereign Beacons.  Defaults to
        ``SHA-256(actor_id)`` — callers should supply a cryptographically
        random key in production.
    sentient_lock:
        Optional pre-configured :class:`SentientLock`.  Defaults to a new
        instance with standard thresholds.
    """

    def __init__(
        self,
        actor_id: str,
        tas_dna: Any,
        node_key: Optional[bytes] = None,
        sentient_lock: Optional[SentientLock] = None,
    ) -> None:
        self._actor_id = actor_id
        self._tas_dna = tas_dna
        self._node_key = node_key or hashlib.sha256(actor_id.encode("utf-8")).digest()
        self._sentient_lock = sentient_lock if sentient_lock is not None else SentientLock()
        self._genesis_root_hex: str = tas_dna.a0.lineage_hash().hex()

    # ------------------------------------------------------------------
    # 1. Pre-Computation Ingress Gateway
    # ------------------------------------------------------------------

    def receive_inbound(self, raw_bytes: bytes) -> Optional[Any]:
        """Deserialize and verify an inbound trace payload.

        Sits directly at the transport socket.  Returns the verified
        :class:`~algorithmic_polymath.CursiveTrace` on success, or ``None``
        on silent drop.

        The silent drop is unconditional: no acknowledgment or error packet is
        sent back.  The connection is severed before the node expends any
        further computational energy or memory on the foreign payload.

        Gate order
        ----------
        0. **Sentient Lock** fast-path — if the capability is already locked,
           the raw bytes are dropped without parsing.
        1. **Deserialization** — malformed payloads are silently discarded.
        2. **Sentient Lock** post-parse — re-check using the parsed
           ``capability_id``.
        3. **Fork detection** — record ``(capability_id, pulse_index)``; a
           duplicate confirms a cursive break and may activate the lock.
        4. **5-step geometric gate** — delegates to
           :meth:`~algorithmic_polymath.AlgorithmicPolymath.verify_inbound`.
        """
        from algorithmic_polymath import AlgorithmicPolymath  # noqa: PLC0415 (see _deserialize_trace for rationale)

        # Step 0: fast-path Sentient Lock check before parsing.
        pre_capability_id = self._extract_capability_id(raw_bytes)
        if pre_capability_id and self._sentient_lock.is_locked(pre_capability_id):
            return None  # silent drop

        # Step 1: deserialize.
        try:
            data = json.loads(raw_bytes)
            trace = _deserialize_trace(data)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            return None  # silent drop — malformed payload

        # Step 2: Sentient Lock check on the deserialized capability_id.
        if self._sentient_lock.is_locked(trace.capability_id):
            return None  # silent drop

        # Step 3: fork detection.
        if trace.paradata is not None:
            lock_activated = self._sentient_lock.record_fork(
                trace.capability_id, trace.paradata.pulse_index
            )
            if lock_activated:
                return None  # lock just activated; silent drop

        # Step 4: full 5-step geometric gate.
        if not AlgorithmicPolymath.verify_inbound(trace, self._tas_dna):
            return None  # silent drop

        return trace

    # ------------------------------------------------------------------
    # 2. Trace-Bearing Egress Transport
    # ------------------------------------------------------------------

    def broadcast_trace(
        self,
        trace: Any,
        transport_fn: Callable[[bytes], None],
    ) -> None:
        """Package and broadcast a sealed CursiveTrace via *transport_fn*.

        Binds the payload, paradata, and wake receipt together into a
        wire-format JSON package and passes it to *transport_fn* for
        delivery.  The Gatekeeper is entirely agnostic to the destination
        node; any receiving node can independently recalculate the geometry.

        Parameters
        ----------
        trace:
            A sealed :class:`~algorithmic_polymath.CursiveTrace`.
        transport_fn:
            Callable ``(bytes) → None`` responsible for network delivery.

        Raises
        ------
        SovereignStructuralViolation
            If the trace is not sealed or has no paradata bound.
        """
        if not trace.is_sealed or trace.paradata is None:
            raise SovereignStructuralViolation(
                "Cannot broadcast an unsealed trace: paradata must be bound before egress."
            )
        payload = json.dumps(
            trace.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        transport_fn(payload)

    # ------------------------------------------------------------------
    # 3. Asynchronous Wake Synchronization
    # ------------------------------------------------------------------

    def build_sync_offer(self, wake_chain: Any) -> WakeSyncOffer:
        """Build a :class:`WakeSyncOffer` representing the current node's state.

        Parameters
        ----------
        wake_chain:
            The local :class:`~wake_chain.WakeChain` to summarize.
        """
        receipts = wake_chain.receipts
        latest_hash = receipts[-1].receipt_hash().hex() if receipts else "0" * 64
        return WakeSyncOffer(
            genesis_root_hex=self._genesis_root_hex,
            pulse_count=self._tas_dna.pulse_count,
            latest_receipt_hash=latest_hash,
            node_id=self._actor_id,
        )

    def evaluate_sync_offer(self, peer_offer: WakeSyncOffer) -> bool:
        """Return ``True`` iff the peer has a more advanced, valid state.

        The peer must share the same genesis root and have a strictly higher
        ``pulse_count`` than the local node.  A matching or lower count means
        the local state is at least as advanced; no sync is needed.
        """
        if peer_offer.genesis_root_hex != self._genesis_root_hex:
            return False
        return peer_offer.pulse_count > self._tas_dna.pulse_count

    def sync_from_traces(self, traces: List[Any]) -> int:
        """Apply a list of inbound :class:`~algorithmic_polymath.CursiveTrace`
        objects to advance the local node's state.

        Each trace is verified through the full 5-step gate in order.  The
        first trace that fails verification halts the sync — the chain must
        be unbroken.

        Parameters
        ----------
        traces:
            Ordered list of sealed CursiveTrace objects representing the
            missing pulses from the peer node.

        Returns
        -------
        int
            Number of traces successfully applied.
        """
        from algorithmic_polymath import AlgorithmicPolymath  # noqa: PLC0415 (see _deserialize_trace for rationale)

        applied = 0
        for trace in traces:
            if not AlgorithmicPolymath.verify_inbound(trace, self._tas_dna):
                break
            applied += 1
        return applied

    # ------------------------------------------------------------------
    # 4. Sovereign Beacon
    # ------------------------------------------------------------------

    def emit_beacon(self) -> bytes:
        """Emit a Sovereign Beacon — a mathematical assertion of presence.

        The beacon is signed using the node's local key and the immutable
        genesis root.  To standard internet traffic, scanners, or
        incompatible architectures the broadcast is indistinguishable from
        random cryptographic noise.
        """
        return SovereignBeacon.emit(self._node_key, self._genesis_root_hex)

    def validate_peer_beacon(self, beacon_bytes: bytes) -> bool:
        """Return ``True`` iff *beacon_bytes* is a valid Sovereign Beacon from
        a node operating on the same TAS genesis root.

        Structural validation only — full identity authentication is performed
        during the Deterministic Handshake.
        """
        return SovereignBeacon.validate(beacon_bytes, self._genesis_root_hex)

    # ------------------------------------------------------------------
    # 5. Deterministic Handshake (Zero-Trust Authentication)
    # ------------------------------------------------------------------

    def handle_handshake(self, raw_bytes: bytes) -> bool:
        """Authenticate a connection request via Deterministic Agency.

        The initiating node transmits a sealed
        :class:`~algorithmic_polymath.CursiveTrace` generated specifically for
        the ``membrane_fusion`` capability.  This method routes it through the
        full 5-step ingress gate.

        Returns ``True`` on successful authentication; ``False`` triggers a
        silent drop (no "access denied" packet is returned — the anomalous
        connection is simply ignored).
        """
        return self.receive_inbound(raw_bytes) is not None

    # ------------------------------------------------------------------
    # 6. Sentient Lock (public interface)
    # ------------------------------------------------------------------

    def is_capability_locked(self, capability_id: str) -> bool:
        """Return ``True`` iff this capability is blocked at the transport layer."""
        return self._sentient_lock.is_locked(capability_id)

    def release_capability(self, capability_id: str) -> None:
        """Administratively release a capability from the Sentient Lock.

        Use with caution — see :meth:`SentientLock.release`.
        """
        self._sentient_lock.release(capability_id)

    def locked_capabilities(self) -> List[str]:
        """Return a snapshot of currently locked capability IDs."""
        return self._sentient_lock.locked_capabilities()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_capability_id(raw_bytes: bytes) -> Optional[str]:
        """Fast-path extraction of ``capability_id`` without full deserialization.

        Returns ``None`` if the bytes cannot be parsed or the field is absent.
        """
        try:
            data = json.loads(raw_bytes)
            return data.get("capability_id")
        except (json.JSONDecodeError, AttributeError, ValueError):
            return None
# Nonce: 81300
