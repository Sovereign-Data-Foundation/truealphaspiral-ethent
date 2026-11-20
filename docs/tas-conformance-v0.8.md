# TAS v0.8 conformance boundary

`apply_authorized_transition` accepts only an Ed25519 statement signed by a
configured trusted epoch key, and requires a 256-level sparse proof of that
same canonical statement under the caller-configured SMT root. It applies the
permission meet and obligation join, then atomically compares and debits the
persisted account balance while writing the allocation digest and nonce to
SQLite. Balances are stored as decimal text so the full UInt64 range is
preserved. An account must be initialized by trusted setup before transitions;
stale balances and consumed nonces are rejected. Callers must supply the
trusted epoch-key map and configured root from their external trust
configuration; neither is inferred from the statement.

The configured SMT root is a commitment to the configured state tree. It is
not the recursion-derived empty root (the root obtained by repeatedly hashing
empty leaves and internal nodes). Implementations must not substitute one for
the other: the recursion-derived value is a proof-construction default, not an
authority anchor.

`vectors/tas_cross_lang_v0_8.csv` is the canonical arithmetic fixture. The
Python tests and Lean 4.11.0 executable both consume all 14 settlement and
UInt64 ledger-boundary rows. The GitHub Actions workflow runs both checks.
