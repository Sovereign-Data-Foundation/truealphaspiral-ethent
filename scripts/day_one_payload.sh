#!/usr/bin/env bash
# Day One human-stewarded entrypoint for TAS deterministic release admission.
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "${SCRIPT_DIR}/day-one-payload-steward.py" "$@"
