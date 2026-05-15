#!/usr/bin/env python3
"""Day One steward directive for deterministic TAS release admission.

This module does not merge pull requests. It records the steward's explicit
intent, verifies the deterministic release workflow target, and prints the exact
local or GitHub Actions command that should be executed next.
"""
# © 2025 Russell Nordland | TrueAlphaSpiral (TAS) | Apache-2.0

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import time
from dataclasses import asdict, dataclass
from typing import Sequence

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_WORKFLOW = ".github/workflows/release-docker.yml"
DEFAULT_INTENT = "initiate-day-one-deterministic-release"


@dataclass(frozen=True)
class DayOneReceipt:
    """Human intent receipt for a Day One payload admission decision."""

    intent: str
    target: str
    command: str
    workflow_sha256: str
    steward_mode: str
    timestamp_utc: str

    @property
    def receipt_sha256(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    """Return the SHA-256 digest for *path*."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_workflow_command(workflow: str, ref: str) -> str:
    """Build the explicit GitHub Actions dispatch command."""
    return f"gh workflow run {pathlib.PurePosixPath(workflow).name} --ref {ref}"


def build_local_command() -> str:
    """Build the local deterministic proof command used before dispatch."""
    return "docker build -t truealphaspiral/sovereign-container-1776:day-one . && docker run --rm truealphaspiral/sovereign-container-1776:day-one"


def build_receipt(intent: str, workflow: pathlib.Path, mode: str, ref: str) -> DayOneReceipt:
    """Create a Day One receipt without executing the selected command."""
    relative_workflow = workflow.relative_to(REPO_ROOT).as_posix() if workflow.is_relative_to(REPO_ROOT) else workflow.as_posix()
    command = build_workflow_command(relative_workflow, ref) if mode == "workflow" else build_local_command()
    return DayOneReceipt(
        intent=intent,
        target=relative_workflow,
        command=command,
        workflow_sha256=sha256_file(workflow),
        steward_mode=mode,
        timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


def write_receipt(receipt: DayOneReceipt, receipt_dir: pathlib.Path) -> pathlib.Path:
    """Persist a receipt JSON document and return its path."""
    receipt_dir.mkdir(parents=True, exist_ok=True)
    path = receipt_dir / f"day-one-{receipt.receipt_sha256[:16]}.json"
    payload = asdict(receipt) | {"receipt_sha256": receipt.receipt_sha256}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Record and print the Day One steward directive.")
    parser.add_argument("--intent", default=DEFAULT_INTENT, help="authenticated human intent label")
    parser.add_argument("--mode", choices=("local", "workflow"), default="workflow", help="next deterministic execution surface")
    parser.add_argument("--ref", default="main", help="git ref used for workflow dispatch")
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW, help="deterministic release workflow path")
    parser.add_argument("--receipt-dir", default="ledger/day_one", help="receipt output directory")
    parser.add_argument("--dry-run", action="store_true", help="print the directive without writing a receipt")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workflow = (REPO_ROOT / args.workflow).resolve()
    if not workflow.is_file():
        raise FileNotFoundError(f"deterministic release workflow not found: {workflow}")

    receipt = build_receipt(args.intent, workflow, args.mode, args.ref)
    output = asdict(receipt) | {"receipt_sha256": receipt.receipt_sha256}

    if not args.dry_run:
        receipt_path = write_receipt(receipt, REPO_ROOT / args.receipt_dir)
        output["receipt_path"] = receipt_path.relative_to(REPO_ROOT).as_posix() if receipt_path.is_relative_to(REPO_ROOT) else receipt_path.as_posix()

    print(json.dumps(output, indent=2, sort_keys=True))
    print(f"DAY_ONE_COMMAND={receipt.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
