import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RECEIPT_PATH = REPO_ROOT / "artifacts" / "artifact-audit-decision-odessa-edge-case-001.json"


def test_odessa_edge_case_receipt_is_refusal_pending_parameters():
    receipt = json.loads(RECEIPT_PATH.read_text(encoding="utf-8"))

    assert receipt["operation"] == "audit_decision"
    assert receipt["receipt"] == "FORENSIC-ODESSA-EDGE-CASE-001"
    assert receipt["decision_gate"]["decision"] == "REFUSAL-PENDING-PARAMETERS"
    assert receipt["forensic_trace"]["replay_material"]["decision"] == "REFUSAL-PENDING-PARAMETERS"
    assert receipt["forensic_trace"]["rejected_logic_leaps"]
