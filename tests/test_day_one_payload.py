import importlib.util
import pathlib
import sys


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "day-one-payload-steward.py"
spec = importlib.util.spec_from_file_location("day_one_payload_steward", MODULE_PATH)
steward = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = steward
spec.loader.exec_module(steward)


def test_workflow_command_targets_release_docker():
    command = steward.build_workflow_command(".github/workflows/release-docker.yml", "main")
    assert command == "gh workflow run release-docker.yml --ref main"


def test_receipt_binds_intent_to_workflow_hash():
    workflow = steward.REPO_ROOT / steward.DEFAULT_WORKFLOW
    receipt = steward.build_receipt("test-intent", workflow, "workflow", "main")
    assert receipt.intent == "test-intent"
    assert receipt.target == ".github/workflows/release-docker.yml"
    assert receipt.command == "gh workflow run release-docker.yml --ref main"
    assert len(receipt.workflow_sha256) == 64
    assert len(receipt.receipt_sha256) == 64
