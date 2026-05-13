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
    receipt = steward.build_receipt("test-intent", workflow, "workflow", "HEAD")
    assert receipt.intent == "test-intent"
    assert receipt.target == ".github/workflows/release-docker.yml"
    assert receipt.command == "gh workflow run release-docker.yml --ref HEAD"
    assert len(receipt.workflow_sha256) == 64
    assert len(receipt.receipt_sha256) == 64


def test_workflow_receipt_uses_hash_from_dispatched_ref(monkeypatch):
    workflow = steward.REPO_ROOT / steward.DEFAULT_WORKFLOW

    def fake_sha256_file_at_ref(ref, relative_path):
        assert ref == "main"
        assert relative_path == ".github/workflows/release-docker.yml"
        return "a" * 64

    monkeypatch.setattr(steward, "sha256_file_at_ref", fake_sha256_file_at_ref)
    receipt = steward.build_receipt("test-intent", workflow, "workflow", "main")
    assert receipt.workflow_sha256 == "a" * 64


def test_local_receipt_uses_local_workflow_hash(monkeypatch):
    workflow = steward.REPO_ROOT / steward.DEFAULT_WORKFLOW

    def fail_if_called(*_):
        raise AssertionError("unexpected call")

    monkeypatch.setattr(steward, "sha256_file_at_ref", fail_if_called)
    receipt = steward.build_receipt("test-intent", workflow, "local", "main")
    assert receipt.workflow_sha256 == steward.sha256_file(workflow)
