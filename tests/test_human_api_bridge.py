from human_api_bridge import (
    DEFAULT_RELEASE_COMMAND,
    BridgeDecision,
    DelegatedAuthority,
    HumanApiBridge,
    HumanIntent,
    build_day_one_bridge,
)


def test_day_one_bridge_admits_release_workflow_command():
    bridge = build_day_one_bridge("TAS Clean Stack")
    receipt = bridge.decide(DEFAULT_RELEASE_COMMAND)

    assert receipt.decision == BridgeDecision.RECEIPT
    assert receipt.command == DEFAULT_RELEASE_COMMAND
    assert receipt.reason == "command admitted by human-scoped bridge"
    assert bridge.replay([receipt])


def test_bridge_refuses_out_of_scope_command_with_replayable_proof():
    bridge = build_day_one_bridge("TAS Clean Stack")
    receipt = bridge.decide("gh pr merge 106 --merge")

    assert receipt.decision == BridgeDecision.REFUSAL
    assert receipt.reason == "command outside delegated scope"
    assert receipt.command_hash != ""
    assert bridge.replay([receipt])


def test_delegated_authority_deduplicates_scope_commands():
    intent = HumanIntent(steward_label="HumanAPI Key 001", issued_at_utc="2026-05-14T00:00:00Z")
    authority = DelegatedAuthority.from_intent(intent, [DEFAULT_RELEASE_COMMAND, DEFAULT_RELEASE_COMMAND])

    assert authority.allowed_commands == (DEFAULT_RELEASE_COMMAND,)
    assert authority.permits(DEFAULT_RELEASE_COMMAND)


def test_replay_rejects_tampered_command():
    bridge = HumanApiBridge(
        DelegatedAuthority.from_intent(
            HumanIntent(steward_label="HumanAPI Key 001", issued_at_utc="2026-05-14T00:00:00Z"),
            [DEFAULT_RELEASE_COMMAND],
        )
    )
    receipt = bridge.decide(DEFAULT_RELEASE_COMMAND)
    tampered = type(receipt)(
        decision=receipt.decision,
        command="gh workflow run release-docker.yml --ref dev",
        intent_hash=receipt.intent_hash,
        scope_hash=receipt.scope_hash,
        command_hash=receipt.command_hash,
        reason=receipt.reason,
        wake_seq=receipt.wake_seq,
        wake_receipt_hash=receipt.wake_receipt_hash,
        timestamp_utc=receipt.timestamp_utc,
    )

    assert not bridge.replay([tampered])
