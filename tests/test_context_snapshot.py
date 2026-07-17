import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from context_snapshot import (
    ContextSnapshot,
    ContextValidationError,
    InMemoryContextResolver,
    InMemoryDefinitionResolver,
    canonical_json,
    definition_id_for_mapping,
    make_definition_record,
    resolve_verified_context,
)


def _fixtures():
    definition = make_definition_record(
        namespace_id="tas:core",
        term="authorized",
        semantic_version="1",
        definition="Authenticated external authority with valid scope.",
    )
    definition_id = definition_id_for_mapping(definition)
    snapshot = ContextSnapshot.build(
        namespace_id="tas:core",
        context_sequence=0,
        definition_ids=[definition_id],
        invariant_set_id="b" * 64,
        authority_binding_hash="a" * 64,
        parent_context_hash=None,
        effective_epoch=7,
    )
    return definition, definition_id, snapshot


def test_context_snapshot_round_trip_pins_ordered_definitions():
    definition, definition_id, snapshot = _fixtures()
    context_resolver = InMemoryContextResolver(
        {snapshot.context_snapshot_hash: canonical_json(snapshot.mapping)},
        {snapshot.namespace_id: snapshot.context_snapshot_hash},
    )
    definition_resolver = InMemoryDefinitionResolver(
        {definition_id: canonical_json(definition)}
    )
    resolved = resolve_verified_context(
        context_snapshot_hash=snapshot.context_snapshot_hash,
        context_resolver=context_resolver,
        definition_resolver=definition_resolver,
    )
    assert resolved == snapshot


def test_context_hash_is_not_self_referential_and_detects_mutation():
    _, _, snapshot = _fixtures()
    mutated = snapshot.mapping
    mutated["effective_epoch"] = 8
    with pytest.raises(
        ContextValidationError, match="context_snapshot_hash mismatch"
    ):
        ContextSnapshot.from_raw(canonical_json(mutated))


def test_definition_content_cannot_be_swapped_behind_same_id():
    definition, definition_id, snapshot = _fixtures()
    swapped = dict(definition)
    swapped["definition"] = "A silently substituted meaning."
    context_resolver = InMemoryContextResolver(
        {snapshot.context_snapshot_hash: canonical_json(snapshot.mapping)},
        {snapshot.namespace_id: snapshot.context_snapshot_hash},
    )
    definition_resolver = InMemoryDefinitionResolver(
        {definition_id: canonical_json(swapped)}
    )
    with pytest.raises(ContextValidationError, match="DefinitionID"):
        resolve_verified_context(
            context_snapshot_hash=snapshot.context_snapshot_hash,
            context_resolver=context_resolver,
            definition_resolver=definition_resolver,
        )


def test_stale_context_is_not_executable_after_namespace_head_advances():
    definition, definition_id, snapshot = _fixtures()
    context_resolver = InMemoryContextResolver(
        {snapshot.context_snapshot_hash: canonical_json(snapshot.mapping)},
        {snapshot.namespace_id: "f" * 64},
    )
    definition_resolver = InMemoryDefinitionResolver(
        {definition_id: canonical_json(definition)}
    )
    with pytest.raises(ContextValidationError, match="active namespace head"):
        resolve_verified_context(
            context_snapshot_hash=snapshot.context_snapshot_hash,
            context_resolver=context_resolver,
            definition_resolver=definition_resolver,
        )
