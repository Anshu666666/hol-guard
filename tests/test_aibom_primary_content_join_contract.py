"""Proposed differential controls for the unselected RSP-130 content join."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import aibom_content_upload as upload
from codex_plugin_scanner.guard.aibom_content_upload import GuardAibomPrimaryContentSource
from codex_plugin_scanner.guard.inventory_contract_models import GuardAgentInventorySnapshot

_BUILTIN_TUPLE = tuple


def _snapshot(key: str) -> GuardAgentInventorySnapshot:
    return GuardAgentInventorySnapshot(
        snapshot_id=key, agent_id="codex:local", agent_type="codex", generated_at="2026-09-19T00:00:00Z"
    )


def _source(key: str, ordinal: int) -> GuardAibomPrimaryContentSource:
    return GuardAibomPrimaryContentSource(
        agent_id="codex:local",
        allowed_root=Path("/tmp/rsp130-public-fixture"),
        content_hash="sha256:" + "0" * 64,
        harness_id="codex",
        item_id=f"item-{ordinal}",
        item_kind="skill",
        mime_type="text/markdown",
        path=Path("/tmp/rsp130-public-fixture") / f"item-{ordinal}.md",
        snapshot_id=key,
        version_id=f"version-{ordinal}",
    )


def _original_join(snapshots, primary_content_sources):
    content_sources_by_snapshot: dict[str, tuple[GuardAibomPrimaryContentSource, ...]] = {}
    for snapshot in snapshots:
        content_sources_by_snapshot[snapshot.snapshot_id] = tuple(
            source for source in primary_content_sources if source.snapshot_id == snapshot.snapshot_id
        )
    return content_sources_by_snapshot


def _candidate_join(snapshots, primary_content_sources):
    indexed = upload._indexed_primary_content_sources(snapshots, primary_content_sources, tuple_factory=tuple)
    if indexed is not None:
        return indexed
    content_sources_by_snapshot: dict[str, tuple[GuardAibomPrimaryContentSource, ...]] = {}
    for snapshot in snapshots:
        content_sources_by_snapshot[snapshot.snapshot_id] = tuple(
            source for source in primary_content_sources if source.snapshot_id == snapshot.snapshot_id
        )
    return content_sources_by_snapshot


def _same(left, right, *, identical_keys=True):
    assert list(left) == list(right)
    for first, second in zip(left, right, strict=True):
        if identical_keys:
            assert first is second
        assert _BUILTIN_TUPLE(map(id, left[first])) == _BUILTIN_TUPLE(map(id, right[second]))


@pytest.mark.parametrize(
    ("snapshot_keys", "source_keys"),
    [
        ((), ()),
        (("a", "b"), ()),
        (("a",), ("a", "unmatched", "a")),
        (("a", "b"), ("b", "a", "b", "a")),
        (("a", "a", "b"), ("a", "b", "a")),
        (("a", "b"), ("unmatched", "a", "b", "unmatched")),
        (("alpha", "a\u0301", "\u00e1"), ("\u00e1", "alpha", "a\u0301", "alpha")),
    ],
)
def test_plain_keys_preserve_order_empty_groups_and_exact_source_objects(snapshot_keys, source_keys):
    snapshots = _BUILTIN_TUPLE(_snapshot(key) for key in snapshot_keys)
    sources = [_source(key, index) for index, key in enumerate(source_keys)]
    indexed = upload._indexed_primary_content_sources(snapshots, sources, tuple_factory=_BUILTIN_TUPLE)
    assert indexed is not None
    _same(_original_join(snapshots, sources), indexed)


def test_repeated_source_references_are_not_deduplicated():
    snapshots = (_snapshot("a"), _snapshot("b"))
    first, second = _source("a", 1), _source("b", 2)
    sources = [first, second, first, first]
    _same(_original_join(snapshots, sources), _candidate_join(snapshots, sources))
    assert _candidate_join(snapshots, sources)["a"] == (first, first, first)


def test_keys_are_captured_after_a_prior_callback_and_never_cached_across_calls():
    snapshots = (_snapshot("a"), _snapshot("b"))
    sources = [_source("a", 1), _source("b", 2)]
    _same(_original_join(snapshots, sources), _candidate_join(snapshots, sources))
    # Deliberately model a completed public provider callback before the join.
    object.__setattr__(snapshots[0], "snapshot_id", "changed")
    object.__setattr__(sources[0], "snapshot_id", "changed")
    indexed = upload._indexed_primary_content_sources(snapshots, sources, tuple_factory=_BUILTIN_TUPLE)
    assert indexed is not None
    _same(_original_join(snapshots, sources), indexed)
    assert list(indexed) == ["changed", "b"]


@pytest.mark.parametrize("which", ["snapshots", "sources"])
def test_custom_container_iteration_stays_on_the_original_loop(which):
    events = []

    class SnapshotTuple(_BUILTIN_TUPLE):
        def __iter__(self):
            events.append("snapshot-iteration")
            yield from _BUILTIN_TUPLE.__iter__(self)

    class SourceList(list):
        def __iter__(self):
            events.append("source-iteration")
            yield from list.__iter__(self)

    snapshots = (_snapshot("a"), _snapshot("b"))
    sources = [_source("a", 1), _source("b", 2)]
    if which == "snapshots":
        snapshots = SnapshotTuple(snapshots)
    else:
        sources = SourceList(sources)
    assert upload._indexed_primary_content_sources(snapshots, sources, tuple_factory=_BUILTIN_TUPLE) is None
    assert events == []
    expected = _original_join(snapshots, sources)
    expected_events = list(events)
    events.clear()
    actual = _candidate_join(snapshots, sources)
    assert events == expected_events
    _same(expected, actual)


@pytest.mark.parametrize("record_class", [GuardAgentInventorySnapshot, GuardAibomPrimaryContentSource])
def test_replaced_slot_property_keeps_every_original_read_and_its_order(monkeypatch, record_class):
    events = []
    snapshots = (_snapshot("a"), _snapshot("b"))
    sources = [_source("a", 1), _source("b", 2)]
    original_slot = record_class.__dict__["snapshot_id"]

    def read(record):
        value = original_slot.__get__(record, record_class)
        events.append((record_class.__name__, id(record), value))
        return value

    monkeypatch.setattr(record_class, "snapshot_id", property(read))
    assert upload._indexed_primary_content_sources(snapshots, sources, tuple_factory=_BUILTIN_TUPLE) is None
    assert events == []
    expected = _original_join(snapshots, sources)
    expected_events = list(events)
    events.clear()
    actual = _candidate_join(snapshots, sources)
    assert events == expected_events
    _same(expected, actual)


def test_replaced_getattribute_stays_on_the_original_loop(monkeypatch):
    events = []
    snapshots = (_snapshot("a"), _snapshot("b"))
    sources = [_source("a", 1), _source("b", 2)]

    def read(record, name):
        if name == "snapshot_id":
            events.append(id(record))
        return object.__getattribute__(record, name)

    monkeypatch.setattr(GuardAibomPrimaryContentSource, "__getattribute__", read)
    assert upload._indexed_primary_content_sources(snapshots, sources, tuple_factory=_BUILTIN_TUPLE) is None
    assert events == []
    expected = _original_join(snapshots, sources)
    expected_events = list(events)
    events.clear()
    actual = _candidate_join(snapshots, sources)
    assert events == expected_events
    _same(expected, actual)


def test_string_subclass_equality_mutation_keeps_original_comparison_and_assignment_order():
    events = []
    snapshot = _snapshot("a")

    class ChangingKey(str):
        __hash__ = str.__hash__

        def __eq__(self, other):
            events.append(("equality", str(self), other))
            object.__setattr__(snapshot, "snapshot_id", "after-equality")
            return str.__eq__(self, other)

    sources = [_source(ChangingKey("a"), 1)]
    snapshots = (snapshot,)
    assert upload._indexed_primary_content_sources(snapshots, sources, tuple_factory=_BUILTIN_TUPLE) is None
    assert events == []
    expected = _original_join(snapshots, sources)
    expected_events = list(events)
    object.__setattr__(snapshot, "snapshot_id", "a")
    events.clear()
    actual = _candidate_join(snapshots, sources)
    assert events == expected_events
    _same(expected, actual)
    assert list(actual) == ["after-equality"]


def test_replaced_tuple_factory_runs_before_generator_reads_and_target_key_assignment(monkeypatch):
    events = []
    snapshots = (_snapshot("a"),)
    sources = [_source("a", 1)]

    def changed_tuple(values):
        events.append("tuple")
        object.__setattr__(snapshots[0], "snapshot_id", "after-tuple")
        return _BUILTIN_TUPLE(values)

    monkeypatch.setitem(globals(), "tuple", changed_tuple)
    assert upload._indexed_primary_content_sources(snapshots, sources, tuple_factory=changed_tuple) is None
    assert events == []
    expected = _original_join(snapshots, sources)
    expected_events = list(events)
    object.__setattr__(snapshots[0], "snapshot_id", "a")
    events.clear()
    actual = _candidate_join(snapshots, sources)
    assert events == expected_events == ["tuple"]
    _same(expected, actual)
    assert list(actual) == ["after-tuple"] and actual["after-tuple"] == ()


def test_uninitialized_real_record_keeps_the_original_attribute_error():
    snapshots = (_snapshot("a"),)
    sources = [object.__new__(GuardAibomPrimaryContentSource)]
    assert upload._indexed_primary_content_sources(snapshots, sources, tuple_factory=_BUILTIN_TUPLE) is None
    with pytest.raises(AttributeError) as before:
        _original_join(snapshots, sources)
    with pytest.raises(AttributeError) as after:
        _candidate_join(snapshots, sources)
    assert str(before.value) == str(after.value)


@pytest.mark.parametrize("mutation_boundary", ["event", "batch"])
@pytest.mark.parametrize("acknowledged", [False, True])
def test_sync_reads_keys_after_live_callbacks_and_preserves_the_ack_gate(
    monkeypatch, tmp_path, mutation_boundary, acknowledged
):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import aibom_cli
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    snapshot = _snapshot("before-callback")
    source = _source("before-callback", 1)
    events = []
    saved = []

    def collect(_context, *, primary_content_sources, **_options):
        primary_content_sources.append(source)
        return (snapshot,)

    def mutate():
        events.append("mutated")
        object.__setattr__(snapshot, "snapshot_id", "after-callback")
        object.__setattr__(source, "snapshot_id", "after-callback")

    original_event = aibom_cli._inventory_snapshot_event
    original_batch = aibom_cli._batch_inventory_events

    def event(**kwargs):
        result = original_event(**kwargs)
        if mutation_boundary == "event":
            mutate()
        return result

    def batch(values):
        result = original_batch(values)
        if mutation_boundary == "batch":
            mutate()
        return result

    def request(_auth_context, *, request_url, method, data, extra_headers):
        events.append("request")
        assert method == "POST" and extra_headers is None
        return SimpleNamespace(data=data, full_url=request_url)

    def respond(**kwargs):
        assert kwargs["timeout_seconds"] == 90
        assert kwargs["retry_timeout_seconds"] == 120
        events.append("acknowledged" if acknowledged else "rejected")
        return {"accepted": int(acknowledged), "rejected": int(not acknowledged)}

    uploaded = []

    def upload_after_ack(_store, _runner, auth_context, *, sources, workspace_id):
        assert events[-1] == "acknowledged"
        assert workspace_id == "workspace-1"
        uploaded.append(sources)
        return upload.empty_content_upload_summary(), auth_context

    runner = SimpleNamespace(
        GuardSyncNotConfiguredError=RuntimeError,
        _guard_events_sync_url=lambda url: url,
        _guard_sync_request=request,
        _urlopen_json_with_timeout_retry=respond,
    )
    store = SimpleNamespace(
        hold_oauth_credential_lock=nullcontext,
        get_cloud_workspace_id=lambda: "workspace-1",
        set_sync_payload=lambda *args: saved.append(args),
    )
    monkeypatch.setattr(aibom_cli, "_runner_module", lambda: runner)
    monkeypatch.setattr(aibom_cli, "_resolve_trust_attestation_context", lambda *args, **kwargs: {})
    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", collect)
    monkeypatch.setattr(aibom_cli, "_inventory_snapshot_event", event)
    monkeypatch.setattr(aibom_cli, "_batch_inventory_events", batch)
    monkeypatch.setattr(aibom_cli, "upload_primary_content_sources", upload_after_ack)

    summary = aibom_cli.sync_aibom_snapshots(
        store,
        HarnessContext(home_dir=tmp_path / "home", workspace_dir=tmp_path / "workspace", guard_home=tmp_path / "guard"),
        generated_at="2026-09-19T00:00:00+00:00",
        auth_context={"sync_url": "https://hol.test/api/v1/guard/events"},
    )

    assert events == ["mutated", "request", "acknowledged" if acknowledged else "rejected"]
    assert uploaded == ([()] if acknowledged else [])
    assert summary["accepted"] == int(acknowledged)
    assert summary["content_upload"]["eligible"] == 0
    assert saved == [("aibom_sync_summary", summary, "2026-09-19T00:00:00+00:00")]


def test_custom_getattribute_descriptor_does_not_run_during_admission(monkeypatch):
    events = []
    snapshots = (_snapshot("a"), _snapshot("b"))
    sources = [_source("a", 1), _source("b", 2)]

    class AccessorDescriptor:
        def __get__(self, record, owner=None):
            events.append(("bind", record is None))

            def read(name):
                events.append(("read", id(record), name))
                return object.__getattribute__(record, name)

            return read

    monkeypatch.setattr(GuardAibomPrimaryContentSource, "__getattribute__", AccessorDescriptor())
    assert upload._indexed_primary_content_sources(snapshots, sources, tuple_factory=_BUILTIN_TUPLE) is None
    assert events == []
    expected = _original_join(snapshots, sources)
    expected_events = list(events)
    events.clear()
    actual = _candidate_join(snapshots, sources)
    assert events == expected_events
    assert all(value is False for kind, value, *rest in events if kind == "bind")
    _same(expected, actual)
