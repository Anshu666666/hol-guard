from __future__ import annotations

import threading
from typing import Any

import pytest

from scripts.ci.priority_launcher_phase.capture import Collector, Patches, bind, call, current, unbind
from scripts.ci.priority_launcher_phase.projection import freeze_input, parse_input
from scripts.native_slo_priority_launchers import launcher_payload


def _coordinate(sample: int = 0) -> dict[str, object]:
    return {"harness": "claude-code", "event": "PreToolUse", "sample": sample, "case": "benign"}


@pytest.mark.parametrize("original_raises", [False, True], ids=["return", "exception"])
@pytest.mark.parametrize("fault_at", ["none", "clock", "before", "after"], ids=["clear", "clock", "entry", "exit"])
def test_forward_once_preserves_objects_under_capture_faults(original_raises, fault_at):
    original_error = RuntimeError("original controlled failure")
    sentinel = object()
    positional, deadline = object(), object()
    observed: list[tuple[Any, Any]] = []

    def clock() -> int:
        if fault_at == "clock":
            raise RuntimeError("diagnostic clock failure")
        return 7

    collector = Collector("parent", clock=clock)
    row = collector.begin(_coordinate())
    assert row is not None
    tokens = bind(collector, row)

    def original(value, *, absolute_deadline):
        observed.append((value, absolute_deadline))
        if original_raises:
            raise original_error
        return sentinel

    def before(_row):
        if fault_at == "before":
            raise RuntimeError("diagnostic entry failure")

    def after(*_arguments):
        if fault_at == "after":
            raise RuntimeError("diagnostic exit failure")

    try:
        if original_raises:
            with pytest.raises(RuntimeError) as caught:
                call(
                    collector,
                    "spawn",
                    original,
                    (positional,),
                    {"absolute_deadline": deadline},
                    before=before,
                    after=after,
                )
            assert caught.value is original_error
        else:
            assert (
                call(
                    collector,
                    "spawn",
                    original,
                    (positional,),
                    {"absolute_deadline": deadline},
                    before=before,
                    after=after,
                )
                is sentinel
            )
    finally:
        unbind(tokens)
    assert observed == [(positional, deadline)]
    assert collector.faults == (0 if fault_at == "none" else 1)


def test_context_is_bound_per_actual_thread_and_nested_span():
    collector = Collector("daemon", clock=lambda: 100)
    rows = [collector.begin(_coordinate(index)) for index in range(2)]
    barrier = threading.Barrier(2)
    seen: list[tuple[int, int]] = []

    def invoke(index: int) -> None:
        row = rows[index]
        assert row is not None
        assert current(collector) is None
        tokens = bind(collector, row)
        try:

            def outer():
                barrier.wait(timeout=2)

                def inner():
                    active = current(collector)
                    assert active is row
                    seen.append((index, active.index))

                call(collector, "native_edge", inner, (), {})

            call(collector, "hook_handler", outer, (), {})
        finally:
            unbind(tokens)
        assert current(collector) is None

    threads = [threading.Thread(target=invoke, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=3)
        assert not thread.is_alive()
    assert sorted(seen) == [(0, 0), (1, 1)]
    for row in rows:
        assert row is not None
        assert [(item["stage"], item["parent_index"]) for item in row.stages] == [
            ("native_edge", 0),
            ("hook_handler", None),
        ]


def test_partial_patch_installation_restores_descriptor_after_setter_mutates_then_raises():
    def original():
        return "original"

    def replacement():
        return "replacement"

    class Target:
        def __init__(self):
            self.operation = original
            self.fail = True

        def __setattr__(self, name, value):
            object.__setattr__(self, name, value)
            if name == "operation" and value is replacement and getattr(self, "fail", False):
                object.__setattr__(self, "fail", False)
                raise RuntimeError("controlled setter failure")

    target = Target()
    collector = Collector("parent")
    patches = Patches(collector)
    with pytest.raises(RuntimeError):
        try:
            patches.set(target, "operation", replacement)
        finally:
            patches.close()
    assert target.operation is original
    assert patches.saved == [] and collector.restore_failures == 0


def test_instance_patch_restores_inherited_method_without_leaving_own_alias():
    class Owner:
        def operation(self):
            return self

    target = Owner()
    before = target.operation
    collector = Collector("parent")
    patches = Patches(collector)
    patches.wrap(target, "operation", "spawn")
    assert target.operation() is target
    patches.close()
    assert "operation" not in vars(target)
    assert target.operation == before


def test_immutable_nested_entry_survives_original_mutation():
    payload = launcher_payload("PostToolUse", 0)
    entry = freeze_input(payload, "claude-code")
    original_digest = entry.facts()["semantic_sha256"]
    response = payload["tool_response"]
    assert isinstance(response, list)
    response[0]["text"] = "mutated after entry"
    assert entry.facts()["semantic_sha256"] == original_digest
    with pytest.raises(ValueError, match="content_unknown"):
        freeze_input(payload, "claude-code")


@pytest.mark.parametrize(
    "field,value",
    [
        ("guard_remaining_ms", True),
        ("guard_remaining_ms", 0),
        ("guard_remaining_ms", 60001),
        ("unexpected", "private"),
        ("guard_codex_browser_wait_process", {"pid": 2, "startToken": "posix:synthetic"}),
    ],
    ids=["bool-budget", "zero-budget", "oversized-budget", "unknown-field", "unpaired-browser"],
)
def test_projection_rejects_undeclared_transformations(field, value):
    payload = launcher_payload("PreToolUse", 0)
    payload[field] = value
    with pytest.raises(ValueError):
        freeze_input(payload, "codex")


def test_known_budget_and_browser_transformations_have_distinct_full_but_equal_semantic_domains():
    original = launcher_payload("PreToolUse", 0)
    transformed = dict(original)
    transformed.update(
        guard_remaining_ms=3999,
        guard_codex_browser_wait_process={"pid": 2, "startToken": "posix:synthetic"},
        guard_codex_browser_wait_timeout_seconds=20,
    )
    first, second = freeze_input(original, "codex"), freeze_input(transformed, "codex")
    assert first.semantic == second.semantic
    assert first.full != second.full
    assert first.facts()["entry_projection_sha256"] != second.facts()["entry_projection_sha256"]
    with pytest.raises(ValueError, match="browser_route"):
        freeze_input(transformed, "claude-code")


def test_custom_containers_are_rejected_without_invoking_user_iteration():
    class Custom(dict):
        def items(self):
            raise AssertionError("custom iteration should not run")

        def __iter__(self):
            raise AssertionError("custom iteration should not run")

    with pytest.raises(ValueError, match="exact_dictionary"):
        freeze_input(Custom(), "claude-code")
    payload = launcher_payload("PreToolUse", 0)
    payload["tool_input"] = Custom(command="pwd")
    with pytest.raises(ValueError, match="projection_type"):
        freeze_input(payload, "claude-code")


@pytest.mark.parametrize("value", ['{"a":1,"a":2}', '{"a":"x"}' + " " * 32768], ids=["duplicate", "oversized"])
def test_actual_input_parser_rejects_duplicates_and_bounds(value):
    with pytest.raises(ValueError):
        parse_input(value)


def test_failure_tail_snapshot_does_not_wait_for_or_relabel_blocked_original_call():
    collector = Collector("parent", clock=lambda: 1)
    entered, release = threading.Event(), threading.Event()
    row = collector.begin(_coordinate())
    assert row is not None

    def worker():
        tokens = bind(collector, row)
        try:

            def original():
                entered.set()
                assert release.wait(timeout=3)
                return "unchanged"

            assert call(collector, "contained_process_call", original, (), {}) == "unchanged"
            collector.finish(row, None)
        finally:
            unbind(tokens)

    thread = threading.Thread(target=worker)
    thread.start()
    assert entered.wait(timeout=2)
    snapshot = collector.snapshot(original_success=False)
    assert snapshot["in_flight"] == 1
    assert snapshot["completed"] == 0
    assert snapshot["tail_complete"] is snapshot["observation_complete"] is False
    release.set()
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert snapshot["rows"][0]["completed"] is False
    assert snapshot["completed"] == 0


def test_row_and_stage_caps_are_explicit_without_replacing_operations():
    collector = Collector("parent", clock=lambda: 1)
    row = collector.begin(_coordinate())
    assert row is not None
    tokens = bind(collector, row)
    try:
        for index in range(35):
            assert call(collector, "spawn", lambda value: value, (index,), {}) == index
    finally:
        unbind(tokens)
    assert len(row.stages) == 32 and collector.stage_overflow == 3
    for _index in range(90):
        collector.begin(_coordinate())
    assert len(collector.rows) == 88 and collector.row_overflow == 3
    assert collector.snapshot(original_success=False)["observation_complete"] is False
