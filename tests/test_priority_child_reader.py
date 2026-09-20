"""Strict record and exact explanatory population controls, without native work."""

from __future__ import annotations

import copy
import hashlib
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.ci.priority_launcher_child.installation import canonical
from scripts.ci.priority_launcher_child.population import measure_selected
from scripts.ci.priority_launcher_child.reader import coordinates, validate


def document() -> dict[str, Any]:
    return {
        "schema": "hol-guard.priority-child-profile.v2",
        "pid": 99,
        "parent_pid": 98,
        "argv_sha256": hashlib.sha256(canonical(["python", "-I", "script"])).hexdigest(),
        "registered_argv_sha256": hashlib.sha256(canonical(["python", "-I", "script"])).hexdigest(),
        "configuration_sha256": "a" * 64,
        "isolated_flag": True,
        "records": [
            {
                "index": 0,
                "stage": "outer",
                "thread": 0,
                "thread_kind": "main",
                "parent": None,
                "start_ns": 100,
                "end_ns": 200,
                "termination": "profile_return_or_unwind",
            },
            {
                "index": 1,
                "stage": "inner",
                "thread": 0,
                "thread_kind": "main",
                "parent": 0,
                "start_ns": 120,
                "end_ns": 180,
                "termination": "profile_return_or_unwind",
            },
        ],
        "callback_count": 4,
        "callback_ns": 2,
        "setup_ns": 3,
        "finish_prewrite_ns": 1,
        "module_roster_before": ["sys"],
        "module_roster_after_setup": ["json", "sys"],
        "faults": [],
        "open_spans": 0,
        "profile_restored": True,
        "observation_complete": True,
        "callbacks_in_flight_at_snapshot": 0,
        "callback_threads_seen": 1,
        "worker_hooks_not_retired": 0,
        "current_worker_threads_at_snapshot": 0,
        "thread_census_complete": True,
        "qualification_eligible": False,
        "return_events_prove_success": False,
    }


def check(value):
    return validate(
        value,
        pid=99,
        parent_pid=98,
        argv=["python", "-I", "script"],
        configuration_sha="a" * 64,
        allowed_stages={"outer", "inner"},
    )


def test_actual_schema_admission_does_not_mutate_input():
    value = document()
    original = copy.deepcopy(value)
    assert check(value) == original and value == original


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("index", -1),
        ("index", 0),
        ("parent", -1),
        ("parent", 2),
        ("thread", 4),
        ("thread", 1),
        ("start_ns", 0),
        ("end_ns", 201),
        ("stage", "PRIVATE_VALUE"),
        ("termination", "success"),
    ],
)
def test_malformed_frame_refused(field, value):
    body = document()
    body["records"][1][field] = value
    with pytest.raises(ValueError):
        check(body)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pid", 97),
        ("argv_sha256", "b" * 64),
        ("configuration_sha256", "b" * 64),
        ("isolated_flag", False),
        ("qualification_eligible", True),
        ("profile_restored", False),
        ("callbacks_in_flight_at_snapshot", 1),
        ("worker_hooks_not_retired", 1),
        ("current_worker_threads_at_snapshot", 1),
        ("thread_census_complete", False),
        ("open_spans", 1),
        ("callback_count", 500002),
        ("return_events_prove_success", True),
    ],
)
def test_false_identity_or_complete_claim_refused(field, value):
    body = document()
    body[field] = value
    with pytest.raises(ValueError):
        check(body)


def test_duplicate_json_and_extra_private_field_refused():
    from scripts.ci.priority_launcher_child.profile_runtime import pairs

    with pytest.raises(ValueError):
        pairs([("pid", 1), ("pid", 2)])
    body = document()
    body["private_payload"] = "PRIVATE_VALUE"
    with pytest.raises(ValueError):
        check(body)


def test_declared24_population_is_strict_subset():
    rows = coordinates()
    assert len(rows) == len({tuple(row.values()) for row in rows}) == 24
    assert sum(row["sample"] == -1 for row in rows) == 8
    assert all(row["harness"] == "claude-code" and row["event"] == "PostToolUse" for row in rows[8:])


@pytest.mark.parametrize("fail_at", [None, 0, 7, 8])
def test_original_population_order_arguments_and_first_failure(fail_at):
    calls = []
    registrations = [
        SimpleNamespace(harness=h, event=e, config_path=f"{h}-{e}")
        for h in ("claude-code", "codex")
        for e in ("PreToolUse", "PostToolUse")
    ]
    sentinel = RuntimeError("original")
    session = object()

    def observe(actual_session, launcher, *, sample, case):
        assert actual_session is session
        calls.append((launcher.harness, launcher.event, sample, case))
        if len(calls) - 1 == fail_at:
            raise sentinel
        return SimpleNamespace(latency_ms=1.0, allowed=case == "benign")

    def concurrent(actual_session, launcher, count):
        assert actual_session is session and launcher is registrations[1] and count == 1
        calls.append("original_concurrent_once")
        if fail_at == 8:
            raise sentinel
        return [1.0] * 16

    producer = SimpleNamespace(
        registered_launcher=lambda path, h, e: next(x for x in registrations if x.config_path == path),
        _route_snapshot=lambda *a, **k: {},
        _require_native_count=lambda *a: None,
        observe_priority_launcher=observe,
        _concurrent_series=concurrent,
    )
    if fail_at is None:
        report, raw = measure_selected(session, producer, registrations)
        assert report["preflight_count"] == 8 and len(raw["claude_post_c16"]) == 16
        assert calls[-1] == "original_concurrent_once"
    else:
        with pytest.raises(RuntimeError) as caught:
            measure_selected(session, producer, registrations)
        assert caught.value is sentinel and len(calls) == fail_at + 1
    assert calls[: min(8, len(calls))] == [tuple(row.values()) for row in coordinates()[: min(8, len(calls))]]


@pytest.mark.parametrize("mutation", ["none", "private_value", "false", "records", "missing_fault", "complete"])
def test_withheld_field_cannot_export_arbitrary_content(mutation):
    body = document()
    body.update(records=[], records_withheld=True, faults=["report_byte_limit"], observation_complete=False)
    if mutation == "private_value":
        body["records_withheld"] = {"private": "PRIVATE_VALUE"}
    elif mutation == "false":
        body["records_withheld"] = False
    elif mutation == "records":
        body["records"] = document()["records"]
    elif mutation == "missing_fault":
        body["faults"] = []
    elif mutation == "complete":
        body["observation_complete"] = True
    if mutation == "none":
        assert check(body) is body
    else:
        with pytest.raises(ValueError, match="withheld_scope"):
            check(body)


@pytest.mark.parametrize("mutation", ["changed_kind", "two_mains"])
def test_thread_attribution_must_be_stable_and_unique(mutation):
    body = document()
    if mutation == "changed_kind":
        body["records"][1]["thread_kind"] = "worker"
    else:
        body["records"][1].update(thread=1, parent=None)
    with pytest.raises(ValueError, match=r"thread_kind_changed|main_thread_unique"):
        check(body)
