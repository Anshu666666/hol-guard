"""Actual input-change branches with finite doubles and no external probes."""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from codex_plugin_scanner.guard.native_policy_snapshot_codec import _digest_v3
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs import (
    AUTHORITY_FILE_NAME,
    NATIVE_RUNTIME_STATE_DIRECTORY,
    NativePolicySnapshotPublisherInputs,
)

from predicate.bindings import Registry
from predicate.capture import Capture
from predicate.hooks import OwnedHooks
from predicate.reasons import changed_inputs, marker


class Publisher(NativePolicySnapshotPublisherInputs):
    def __init__(self, home: Path, previous: str | None, returned: str) -> None:
        self.guard_home = home
        self._condition = threading.Condition()
        self._acked, self._closed, self._epoch, self._snapshot = True, False, 1, None
        self._database_policy_fingerprint = previous
        self._observed_policy_fingerprint = None
        self._published_policy_fingerprint = (_digest_v3({"policy": "retained"}), "enforce", _digest_v3({}))
        self.returned = returned
        self.calls: list[tuple[str, bool]] = []

    def _database_policy_marker(self) -> str:
        self.calls.append(("marker", self._acked))
        return self.returned

    def _compiled_effective_policy(self) -> dict[str, object]:
        self.calls.append(("compile", self._acked))
        return {"policy": "retained", "mode": "enforce"}

    def _compiled_command_extensions(self) -> dict[str, object]:
        self.calls.append(("command_binding", self._acked))
        return {}


def fixture(home: Path, previous: str | None = "a" * 64, returned: str = "a" * 64):
    publisher = Publisher(home, previous, returned)
    session = SimpleNamespace(
        store=object(),
        daemon=SimpleNamespace(
            _server=SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher))
        ),
    )
    capture = Capture(session)
    registry = Registry.__new__(Registry)
    registry.codes, registry.sites = {}, {}
    registry.add(sys._getframe(1).f_code, "control")
    registry.add(
        NativePolicySnapshotPublisherInputs._policy_input_changed.__code__,
        NativePolicySnapshotPublisherInputs.__module__,
    )
    return publisher, capture, OwnedHooks(capture, registry)


@pytest.mark.parametrize(
    "case,changed,branch,expected,compiled_acked,marker_calls",
    [
        ("none_initial", None, "empty_or_none_database_marker", False, True, 1),
        ("none_changed", None, "empty_or_none_database_marker", True, False, 1),
        ("empty_changed", set(), "empty_or_none_database_marker", True, False, 1),
        ("database_same", {"guard.db-wal"}, "database_paths_marker", False, None, 1),
        ("database_changed", {"guard.db-wal"}, "database_paths_marker", True, False, 1),
        ("database_and_control", {"guard.db", "CONTROL"}, "database_paths_marker", False, True, 1),
        ("control_only", {"CONTROL"}, "control_marker_only_compile", False, True, 0),
        ("config", {"config.toml"}, "non_database_metadata_force", True, False, 0),
        ("other", {"PRIVATE_WORKSPACE/.hol-guard.toml"}, "non_database_metadata_force", True, False, 0),
    ],
)
def test_actual_input_change_branch_only_observes_existing_calls(
    tmp_path, monkeypatch, case, changed, branch, expected, compiled_acked, marker_calls
):
    previous = None if case == "none_initial" else "a" * 64
    returned = "b" * 64 if case.endswith("changed") else "a" * 64
    publisher, capture, hooks = fixture(tmp_path, previous, returned)
    paths = (
        None
        if changed is None
        else {
            str(tmp_path / NATIVE_RUNTIME_STATE_DIRECTORY / AUTHORITY_FILE_NAME)
            if item == "CONTROL"
            else str(tmp_path / item)
            for item in changed
        }
    )
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("new external probe")

    monkeypatch.setattr(Path, "stat", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    try:
        hooks.add(Publisher, "_policy_input_changed", "policy_input_changed", "publisher")
        hooks.add(Publisher, "_database_policy_marker", "database_policy_marker", "publisher", project=marker)
        assert publisher._policy_input_changed(paths) is expected
    finally:
        hooks.close()
    assert hooks.restored and calls == []
    assert sum(name == "marker" for name, _ in publisher.calls) == marker_calls
    compile_states = [acked for name, acked in publisher.calls if name == "compile"]
    assert compile_states == ([] if compiled_acked is None else [compiled_acked])
    report = capture.freeze()
    assert report["observation_complete"]
    parent = report["rows"][0]
    assert parent["arguments"]["argument_branch"] == branch
    assert parent["before"]["database_marker"] == marker(previous)
    marker_rows = [row for row in report["rows"] if row["stage"] == "database_policy_marker"]
    assert len(marker_rows) == marker_calls
    if marker_rows:
        assert marker_rows[0]["returned"] == marker(returned)
        assert marker_rows[0]["parent"] == parent["id"]
    encoded = json.dumps(report)
    assert str(tmp_path) not in encoded and "PRIVATE_WORKSPACE" not in encoded


def test_changed_set_is_frozen_without_mutating_original(tmp_path):
    publisher, capture, hooks = fixture(tmp_path)
    value = {str(tmp_path / "PRIVATE_FIRST")}
    sentinel = object()

    class Target:
        def original(self: Any, paths):
            assert paths is value
            paths.add(str(tmp_path / "PRIVATE_SECOND"))
            return sentinel

    try:
        hooks.add(Target, "original", "policy_input_changed", "publisher")
        assert Target.original(publisher, value) is sentinel
    finally:
        hooks.close()
    assert len(value) == 2 and capture.rows[0]["arguments"]["count"] == 1
    assert "PRIVATE_" not in json.dumps(capture.freeze())


@pytest.mark.parametrize("error", [None, RuntimeError("PRIVATE_ERROR")])
def test_projection_refusal_preserves_original_call_result_or_error(tmp_path, error):
    publisher, capture, hooks = fixture(tmp_path)
    calls: list[Any] = []
    sentinel = object()

    class Target:
        def original(self: Any, paths):
            calls.append(paths)
            if error is not None:
                raise error
            return sentinel

    value = {1}
    try:
        hooks.add(Target, "original", "policy_input_changed", "publisher")
        if error is None:
            assert Target.original(publisher, value) is sentinel
        else:
            with pytest.raises(RuntimeError) as caught:
                Target.original(publisher, value)
            assert caught.value is error
    finally:
        hooks.close()
    assert calls == [value] and capture.freeze()["lost"]
    assert "PRIVATE_ERROR" not in json.dumps(capture.freeze())


@pytest.mark.parametrize("value", [{str(i) for i in range(4097)}, {"x" * 4097}, {object()}, []])
def test_changed_path_projection_refuses_shape_or_bound(tmp_path, value):
    with pytest.raises(ValueError):
        changed_inputs(value, tmp_path)


@pytest.mark.parametrize("value", ["PRIVATE", 1, True, "a" * 65])
def test_marker_projection_refuses_arbitrary_values(value):
    with pytest.raises(ValueError):
        marker(value)
