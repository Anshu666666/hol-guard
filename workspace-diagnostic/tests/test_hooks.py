"""Actual publisher-method and filesystem controls; no native workload is run."""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher

from workspace_cause.capture import Capture
from workspace_cause.hooks import OwnedHooks


def bare_publisher(home: Path) -> NativePolicySnapshotPublisher:
    owner = NativePolicySnapshotPublisher.__new__(NativePolicySnapshotPublisher)
    owner.guard_home = home
    owner._condition = threading.Condition()
    owner._epoch, owner._acked, owner._closed, owner._last_error = 1, True, False, None
    owner._publish_event = threading.Event()
    owner._thread = None
    owner._snapshot = {"expires_at_ms": int(time.time() * 1000) + 60000, "generation": 1}
    owner._monotonic_clock, owner._wall_clock = time.monotonic, time.time
    return owner


def test_real_request_publish_alias_and_cleanup_are_distinct(tmp_path: Path) -> None:
    owner = bare_publisher(tmp_path)
    capture = Capture(tmp_path)
    with OwnedHooks(capture) as hooks:
        owner.request_publish()
        owner.notify_policy_changed()
        owner.close()
    rows = capture.freeze()["rows"]
    requests = [row for row in rows if row["stage"] == "request_publish"]
    closed = [row for row in rows if row["stage"] == "publisher_close"]
    assert len(requests) == 2 and len(closed) == 1
    assert [(row["before"]["epoch"], row["after"]["epoch"]) for row in requests] == [(1, 2), (2, 3)]
    assert closed[0]["before"]["closed"] is False and closed[0]["after"]["closed"] is True
    assert hooks.restored is True


def test_real_expiry_records_error_without_replacing_deadline(tmp_path: Path) -> None:
    owner = bare_publisher(tmp_path)
    owner._snapshot = {"expires_at_ms": 1, "generation": 1}
    capture = Capture(tmp_path)
    original_deadline = time.monotonic() - 1
    with OwnedHooks(capture):
        assert owner.wait_until_ready(deadline_monotonic=original_deadline) is False
    rows = capture.freeze()["rows"]
    waits = [row for row in rows if row["stage"] == "wait_ready"]
    expiry = [row for row in rows if row["stage"] == "mark_expired"]
    assert len(waits) == 1
    assert waits[0]["details"]["deadline_from_origin_ms"] == (original_deadline - capture.started) * 1000
    assert any(row["after"]["error"] == "native_policy_snapshot_expired" for row in expiry)
    assert owner._acked is False


def test_real_resident_confirmation_with_no_added_filesystem_calls(tmp_path: Path) -> None:
    owner = bare_publisher(tmp_path)
    directory = tmp_path / NATIVE_RUNTIME_STATE_DIRECTORY
    generation_dir = directory / "resident-v3-owned"
    generation_dir.mkdir(parents=True)
    generation_file = generation_dir / "generation-2.json"
    generation_file.write_text("owned fixture", encoding="utf-8")
    observed = owner._current_resident_fingerprint()
    observed_directory = owner._resident_directory_fingerprint()
    original_directory = NativePolicySnapshotPublisher._resident_directory_fingerprint
    original_paths = NativePolicySnapshotPublisher._resident_paths_match
    counts = {"directory": 0, "paths": 0}

    def counted_directory(current: NativePolicySnapshotPublisher) -> tuple[int, int] | None:
        counts["directory"] += 1
        return original_directory(current)

    def counted_paths(current: NativePolicySnapshotPublisher, sampled: tuple[tuple[str, int, int], ...]) -> bool:
        counts["paths"] += 1
        return original_paths(current, sampled)

    capture = Capture(tmp_path)
    with (
        patch.object(NativePolicySnapshotPublisher, "_resident_directory_fingerprint", counted_directory),
        patch.object(NativePolicySnapshotPublisher, "_resident_paths_match", counted_paths),
        OwnedHooks(capture),
    ):
        returned = owner._confirm_resident_fingerprint((), observed, 2, observed_directory)
    assert returned is observed
    assert counts == {"directory": 1, "paths": 1}
    rows = capture.freeze()["rows"]
    assert any(row["stage"] == "resident_generation" and row["outcome"] == "true" for row in rows)
    assert any(row["details"].get("confirmation_directory_equal") is True for row in rows)


def test_real_resident_confirmation_refusals_keep_their_original_paths(tmp_path: Path) -> None:
    owner = bare_publisher(tmp_path)
    directory = tmp_path / NATIVE_RUNTIME_STATE_DIRECTORY
    generation_dir = directory / "resident-v3-owned"
    generation_dir.mkdir(parents=True)
    generation_file = generation_dir / "generation-2.json"
    generation_file.write_text("owned fixture", encoding="utf-8")
    observed = owner._current_resident_fingerprint()
    observed_directory = owner._resident_directory_fingerprint()
    cases: tuple[
        tuple[str, tuple[tuple[str, int, int], ...], tuple[tuple[str, int, int], ...], int, tuple[int, int] | None], ...
    ] = (
        ("before", (("other-owned", 0, 0),), observed, 2, observed_directory),
        ("generation", (), observed, 1, observed_directory),
        ("missing_directory", (), observed, 2, None),
    )
    for name, before, sampled, generation, sampled_directory in cases:
        capture = Capture(tmp_path)
        with OwnedHooks(capture):
            assert owner._confirm_resident_fingerprint(before, sampled, generation, sampled_directory) is None
        rows = capture.freeze()["rows"]
        outer = rows[0]
        assert outer["stage"] == "resident_confirm" and outer["outcome"] == "none"
        if name == "before":
            assert outer["details"]["before_observed_equal"] is False and len(rows) == 1
        elif name == "generation":
            assert any(row["stage"] == "resident_generation" and row["outcome"] == "false" for row in rows)
        else:
            assert outer["details"]["observed_directory_present"] is False

    # A real same-path content/metadata change fails the existing sampled-path guard.
    metadata = generation_file.stat()
    generation_file.write_text("changed owned fixture", encoding="utf-8")
    os.utime(generation_file, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1000000000))
    capture = Capture(tmp_path)
    with OwnedHooks(capture):
        assert owner._confirm_resident_fingerprint((), observed, 2, observed_directory) is None
    assert any(row["stage"] == "resident_paths" and row["outcome"] == "false" for row in capture.freeze()["rows"])


def test_real_configuration_change_outcome_does_not_invent_invalidation(tmp_path: Path) -> None:
    owner = bare_publisher(tmp_path)
    owner.config_capture = None
    config = tmp_path / "config.toml"
    config.write_text('sandbox_analysis = "balanced"\n', encoding="utf-8")
    config.chmod(0o600)
    owner._compiled_config_inputs = {config: owner._capture_config_policy_input(config).identity}
    capture = Capture(tmp_path)
    with patch.object(NativePolicySnapshotPublisher, "_workspace_policy_paths", return_value=()), OwnedHooks(capture):
        assert owner._configuration_input_changed() is False
        config.write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
        assert owner._configuration_input_changed() is True
    rows = [row for row in capture.freeze()["rows"] if row["stage"] == "configuration_changed"]
    assert [row["outcome"] for row in rows] == ["false", "true"]
    # This method returns a change hint; its caller performs the request_publish.
    assert all(row["after"]["acked"] is True for row in rows)


def test_owned_filter_and_setup_failure_restore_exact_bindings(tmp_path: Path) -> None:
    class Owner:
        def __init__(self, home: Path) -> None:
            self.guard_home = home
            self.calls = 0

        def execute(self, value: object) -> object:
            self.calls += 1
            return value

    original = Owner.execute
    owned, other = Owner(tmp_path), Owner(tmp_path / "other")
    capture = Capture(tmp_path)
    hooks = OwnedHooks(capture)
    hooks.add(Owner, "execute", "authority_registry_read", "store")
    sentinel = object()
    assert owned.execute(sentinel) is sentinel and other.execute(sentinel) is sentinel
    hooks.close()
    assert Owner.execute is original and hooks.restored
    assert owned.calls == other.calls == 1 and len(capture.freeze()["rows"]) == 1

    originals = {
        name: getattr(NativePolicySnapshotPublisher, name) for name in ("_publish_once", "_publication_context")
    }
    broken = OwnedHooks(Capture(tmp_path))
    original_add = broken.add
    count = 0

    def fail_third(*args: Any, **kwargs: Any) -> None:
        nonlocal count
        count += 1
        if count == 3:
            raise RuntimeError("setup fault")
        original_add(*args, **kwargs)

    with patch.object(broken, "add", fail_third), pytest.raises(RuntimeError, match="setup fault"):
        broken.__enter__()
    assert all(getattr(NativePolicySnapshotPublisher, name) is value for name, value in originals.items())
    assert broken.restored is True


def test_real_input_fingerprint_equality_exports_no_source_names(tmp_path: Path) -> None:
    owner = bare_publisher(tmp_path)
    owner._input_fingerprint = ((("private-source-name", None),), ())
    capture = Capture(tmp_path)
    hooks = OwnedHooks(capture)
    result = ((("private-source-name", (1, 2, 3, 4)),), (("private-resident-name", 1, 2),))
    summary = hooks._summary("input_fingerprint", owner, result)
    assert summary == {
        "prior_input_present": True,
        "configuration_metadata_changed": True,
        "resident_metadata_changed": True,
    }
    assert "private" not in str(summary)
