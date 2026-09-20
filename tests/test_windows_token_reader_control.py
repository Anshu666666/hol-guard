from __future__ import annotations

import errno
import json
import os

import pytest

from ci.native_runtime import windows_token_reader_control as controls
from codex_plugin_scanner.guard.daemon import manager


@pytest.mark.parametrize("route", controls.ROUTES)
@pytest.mark.parametrize("phase", controls.PHASES)
def test_actual_filesystem_cases_preserve_outcome_and_close_readers(route: str, phase: str) -> None:
    report = controls.run_case(route, phase)

    assert report["control_complete"], report
    assert report["writer_calls"] == report["replace_calls"] == 1
    assert report["fixture_directory_removed"]
    assert report["temporary_siblings_removed"]
    assert report["reader_thread_finished"] and report["writer_thread_finished"]
    if phase == "held_reader":
        assert report["reader_open_before_writer"]
        assert report["writer_finished_before_release"]
        assert report["expected_windows_sharing_failure"] is (os.name == "nt")
    elif phase == "released_reader":
        assert report["reader_closed_before_writer"]
        assert report["replace_error"] is None


class _FailingReplace:
    def __init__(self, error: OSError) -> None:
        self.error = error

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)

    def replace(self, *_args: object) -> None:
        raise self.error


def test_original_replace_failure_is_retained_without_error_message_or_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = PermissionError(errno.EACCES, "unretained-message", "unretained-private-path")
    monkeypatch.setattr(manager, "os", _FailingReplace(error))
    report = controls.run_case("bounded_manager", "released_reader")

    assert not report["control_complete"]
    assert report["original_replace_error_retained"]
    assert report["replace_calls"] == report["writer_calls"] == 1
    assert report["writer_error"] == report["replace_error"]
    assert report["replace_error"] == {"kind": "PermissionError", "errno": errno.EACCES, "winerror": None}
    assert report["final_value"] == "old"
    assert report["fixture_directory_removed"] and report["reader_closed"]
    encoded = json.dumps(report)
    assert "unretained-message" not in encoded
    assert "unretained-private-path" not in encoded


def test_writer_noop_is_incomplete_and_still_releases_original_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(manager, "_write_private_atomic_text", lambda *_args: None)
    report = controls.run_case("codex_path_read_text", "held_reader")

    assert not report["control_complete"]
    assert report["writer_calls"] == 1
    assert report["replace_calls"] == 0
    assert report["reader_closed"] and report["reader_thread_finished"]
    assert report["writer_thread_finished"] and report["fixture_directory_removed"]
    assert report["final_value"] == "old"


def test_error_record_uses_closed_kind_and_integer_codes_only() -> None:
    error = OSError(errno.EIO, "unretained-message")
    error.winerror = 32
    assert controls.error_record(error) == {"kind": "OSError", "errno": errno.EIO, "winerror": 32}
    assert controls.error_record(KeyError("unretained-secret")) == {
        "kind": "unregistered_error",
        "errno": None,
        "winerror": None,
    }
    assert controls.error_record(None) is None


@pytest.mark.parametrize(("route", "phase"), [("bad", "held_reader"), ("bounded_manager", "bad")])
def test_invalid_case_does_not_run_an_operation(route: str, phase: str) -> None:
    with pytest.raises(ValueError, match="control_case_invalid"):
        controls.run_case(route, phase)
