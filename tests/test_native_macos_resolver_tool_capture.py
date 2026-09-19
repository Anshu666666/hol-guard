"""Real command witnesses for stream caps without a process-wide file cap."""

from __future__ import annotations

import json
import resource
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from scripts.ci import native_macos_resolver_path as diagnostic
from scripts.ci import native_macos_resolver_tool_capture as capture
from scripts.ci.native_macos_service_identity import _capture as historical_capture


def _command(program, *arguments):
    return (sys.executable, "-I", "-c", program, *map(str, arguments))


def test_private_file_write_demonstrates_global_limit_interference(tmp_path):
    limits_before = resource.getrlimit(resource.RLIMIT_FSIZE)
    program = """
import errno, sys
from pathlib import Path
try:
    Path(sys.argv[1]).write_bytes(b'x' * (3 * 128 * 1024))
except OSError as error:
    if error.errno != errno.EFBIG:
        raise
    print('file-limit', flush=True)
    raise SystemExit(7)
print('cache-ok', flush=True)
"""
    previous = tmp_path / "old-cache"
    repaired = tmp_path / "new-cache"
    old = historical_capture(_command(program, previous))
    new = capture._capture(_command(program, repaired))
    assert old["return_code"] == 7 and old["stdout"] == "file-limit\n"
    assert previous.stat().st_size == 128 * 1024
    assert new["status"] == "completed" and new["return_code"] == 0
    assert new["stdout"] == "cache-ok\n" and new["stderr_bytes"] == 0
    assert repaired.stat().st_size == 3 * 128 * 1024
    assert new["direct_child_reaped"] and not new["termination_attempted"]
    assert new["process_file_size_limit_modified"] is False
    assert resource.getrlimit(resource.RLIMIT_FSIZE) == limits_before


@pytest.mark.parametrize("descriptor,label", [(1, "stdout"), (2, "stderr")])
def test_both_streams_remain_capped_and_overflow_is_failure(descriptor, label):
    result = capture._capture(_command(f"import os; os.write({descriptor}, b'x' * {capture.OUTPUT_LIMIT * 2})"))
    assert result["status"] == "output_limit" and result[label + "_truncated"]
    assert capture.OUTPUT_LIMIT <= result[label + "_bytes"] <= capture.OUTPUT_LIMIT + 1
    assert len(result[label]) <= capture.OUTPUT_LIMIT
    assert result["direct_child_reaped"] and not result["completed_without_intervention"]
    assert result["descendant_retirement_verified"] is False


def test_timeout_retains_observed_prefix_and_reaps_owned_child():
    result = capture._capture(_command("import time; print('prefix', flush=True); time.sleep(60)"), timeout=0.1)
    assert result["status"] == "deadline_exceeded"
    assert result["stdout"] == "prefix\n"
    assert result["termination_attempted"] and result["direct_child_reaped"]
    assert not result["completed_without_intervention"]


def test_nonzero_exit_is_retained_without_termination():
    result = capture._capture(_command("print('original'); raise SystemExit(72)"))
    assert result["status"] == "completed" and result["return_code"] == 72
    assert result["stdout"] == "original\n" and not result["termination_attempted"]
    assert result["direct_child_reaped"]


def test_late_final_wait_cannot_pass(monkeypatch):
    original = subprocess.Popen
    monotonic = time.monotonic
    clock_offset = [0.0]
    observed_exit = []

    monkeypatch.setattr(capture, "time", SimpleNamespace(monotonic=lambda: monotonic() + clock_offset[0]))

    def delayed_wait(*args, **kwargs):
        process = original(*args, **kwargs)
        wait = process.wait

        def late(*wait_args, **wait_kwargs):
            code = wait(*wait_args, **wait_kwargs)
            observed_exit.append(code)
            clock_offset[0] += capture.IDENTITY_SECONDS
            return code

        process.wait = late
        return process

    monkeypatch.setattr(capture.subprocess, "Popen", delayed_wait)
    result = capture._capture(_command("print('natural exit')"))
    assert observed_exit == [0] and result["stdout"] == "natural exit\n"
    assert result["status"] == "deadline_exceeded" and result["return_code"] == 0
    assert result["direct_child_reaped"] and not result["completed_without_intervention"]
    assert not result["termination_attempted"]


def test_startup_time_consumes_original_command_budget(monkeypatch):
    original = subprocess.Popen

    def delayed_start(*args, **kwargs):
        process = original(*args, **kwargs)
        time.sleep(0.06)
        return process

    monkeypatch.setattr(capture.subprocess, "Popen", delayed_start)
    result = capture._capture(_command("pass"), timeout=0.05)
    assert result["status"] == "deadline_exceeded" and result["direct_child_reaped"]
    assert not result["completed_without_intervention"]


def test_cleanup_errors_preserve_original_failure():
    class Unreaped:
        returncode = None

        def kill(self):
            raise PermissionError(1, "private error")

        def wait(self, *, timeout):
            assert timeout == 1.0
            raise subprocess.TimeoutExpired("private command", timeout)

    result = {"status": "deadline_exceeded", "direct_child_reaped": False}
    capture._retire(Unreaped(), result)
    assert result["status"] == "deadline_exceeded" and not result["direct_child_reaped"]
    assert result["kill_error"] == "PermissionError" and result["cleanup_error"] == "TimeoutExpired"
    assert "private" not in json.dumps(result)


def test_identity_error_exports_only_fixed_stderr_categories(monkeypatch):
    command = _command(
        "import sys; print('xcrun: unable to find utility private-path', file=sys.stderr); raise SystemExit(72)"
    )
    observed = capture._capture(command)
    monkeypatch.setattr(diagnostic, "_capture", lambda _arguments: observed)
    with pytest.raises(diagnostic.IdentityCommandError) as caught:
        diagnostic._fixed(("/usr/bin/xcrun", "--sdk", "macosx", "--find", "clang"))
    metadata = caught.value.metadata
    assert metadata["stderr_classes"] == ["tool_unavailable"]
    assert metadata["operation"] == "clang"
    assert "private-path" not in json.dumps(metadata)
    assert "stdout" not in metadata and "stderr" not in metadata and "argv" not in metadata


def test_default_deadline_and_source_closure_remain_bound():
    assert capture.IDENTITY_SECONDS == 5.0 and capture.OUTPUT_LIMIT == 128 * 1024
    assert "scripts/ci/native_macos_resolver_tool_capture.py" in diagnostic.SOURCES
    assert "tests/test_native_macos_resolver_tool_capture.py" in diagnostic.SOURCES
    assert ".github/workflows/native-macos-resolver-path.yml" in diagnostic.SOURCES
