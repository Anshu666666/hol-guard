"""Actual direct-child bounds and finite late/failed-cleanup controls."""

from __future__ import annotations

import errno
import json
import subprocess
import sys

from scripts.ci import native_macos_resolver_capture as capture


def test_actual_child_exit_and_private_output_are_preserved_without_export():
    report, data = capture.run_lookup(
        (sys.executable, "-I", "-c", "print('private-dns-value', flush=True); raise SystemExit(7)")
    )
    assert data == b"private-dns-value\n"
    assert report["return_code"] == 7 and report["direct_child_reaped"] is True
    assert report["termination_attempted"] is False
    assert not capture.clean_completion(report)
    assert "private-dns-value" not in json.dumps(report)
    assert report["descendant_retirement_verified"] is False


def test_actual_blocked_child_is_killed_and_reaped_after_original_deadline(monkeypatch):
    monkeypatch.setattr(capture, "LOOKUP_SECONDS", 0.5)
    report, data = capture.run_lookup(
        (sys.executable, "-I", "-c", "import time; print('prefix', flush=True); time.sleep(60)")
    )
    assert report["status"] == "deadline_exceeded"
    assert data == b"prefix\n"
    assert report["termination_attempted"] is True and report["direct_child_reaped"] is True
    assert report["return_code"] == -9 and not capture.clean_completion(report)


def test_actual_child_regular_file_output_is_kernel_bounded():
    report, data = capture.run_lookup((sys.executable, "-I", "-c", "import os; os.write(1, b'x' * 20000)"))
    assert data == b"x" * capture.CAPTURE_BYTES
    assert report["stdout_bytes"] == capture.CAPTURE_BYTES and report["output_limit"] is True
    assert report["direct_child_reaped"] is True and not capture.clean_completion(report)


def test_late_observed_success_keeps_original_exit_but_is_not_admitted(monkeypatch):
    class Process:
        pid = 123

        def wait(self, *, timeout):
            assert timeout == 5
            return 0

    moments = iter((0.0, 0.0, 5.1))
    monkeypatch.setattr(capture.time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(capture.subprocess, "Popen", lambda *_a, **_k: Process())
    report, _ = capture.run_lookup(("fixed-probe",))
    assert report["status"] == "deadline_exceeded" and report["return_code"] == 0
    assert report["direct_child_reaped"] is True and report["termination_attempted"] is False
    assert not capture.clean_completion(report)


def test_kill_and_reap_failure_are_both_retained(monkeypatch):
    class Process:
        pid = 123

        def wait(self, *, timeout):
            raise subprocess.TimeoutExpired("fixed-probe", timeout)

        def kill(self):
            raise OSError(errno.EPERM, "private-kill-message")

    monkeypatch.setattr(capture.subprocess, "Popen", lambda *_a, **_k: Process())
    report, _ = capture.run_lookup(("fixed-probe",))
    assert report["kill_errno"] == errno.EPERM and report["cleanup_error"] == "TimeoutExpired"
    assert report["direct_child_reaped"] is False and not capture.clean_completion(report)
    assert "private-kill-message" not in json.dumps(report)
