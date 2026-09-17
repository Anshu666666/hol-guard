"""Read-only witnesses retain bounded categories and reap only owned children."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest

from scripts.ci import native_loopback_lookup as lookup


class Responder:
    received = 2

    def snapshot(self):
        return {"received": self.received}


def test_stack_summary_recognizes_only_allowlisted_call_graph_frames() -> None:
    trace = b"""Process: private-fixture-name
Path: /private/fixture/DNSServiceProcessResult
  999 mach_msg (in header)
Call graph:
    + 999 gethostbyaddr (in libsystem_info.dylib) + 4 [0x1234]
    + ! 998 _mdns_search_ex (in libsystem_info.dylib) + 8 [0x5678]
    + ! : 997 kevent (in libsystem_kernel.dylib) + 12 [0x9abc]
    + ! : 996 private_symbol (in private-fixture-name) + 16
    + ! : 995 DNSServiceProcessResult_suffix (in image) + 20
Total number in stack (recursive counted multiple, when >=5):
  999 mach_msg (in footer)
"""
    report = lookup.stack_summary(trace)
    assert report["categories"] == ["kevent_wait", "libinfo_search", "mdns_query"]
    assert report["recognized_frames"] == 3
    assert report["stack_sha256"] == hashlib.sha256(trace).hexdigest()
    assert report["stack_bytes"] == len(trace)
    assert "private" not in json.dumps(report) and "0x1234" not in json.dumps(report)
    assert lookup.stack_summary(b"100 gethostbyaddr (in private-header)")["recognized_frames"] == 0


@pytest.mark.skipif(os.name != "posix", reason="macOS diagnostic uses POSIX process groups and selectable pipes")
def test_numeric_control_is_fixed_local_and_reaped() -> None:
    report = lookup.lookup_probe("numeric_control", Responder())
    assert report["status"] == "completed" and report["return_code"] == 0
    assert report["contained"] is True
    assert report["lookup"] == {"status": "completed", "loopback_label": True}
    assert report["responder_packet_delta"] == 0
    assert "native_sample" not in report


@pytest.mark.parametrize(
    ("code", "status", "limit"),
    [("import time; time.sleep(30)", "deadline_exceeded", 64), ("print('x' * 4096, flush=True)", "size_limit", 17)],
)
@pytest.mark.skipif(os.name != "posix", reason="macOS diagnostic uses POSIX process groups and selectable pipes")
def test_process_deadline_and_output_limit_reap_child(code: str, status: str, limit: int) -> None:
    timeout = 0.15 if status == "deadline_exceeded" else 2.0
    report, data = lookup._bounded_process([sys.executable, "-I", "-c", code], timeout=timeout, limit=limit)
    assert report["status"] == status and report["contained"] is True
    assert type(report["return_code"]) is int
    assert len(data) <= limit
    assert report["stdout_bytes"] + report["stderr_bytes"] <= limit
    assert report["elapsed_ms"] < 4000


@pytest.mark.skipif(os.name != "posix", reason="macOS diagnostic uses POSIX process groups and selectable pipes")
def test_sampler_receives_only_owned_unreaped_child_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    real_popen = subprocess.Popen
    processes = []
    sample_pids = []
    trace = "Call graph:\n  + 999 kevent (in image) + 4\nprivate-fixture-name"

    def popen(argv, **kwargs):
        assert kwargs["start_new_session"] is True
        if argv[0] == "/usr/bin/sample":
            assert argv == ["/usr/bin/sample", str(processes[0].pid), "1", "10", "-mayDie", "-file", "/dev/stdout"]
            assert processes[0].poll() is None
            os.kill(processes[0].pid, 0)
            sample_pids.append(int(argv[1]))
            argv = [sys.executable, "-I", "-c", "print(" + repr(trace) + ")"]
        process = real_popen(argv, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(lookup.subprocess, "Popen", popen)
    report, _data = lookup._bounded_process(
        [sys.executable, "-I", "-c", "import time; time.sleep(30)"], timeout=0.6, limit=1024, sample_owned=True
    )
    assert sample_pids == [processes[0].pid]
    assert report["status"] == "deadline_exceeded" and report["contained"] is True
    assert report["native_sample"]["categories"] == ["kevent_wait"]
    assert report["native_sample"]["contained"] is True
    assert all(process.poll() is not None for process in processes)
    assert "private-fixture-name" not in json.dumps(report)


@pytest.mark.parametrize(
    ("child", "expected"),
    [
        (
            {"status": "completed", "loopback_label": False, "raw": "private-answer"},
            {"status": "completed", "loopback_label": False},
        ),
        (
            {"status": "lookup_error", "category": "gaierror", "errno": 8, "raw": "private-answer"},
            {"status": "lookup_error", "category": "gaierror", "errno": 8},
        ),
        ({"status": "completed", "loopback_label": 1}, {"status": "invalid_child_evidence"}),
        ([], {"status": "invalid_child_evidence"}),
        ({}, {"status": "invalid_child_evidence"}),
    ],
)
def test_lookup_keeps_only_safe_child_projection_and_packet_window(
    monkeypatch: pytest.MonkeyPatch, child, expected
) -> None:
    responder = Responder()

    def process(argv, **kwargs):
        assert argv[:3] == [sys.executable, "-I", "-c"]
        assert "socket.gethostbyaddr('127.0.0.1')" in argv[-1]
        assert kwargs == {"timeout": 5.0, "limit": 1024, "sample_owned": True}
        responder.received += 2
        return {"status": "completed", "return_code": 0}, json.dumps(child).encode()

    monkeypatch.setattr(lookup, "_bounded_process", process)
    report = lookup.lookup_probe("gethostbyaddr", responder)
    assert report["lookup"] == expected
    assert report["responder_packet_delta"] == 2
    assert "private-answer" not in json.dumps(report)


def test_witness_uses_only_three_fixed_operations_outside_measurements(monkeypatch: pytest.MonkeyPatch) -> None:
    operations = []
    with pytest.raises(KeyError):
        lookup.lookup_probe("external.example", Responder())

    def probe(operation, responder):
        operations.append(operation)
        return {"operation": operation}

    monkeypatch.setattr(lookup, "lookup_probe", probe)
    report = lookup.lookup_witness(Responder())
    assert operations == ["numeric_control", "gethostbyaddr", "getnameinfo"]
    assert report["phase"] == "after_qualification_before_resolver_cleanup"
    assert report["process_deadline_seconds"] == 5
    assert report["fixed_loopback_only"] is True
    assert report["packet_delta_scope"] == "responder_window_including_system_activity"
    assert all(
        report[key] is False for key in ("qualification_outcomes_changed", "qualification_sample", "baseline_modified")
    )
