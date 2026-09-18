from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import probe_sqlite_syscall_observation as probe
from scripts import sqlite_syscall_probe_supervision as supervision
from scripts.probe_sqlite_syscall_observation import descriptor_witness, parse_calls


def test_trace_pairs_incomplete_and_resumed_calls_without_guessing():
    trace = (
        b'10 openat(AT_FDCWD, "/fixture/a", O_RDWR <unfinished ...>\n11 fsync(4) = 0\n10 <... openat resumed>) = 3\n'
    )
    calls, complete = parse_calls(trace, 10)
    assert complete
    assert calls == [(11, "fsync", "4", "0"), (10, "openat", 'AT_FDCWD, "/fixture/a", O_RDWR', "3")]


@pytest.mark.parametrize(
    "trace",
    [
        b"10 fsync(3 <unfinished ...>\n",
        b"10 <... fsync resumed>) = 0\n",
        b"10 fsync(3 <unfinished ...>\n10 <... close resumed>) = 0\n",
        b"strace: ptrace request failed\n",
        b"10 fsync(3 <unfinished ...>\n10 close(3 <unfinished ...>\n10 <... close resumed>) = 0\n",
    ],
)
def test_ambiguous_trace_never_becomes_complete(trace):
    assert parse_calls(trace, 10)[1] is False


def _serial_trace():
    return (
        b'10 openat(AT_FDCWD, "/fixture/descriptor-a", O_RDWR|O_CREAT|O_EXCL, 0600) = 3</fixture/descriptor-a>\n'
        b"10 fcntl(3</fixture/descriptor-a>, F_DUPFD_CLOEXEC, 0) = 4</fixture/descriptor-a>\n"
        b"10 write(0x3, 0xdeadbeef, 0x2a) = 0x2a\n"
        b"10 fsync(4</fixture/descriptor-a>) = 0\n"
        b"10 close(3</fixture/descriptor-a>) = 0\n"
        b'10 openat(AT_FDCWD, "/fixture/descriptor-b", O_RDWR|O_CREAT|O_EXCL, 0600) = 3</fixture/descriptor-b>\n'
        b"10 pwrite64(0x3, 0xdeadbeef, 0x2a, 0x7) = 0x2a\n"
        b"10 fdatasync(3</fixture/descriptor-b>) = 0\n"
        b"10 close(3</fixture/descriptor-b>) = 0\n"
        b"10 close(4</fixture/descriptor-a>) = 0\n"
        b"10 fsync(9) = -1 EBADF (Bad file descriptor)\n"
    )


def _child():
    return {
        "identity": {"pid": 10},
        "descriptors": {
            "first_fd": 3,
            "second_fd": 3,
            "first_identity": [5, 6],
            "second_identity": [5, 7],
            "fd_reused": True,
            "expected_bytes": 42,
            "write_bytes": 42,
            "pwrite_bytes": 42,
            "invalid_sync_errno": 9,
            "invalid_sync_fd": 9,
            "invalid_sync_expected": 9,
        },
    }


def test_serial_fd_reuse_keeps_duplicate_open_lifetime_bound_to_first_file():
    calls, complete = parse_calls(_serial_trace(), 10)
    assert complete
    result = descriptor_witness(calls, Path("/fixture"), _child())
    assert result["passed"]
    assert result["counts"] == {
        "a_write_bytes": 42,
        "a_sync_success": 1,
        "b_pwrite_bytes": 42,
        "b_sync_success": 1,
        "bad_sync": 1,
    }


@pytest.mark.parametrize(
    "before,after",
    [
        (b"0x2a) = 0x2a", b"0x2a) = 0x10"),
        (b"fsync(4</fixture/descriptor-a>) = 0", b"fsync(4</fixture/descriptor-a>) = -1 EIO (Input/output error)"),
        (b"close(3</fixture/descriptor-a>) = 0", b"close(3</fixture/descriptor-a>) = -1 EIO (Input/output error)"),
        (b"fsync(9) = -1 EBADF", b"fsync(9) = -1 EIO"),
    ],
)
def test_actual_partial_failure_and_ambiguous_reuse_cannot_pass(before, after):
    calls, complete = parse_calls(_serial_trace().replace(before, after), 10)
    assert complete
    assert descriptor_witness(calls, Path("/fixture"), _child())["passed"] is False


@pytest.mark.skipif(sys.platform != "linux", reason="Linux disposable probe orchestration")
def test_uncontained_baseline_stops_followup_and_preserves_owned_scratch(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(probe.tempfile, "mkdtemp", lambda **_kwargs: str(tmp_path))
    monkeypatch.setattr(probe.shutil, "which", lambda _name: "/bin/true")

    def child(root, tracer):
        calls.append((root, tracer))
        return {"contained": False, "child": None}, b""

    monkeypatch.setattr(probe, "_run_child", child)
    report = probe.run_probe()
    assert report["status"] == "ambiguous" and report["reason"] == "baseline_containment_or_reader_retirement_unproved"
    assert report["owned_scratch_retained"] is True and tmp_path.exists()
    assert len(calls) == 1 and calls[0][1] is None


@pytest.mark.skipif(sys.platform != "linux", reason="Linux disposable probe orchestration")
def test_denied_tracing_is_explicit_even_if_target_executes_and_scratch_is_cleaned(tmp_path, monkeypatch):
    monkeypatch.setattr(probe.tempfile, "mkdtemp", lambda **_kwargs: str(tmp_path))
    monkeypatch.setattr(probe.shutil, "which", lambda _name: "/bin/true")
    monkeypatch.setattr(
        probe,
        "_run_child",
        lambda _root, tracer: (
            {"contained": True, "reader_resources_retired": True, "child": None},
            b"strace: ptrace(PTRACE_SEIZE): Operation not permitted\n" if tracer else b"",
        ),
    )
    report = probe.run_probe()
    assert report["status"] == "denied" and report["rsp131_qualified"] is False
    assert report["owned_scratch_retained"] is False and not tmp_path.exists()


def test_report_discards_raw_descriptor_values_and_keeps_identity_digest():
    child = _child()
    child["descriptors"]["duplicate_fd"] = 9876543
    report = {"child": child}
    probe._redact_descriptors(report)
    descriptors = child["descriptors"]
    assert not {
        "first_fd",
        "second_fd",
        "duplicate_fd",
        "invalid_sync_fd",
        "first_identity",
        "second_identity",
    }.intersection(descriptors)
    assert len(descriptors["file_identity_sha256"]) == 64 and descriptors["different_file_identity"] is True


@pytest.mark.parametrize(
    "arguments", ['3, "rsp131-private-value-never"..., 42', '3, "short", 5', "3, [{iov_base=0x123, iov_len=3}], 1"]
)
def test_partial_data_dumps_and_decoded_vectors_never_prove_raw_buffer_suppression(arguments):
    assert not probe.raw_write_arguments_only([(10, "write", arguments, "0x2a")])


def test_raw_arguments_need_actual_write_records_and_only_numeric_pointer_count_fields():
    assert not probe.raw_write_arguments_only([])
    assert probe.raw_write_arguments_only([(10, "pwrite64", "0x3, 0xdeadbeef, 0x2a, 0x7", "0x2a")])


@pytest.mark.skipif(sys.platform != "linux", reason="Linux pipe polling")
def test_reader_retires_without_waiting_for_a_live_writer_to_close():
    read_fd, write_fd = os.pipe()
    try:
        reader = supervision.BoundedStream(os.fdopen(read_fd, "rb"))
        assert reader.close()
        assert reader.stream.closed and not reader.eof
    finally:
        os.close(write_fd)


@pytest.mark.parametrize("known_start,observed_start,live", [(12, 13, 1), (None, 12, 1), (12, 12, None)])
@pytest.mark.skipif(sys.platform != "linux", reason="Linux process group supervision")
def test_unproved_group_identity_or_membership_never_signals(monkeypatch, known_start, observed_start, live):
    signals = []
    monkeypatch.setattr(supervision, "_start_ticks", lambda _pid: observed_start)
    monkeypatch.setattr(supervision, "_live_group_members", lambda _pid: live)
    monkeypatch.setattr(supervision.os, "killpg", lambda *_args: signals.append(True))
    assert supervision._stop_group(77, known_start) is False
    assert not signals


def test_failed_reap_retains_normalized_outcome_and_retires_both_readers(tmp_path, monkeypatch):
    events = []
    readers = []

    class Process:
        pid, returncode = 77, None
        stdout = SimpleNamespace(close=lambda: None, closed=True)
        stderr = SimpleNamespace(close=lambda: None, closed=True)

        def wait(self, **_kwargs):
            events.append("reap")
            raise subprocess.TimeoutExpired("owned-control", 1)

    class Reader:
        def __init__(self, _stream):
            self.data, self.eof, self.failed, self.overflow = b"", True, False, False
            self.thread = SimpleNamespace(join=lambda **_kwargs: None)
            readers.append(self)

        def close(self):
            events.append("reader-retired")
            return True

    monkeypatch.setattr(supervision.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    monkeypatch.setattr(supervision, "BoundedStream", Reader)
    monkeypatch.setattr(supervision, "_start_ticks", lambda _pid: 12)
    monkeypatch.setattr(supervision, "_wait_without_reaping", lambda _pid: events.append("observed-unreaped") or True)
    monkeypatch.setattr(
        supervision, "_stop_group", lambda pid, start: events.append(("checked-group", pid, start)) or False
    )
    report, _trace = probe._run_child(tmp_path, None)
    assert not report["contained"] and not report["leader_reaped"]
    assert report["reader_resources_retired"] and len(readers) == 2
    assert events == ["observed-unreaped", ("checked-group", 77, 12), "reap", "reader-retired", "reader-retired"]
