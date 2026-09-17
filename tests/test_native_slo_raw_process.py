from __future__ import annotations

import io
import os
import sys
import threading

import pytest

from scripts import native_slo_raw_process as raw


def test_real_contained_pipe_keeps_invalid_octets_and_stream_boundaries(tmp_path):
    data = b'\x00\xff\xfe\xc0\xaf{"fixture":1}\n'
    result = raw.run_registered_bytes(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys; d=sys.stdin.buffer.read(); sys.stdout.buffer.write(d); "
            "sys.stderr.buffer.write(b'\\xffstderr')",
        ],
        stdin=data,
        cwd=tmp_path,
        environment=dict(os.environ),
    )
    assert result.returncode == result.observed_exit == 0
    assert result.stdout == data and result.stderr == b"\xffstderr"
    assert result.stdin_written == len(data) and result.stdin_flushed
    assert not (result.timed_out or result.containment_failed or result.output_limit_exceeded or result.io_failed)


def test_real_output_overflow_remains_bounded_and_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(raw, "OUTPUT_LIMIT", 128)
    result = raw.run_registered_bytes(
        [sys.executable, "-I", "-c", "import sys; sys.stdout.buffer.write(b'x'*1024); sys.stdout.flush()"],
        stdin=b"",
        cwd=tmp_path,
        environment=dict(os.environ),
    )
    assert result.output_limit_exceeded and len(result.stdout) + len(result.stderr) <= 128
    assert not result.containment_failed


def test_raw_input_bounds_precede_spawn(tmp_path, monkeypatch):
    monkeypatch.setattr(raw.lifecycle, "_spawn_hook_process", lambda *args, **kwargs: pytest.fail("must not spawn"))
    for data in ("text", b"x" * (raw.INPUT_LIMIT + 1)):
        with pytest.raises(ValueError, match="bounds"):
            raw.run_registered_bytes(["unused"], stdin=data, cwd=tmp_path, environment={})


def test_partial_writes_preserve_all_octets_and_failed_flush_is_not_completion():
    class Sink(io.BytesIO):
        saved = b""

        def write(self, value):
            return super().write(value[:2])

        def close(self):
            self.saved = self.getvalue()
            super().close()

    stream, written, flushed, failed = Sink(), [0], threading.Event(), threading.Event()
    raw._write(stream, b"\xffabcdef", written, flushed, failed)
    assert stream.saved == b"\xffabcdef" and written == [7]
    assert flushed.is_set() and not failed.is_set()

    class FailedFlush(Sink):
        def flush(self):
            raise BrokenPipeError

    stream, written, flushed, failed = FailedFlush(), [0], threading.Event(), threading.Event()
    raw._write(stream, b"\xff", written, flushed, failed)
    assert written == [1] and failed.is_set() and not flushed.is_set()


def test_reader_failure_is_not_an_empty_success(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("private read failure")

    monkeypatch.setattr(raw, "_drain_hook_stream", fail)
    failed = threading.Event()
    raw._read(
        io.BytesIO(),
        bytearray(),
        failed,
        output_limit=128,
        output_count=[0],
        output_lock=threading.Lock(),
        output_limit_exceeded=threading.Event(),
    )
    assert failed.is_set()


def test_concurrently_closed_input_is_retained_as_io_failure():
    stream, written, flushed, failed = io.BytesIO(), [0], threading.Event(), threading.Event()
    stream.close()
    raw._write(stream, b"\xff", written, flushed, failed)
    assert failed.is_set() and not flushed.is_set() and written == [0]


def test_cleanup_failure_does_not_erase_actual_observed_exit(tmp_path, monkeypatch):
    cleanup = raw.lifecycle.join_and_cleanup_hook_process

    def fail_after_cleanup(*args, **kwargs):
        job, _, _ = cleanup(*args, **kwargs)
        return job, False, True

    monkeypatch.setattr(raw.lifecycle, "join_and_cleanup_hook_process", fail_after_cleanup)
    result = raw.run_registered_bytes(
        [sys.executable, "-I", "-c", "import sys; sys.exit(2)"],
        stdin=b"",
        cwd=tmp_path,
        environment=dict(os.environ),
    )
    assert result.returncode is None and result.observed_exit == 2 and result.containment_failed


def test_real_valid_utf8_and_exit_match_existing_text_lifecycle(tmp_path):
    argv = [sys.executable, "-I", "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.exit(2)"]
    data = '{"fixture":"café雪"}\n'
    existing = raw.lifecycle.run_isolated_hook_process(
        argv,
        input_text=data,
        cwd=tmp_path,
        environment=dict(os.environ),
        timeout_seconds=10,
    )
    binary = raw.run_registered_bytes(argv, stdin=data.encode(), cwd=tmp_path, environment=dict(os.environ))
    assert existing.returncode == binary.returncode == 2
    assert existing.stdout.encode() == binary.stdout == data.encode()
    assert existing.stderr.encode() == binary.stderr == b""
    assert existing.output_limit_exceeded is binary.output_limit_exceeded is False
    assert existing.containment_failed is binary.containment_failed is False
    assert existing.timed_out is binary.timed_out is False
