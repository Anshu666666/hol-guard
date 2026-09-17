"""Exact-byte fixture I/O through the installed process containment contract."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from codex_plugin_scanner.guard import codex_hook_launch_runtime as lifecycle
from codex_plugin_scanner.guard.codex_hook_process_runtime import _drain_hook_stream

INPUT_LIMIT = 1_000_001
# This new diagnostic retains a prefix; existing text-launcher limits are unchanged.
OUTPUT_LIMIT = 64 * 1024


@dataclass(frozen=True)
class RawProcessResult:
    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    containment_failed: bool = False
    output_limit_exceeded: bool = False
    stdin_written: int = 0
    stdin_flushed: bool = False
    io_failed: bool = False
    observed_exit: int | None = None


def _write(
    stream: BinaryIO | None, data: bytes, written: list[int], flushed: threading.Event, failed: threading.Event
) -> None:
    if stream is None:
        failed.set()
        return
    try:
        while written[0] < len(data):
            chunk = data[written[0] : written[0] + 65536]
            count = stream.write(chunk)
            if type(count) is not int or not 0 < count <= len(chunk):
                failed.set()
                return
            written[0] += count
        stream.flush()
        flushed.set()
    except (OSError, ValueError):
        failed.set()
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            failed.set()


def _read(
    stream: BinaryIO,
    target: bytearray,
    failed: threading.Event,
    *,
    output_limit: int,
    output_count: list[int],
    output_lock: threading.Lock,
    output_limit_exceeded: threading.Event,
) -> None:
    try:
        _drain_hook_stream(
            stream,
            target,
            output_limit=output_limit,
            output_count=output_count,
            output_lock=output_lock,
            output_limit_exceeded=output_limit_exceeded,
        )
    except Exception:
        failed.set()


def run_registered_bytes(
    argv: Sequence[str], *, stdin: bytes, cwd: Path, environment: Mapping[str, str], timeout_seconds: float = 10.0
) -> RawProcessResult:
    """Run the exact registered argv, with no codec or intermediate process.

    The existing installed spawn, wait, group/Job termination, cleanup and
    quarantine primitives are identical in frozen 2e672 and the candidate.
    Only the fixture writer/capture representation differs from the text API.
    """
    if type(stdin) is not bytes or len(stdin) > INPUT_LIMIT or not 0 < timeout_seconds <= 10:
        raise ValueError("registered_raw_process_bounds")
    if lifecycle._HOOK_PROCESS_CONTAINMENT_FAILED.is_set() and not lifecycle._retry_quarantined_hook_processes():
        return RawProcessResult(None, containment_failed=True)
    deadline = time.monotonic() + timeout_seconds
    try:
        process, job, liveness = lifecycle._spawn_hook_process(
            argv,
            cwd=cwd,
            environment=environment,
            allow_windows_breakaway=False,
            windows_kill_on_job_close=True,
            parent_liveness=False,
        )
    except OSError:
        return RawProcessResult(None, io_failed=True)
    stdout, stderr = bytearray(), bytearray()
    count, written = [0], [0]
    lock = threading.Lock()
    exceeded, flushed, failed = threading.Event(), threading.Event(), threading.Event()
    options = dict(output_limit=OUTPUT_LIMIT, output_count=count, output_lock=lock, output_limit_exceeded=exceeded)
    threads = [
        threading.Thread(target=_read, args=(process.stdout, stdout, failed), kwargs=options, daemon=True),
        threading.Thread(target=_read, args=(process.stderr, stderr, failed), kwargs=options, daemon=True),
        threading.Thread(target=_write, args=(process.stdin, stdin, written, flushed, failed), daemon=True),
    ]
    started: list[threading.Thread] = []
    try:
        for thread in threads:
            thread.start()
            started.append(thread)
        returncode, timed_out, contained, terminated = lifecycle.wait_for_hook_process(
            process,
            job,
            deadline=deadline,
            stop_event=None,
            output_limit_exceeded=exceeded,
            terminate=lifecycle._kill_hook_process,
        )
    except BaseException:
        contained = lifecycle._kill_hook_process(process, job)
        _ = lifecycle.join_and_cleanup_hook_process(
            process,
            job,
            started,
            containment_confirmed=contained,
            termination_requested=True,
            terminate=lifecycle._kill_hook_process,
            quarantine=lifecycle._quarantine_hook_process,
            close_streams=lifecycle._close_process_streams,
            close_job=lifecycle.close_windows_hook_job,
        )
        if liveness is not None:
            os.close(liveness)
        raise
    job, contained, cleanup_failed = lifecycle.join_and_cleanup_hook_process(
        process,
        job,
        threads,
        containment_confirmed=contained,
        termination_requested=terminated,
        terminate=lifecycle._kill_hook_process,
        quarantine=lifecycle._quarantine_hook_process,
        close_streams=lifecycle._close_process_streams,
        close_job=lifecycle.close_windows_hook_job,
    )
    if liveness is not None:
        os.close(liveness)
    with lock:
        return RawProcessResult(
            None if cleanup_failed or not contained else returncode,
            bytes(stdout),
            bytes(stderr),
            timed_out,
            not contained,
            exceeded.is_set(),
            written[0],
            flushed.is_set(),
            failed.is_set(),
            returncode,
        )
