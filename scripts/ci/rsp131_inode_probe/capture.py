"""Adapt the unchanged diagnostic supervisor to one explicit owned command."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from types import ModuleType
from typing import Any


def run(command: list[str], directory: Path, supervisor: ModuleType) -> tuple[dict[str, Any], bytes, bytes]:
    started = time.monotonic()
    process = subprocess.Popen(
        command, cwd=directory, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    identity = supervisor._start_ticks(process.pid)
    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    readers: list[Any] = []
    timed_out = True
    contained = retired = eof = reaped = False
    failure = None
    try:
        for stream in streams:
            readers.append(supervisor.BoundedStream(stream))
        timed_out = not supervisor._wait_without_reaping(process.pid)
    except Exception as error:
        failure = type(error).__name__
    finally:
        try:
            if not timed_out:
                for reader in readers:
                    reader.thread.join(timeout=1)
                eof = len(readers) == 2 and all(reader.eof for reader in readers)
            # The unchanged WNOWAIT/group-identity protocol reserves the PID.
            contained = supervisor._stop_group(process.pid, identity)
            try:
                process.wait(timeout=1)
                reaped = True
            except subprocess.TimeoutExpired:
                contained = False
        except Exception as error:
            failure = type(error).__name__
            contained = False
        finally:
            retirement: list[bool] = []
            for reader in readers:
                try:
                    retirement.append(reader.close())
                except (OSError, RuntimeError):
                    retirement.append(False)
            for stream in streams:
                try:
                    stream.close()
                except OSError:
                    retirement.append(False)
            retired = all(retirement) and all(stream.closed for stream in streams)
    complete = (
        len(readers) == 2 and retired and eof
        and all(not reader.overflow and not reader.failed for reader in readers)
    )
    return {
        "pid": process.pid, "start_ticks": identity, "caller_pid": os.getpid(),
        "returncode": process.returncode, "timed_out": timed_out, "contained": contained,
        "leader_reaped": reaped, "reader_resources_retired": retired,
        "streams_complete": complete, "supervisor_failure": failure,
        "elapsed_diagnostic_seconds": time.monotonic() - started,
    }, bytes(readers[0].data) if readers else b"", bytes(readers[1].data) if len(readers) == 2 else b""
