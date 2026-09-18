"""Owned, bounded Linux child supervision for disposable SQLite controls."""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import IO, Any

MAX_STREAM_BYTES = 256 * 1024
TIMEOUT_SECONDS = 8.0
TRACE_CALLS = "open,openat,close,dup,dup2,dup3,fcntl,write,pwrite64,writev,pwritev,pwritev2,fsync,fdatasync"
RAW_CALLS = "write,pwrite64,writev,pwritev,pwritev2"


class BoundedStream:
    def __init__(self, stream: IO[bytes]) -> None:
        self.stream = stream
        self.data = bytearray()
        self.overflow = False
        self.failed = False
        self.eof = False
        self.stop = threading.Event()
        os.set_blocking(stream.fileno(), False)
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self) -> None:
        try:
            while not self.stop.is_set():
                if not select.select([self.stream.fileno()], [], [], 0.05)[0]:
                    continue
                try:
                    block = os.read(self.stream.fileno(), 4096)
                except BlockingIOError:
                    continue
                if not block:
                    self.eof = True
                    break
                remaining = MAX_STREAM_BYTES - len(self.data)
                self.data.extend(block[:remaining])
                self.overflow |= len(block) > remaining
        except (OSError, ValueError):
            self.failed = True

    def close(self) -> bool:
        self.stop.set()
        self.thread.join(timeout=0.2)
        try:
            self.stream.close()
        except OSError:
            self.failed = True
        return not self.thread.is_alive()


def _start_ticks(pid: int) -> int | None:
    try:
        return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def _live_group_members(group: int) -> int | None:
    count = 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            count += int(fields[2]) == group and fields[0] != "Z"
        except FileNotFoundError:
            continue
        except (OSError, ValueError, IndexError):
            return None
    return count


def _stop_group(group: int, start_ticks: int | None) -> bool:
    if start_ticks is None or _start_ticks(group) != start_ticks:
        return False
    live = _live_group_members(group)
    if live is None:
        return False
    if live:
        if _start_ticks(group) != start_ticks:
            return False
        with suppress(ProcessLookupError):
            os.killpg(group, signal.SIGTERM)
        deadline = time.monotonic() + 0.2
        while _live_group_members(group) and time.monotonic() < deadline:
            time.sleep(0.005)
    live = _live_group_members(group)
    if live is None:
        return False
    if live:
        if _start_ticks(group) != start_ticks:
            return False
        with suppress(ProcessLookupError):
            os.killpg(group, signal.SIGKILL)
    deadline = time.monotonic() + 0.5
    while _live_group_members(group) and time.monotonic() < deadline:
        time.sleep(0.005)
    return _live_group_members(group) == 0


def _wait_without_reaping(pid: int) -> bool:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
            return True
        time.sleep(0.005)
    return False


def _run_child(root: Path, strace: str | None) -> tuple[dict[str, Any], bytes]:
    child = Path(__file__).with_name("sqlite_syscall_probe_child.py")
    command = [sys.executable, str(child), str(root)]
    if strace is not None:
        command = [strace, "-D", "-f", "-yy", "-e", f"trace={TRACE_CALLS}", "-e", f"raw={RAW_CALLS}", *command]
    started = time.monotonic()
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    )
    identity = _start_ticks(process.pid)
    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    readers: list[BoundedStream] = []
    timed_out = False
    contained = retired = clean_exit_streams = reaped = False
    supervisor_failure = None
    try:
        for stream in streams:
            readers.append(BoundedStream(stream))
        timed_out = not _wait_without_reaping(process.pid)
    except Exception as error:
        supervisor_failure = type(error).__name__
    finally:
        try:
            if not timed_out:
                for reader in readers:
                    reader.thread.join(timeout=1)
                clean_exit_streams = len(readers) == 2 and all(reader.eof for reader in readers)
            # WNOWAIT keeps the leader's PID reserved through every group signal.
            contained = _stop_group(process.pid, identity)
            try:
                process.wait(timeout=1)
                reaped = True
            except subprocess.TimeoutExpired:
                contained = False
        except Exception as error:
            supervisor_failure = type(error).__name__
            contained = False
        finally:
            retirement = []
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
    raw_trace = bytes(readers[1].data) if len(readers) == 2 else b""
    try:
        child_report = json.loads(readers[0].data if readers else b"")
    except (ValueError, UnicodeError):
        child_report = None
    result = {
        "returncode": process.returncode,
        "timed_out": timed_out,
        "contained": contained,
        "reader_resources_retired": retired,
        "leader_reaped": reaped,
        "supervisor_failure": supervisor_failure,
        "streams_complete": retired and clean_exit_streams and all(not r.overflow and not r.failed for r in readers),
        "trace_bytes": len(raw_trace),
        "child": child_report,
        "launch_pid": process.pid,
        "launch_start_ticks": identity,
        "caller_pid": os.getpid(),
        "elapsed_diagnostic_seconds": time.monotonic() - started,
    }
    return result, raw_trace
