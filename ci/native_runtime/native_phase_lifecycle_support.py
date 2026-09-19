"""Owned real-binary controls for native diagnostic lifecycle tests.

These synthetic controls may keep their stdin stream open to sample the
exporter. They do not change the installed workload, native deadlines or
shutdown implementation. Failure cleanup targets retained pidfds only.
"""

from __future__ import annotations

import json
import os
import select
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, BinaryIO

from scripts.native_slo_rust_phase_process import Executable, ProcessIdentity, parse_stat, read_process
from scripts.native_slo_rust_phase_receiver import NativePhaseReceiver

HEALTH = b'{"operation":"health","request":{}}'
INVALID = b"{"
HEALTH_RESPONSE = b'{"protocol_version":2,"status":"ready"}'
INVALID_RESPONSE = b'{"error":"native_request_invalid_json","retryable":false}'
MAX_CONTROL_PROCESSES = 32
MAX_PROC_ENTRIES = 32768


def wait_report(receiver: NativePhaseReceiver, predicate: Any, seconds: float = 4.0) -> dict[str, Any]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        report = receiver.report()
        if predicate(report):
            return report
        if report["receiver_terminal"]:
            break
        time.sleep(0.01)
    raise AssertionError("bounded native diagnostic observation was not retained")


def statistics(report: dict[str, Any], role: str, phase: str) -> list[dict[str, Any]]:
    return [
        row["statistics"]
        for process in report["processes"]
        if process["role"] == role and process["snapshot"] is not None
        for row in process["snapshot"]["phases"]
        if row["phase"] == phase and row["statistics"] is not None
    ]


def fill_owned_receiver(receiver: NativePhaseReceiver) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as filler:
        filler.setblocking(False)
        filler.connect(str(receiver.path))
        for _ in range(1024):
            try:
                filler.send(b"controlled diagnostic backpressure", socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            except BlockingIOError:
                return
    raise AssertionError("bounded diagnostic queue-fill control did not reach backpressure")


def _read_exact(stream: BinaryIO, length: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise AssertionError("original native response was not received within the control deadline")
        chunk = os.read(stream.fileno(), length - len(result))
        if not chunk:
            raise AssertionError("original native response ended before its frame")
        result.extend(chunk)
    return bytes(result)


class OwnedNativeStream:
    def __init__(self, runtime: Path, root: Path, diagnostic_environment: dict[str, str]) -> None:
        self.runtime = runtime
        self.executable = Executable(runtime)
        self.root = root
        root.mkdir(mode=0o700)
        self.state = root / "native-runtime"
        self.state.mkdir(mode=0o700)
        descriptor = os.open(self.state / "policy-verifier.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            assert os.write(descriptor, bytes([7]) * 32) == 32
        finally:
            os.close(descriptor)
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("HOL_GUARD_NATIVE_PHASE_")
        }
        environment.update(diagnostic_environment)
        self.environment = environment
        self.process = subprocess.Popen(
            [str(runtime), "resident-client-stream", "--stdin", str(self.state)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, start_new_session=True,
        )
        self.handles: dict[tuple[int, int], tuple[ProcessIdentity, int]] = {}
        self.closed = False
        self.completed_requests = 0
        self.cleanup: dict[str, Any] | None = None
        try:
            self.identity, role = read_process(self.process.pid, self.executable)
            assert role == "persistent_client"
            assert self.identity.parent == os.getpid()
            assert self.identity.group == self.identity.session == self.identity.pid
            self.capture_owned_processes()
        except BaseException:
            # No request has been written: this exact stream cannot yet have
            # spawned a managed resident. Retire only the owned direct child.
            self.process.kill()
            self.process.wait(timeout=3)
            for _row, handle in self.handles.values():
                os.close(handle)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()
            self.executable.close()
            raise

    def capture_owned_processes(self) -> None:
        """Capture only this live session's exact native executable generations."""
        current, _ = read_process(self.process.pid, self.executable)
        assert current == self.identity, "original native session leader changed"
        entries = list(Path("/proc").iterdir())
        assert len(entries) <= MAX_PROC_ENTRIES
        for path in entries:
            if not path.name.isdecimal():
                continue
            pid = int(path.name)
            try:
                with (path / "stat").open("rb") as stream:
                    raw = stream.read(4097)
                assert len(raw) <= 4096
                try:
                    row = parse_stat(raw, pid)
                except ValueError:
                    # Dead/zombie entries are not live cleanup targets.
                    continue
                if row.session != self.identity.session:
                    continue
                verified, _ = read_process(pid)
                assert verified == row and row.start_ticks >= self.identity.start_ticks
                metadata = os.stat(path / "exe")
                identity = (
                    metadata.st_dev, metadata.st_ino, metadata.st_mode,
                    metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
                )
                assert identity == self.executable.identity, "unrecognized binary in owned native session"
                key = row.pid, row.start_ticks
                if key in self.handles:
                    continue
                assert len(self.handles) < MAX_CONTROL_PROCESSES
                handle = os.pidfd_open(pid, 0)
                try:
                    assert read_process(pid)[0] == row
                except BaseException:
                    os.close(handle)
                    raise
                self.handles[key] = row, handle
            except (FileNotFoundError, ProcessLookupError):
                continue
        assert read_process(self.process.pid, self.executable)[0] == self.identity

    def request(self, payload: bytes) -> bytes:
        assert self.process.stdin is not None and self.process.stdout is not None
        assert 0 < len(payload) <= 4096
        deadline = time.monotonic() + 3.0
        self.process.stdin.write(len(payload).to_bytes(4, "big") + payload)
        self.process.stdin.flush()
        header = _read_exact(self.process.stdout, 4, deadline)
        length = int.from_bytes(header, "big")
        assert 0 < length <= 65536
        result = _read_exact(self.process.stdout, length, deadline)
        self.capture_owned_processes()
        self.completed_requests += 1
        return result

    def _live_handles(self) -> list[int]:
        return [handle for _row, handle in self.handles.values() if not select.select([handle], [], [], 0)[0]]

    def close(self, expected_returncode: int = 0) -> dict[str, Any]:
        if self.closed:
            assert self.cleanup is not None
            return self.cleanup
        self.closed = True
        result: dict[str, Any] = {
            "scope": "existing_resident_stop_then_retained_owned_generation_pidfds",
            "stop_returncode": None, "client_returncode": None,
            "original_session_capture_failed": False,
            "forced_signals": [], "no_live_retained_generations": False,
            "state_files_remaining": None, "passed": False,
            "never_started_partial_header_control": (
                expected_returncode == 2 and self.completed_requests == 0
                and set(self.handles) == {(self.identity.pid, self.identity.start_ticks)}
                and not list(self.state.glob("resident-v3-*/generation-*.json"))
            ),
            "stop_response_expected": False,
        }
        try:
            if self.process.poll() is None:
                try:
                    self.capture_owned_processes()
                except Exception:
                    result["original_session_capture_failed"] = True
            stop_environment = {
                key: value for key, value in self.environment.items()
                if not key.startswith("HOL_GUARD_NATIVE_PHASE_")
            }
            try:
                stopped = subprocess.run(
                    [str(self.runtime), "resident-stop", "--state-dir", str(self.state)],
                    env=stop_environment, capture_output=True, timeout=3, check=False,
                )
                assert len(stopped.stdout) + len(stopped.stderr) <= 4096
                result["stop_returncode"] = stopped.returncode
                result["stop_response_expected"] = (
                    (stopped.returncode, stopped.stdout, stopped.stderr)
                    == ((2, b"", b"native_resident_stop_unavailable\n")
                        if result["never_started_partial_header_control"] else (0, b"", b""))
                )
            except (subprocess.TimeoutExpired, OSError):
                result["stop_failed"] = True
            if self.process.stdin is not None:
                self.process.stdin.close()
            try:
                result["client_returncode"] = self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                result["client_timeout"] = True
            # The original supervisor joins its 50 ms watcher after serving
            # stops. Observe that normal retirement before any fallback signal.
            passive_deadline = time.monotonic() + 2
            while time.monotonic() < passive_deadline and self._live_handles():
                self.process.poll()
                time.sleep(0.01)
            for signum in (signal.SIGTERM, signal.SIGKILL):
                live = self._live_handles()
                if not live:
                    break
                for handle in live:
                    try:
                        signal.pidfd_send_signal(handle, signum)
                        result["forced_signals"].append(int(signum))
                    except ProcessLookupError:
                        pass
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline and self._live_handles():
                    self.process.poll()
                    time.sleep(0.01)
            self.process.poll()
            result["client_returncode"] = self.process.returncode
            result["no_live_retained_generations"] = not self._live_handles()
            result["retained_generation_count"] = len(self.handles)
            result["state_files_remaining"] = len(list(self.state.glob("resident-v3-*/generation-*.json")))
            result["passed"] = (
                result["stop_response_expected"]
                and result["client_returncode"] == expected_returncode
                and result["no_live_retained_generations"]
                and not result["original_session_capture_failed"]
                and result["state_files_remaining"] == 0
                and not result["forced_signals"]
            )
        finally:
            for _row, handle in self.handles.values():
                os.close(handle)
            self.handles.clear()
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()
            self.executable.close()
            self.cleanup = result
        return result


def keep_record(record_property: Any, label: str, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, sort_keys=True)
    assert len(encoded.encode("utf-8")) <= 1024 * 1024
    record_property(label, encoded)
