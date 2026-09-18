"""Observe one owned resolver probe without publishing native stacks or paths.

Sampling is diagnostic only, runs before either measured arm, and shares the
existing phase deadline. A complete sample shows observed frames, not a cause
of the baseline stall. Missing or partial samples cannot prove frame absence.
"""

from __future__ import annotations

import base64
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress

_STACK_BYTES = 65536
_PROBE_BYTES = 128
# These reports describe Darwin child processes, even when reviewed elsewhere.
# Windows does not expose signal.SIGKILL to its Python interpreter.
_SIGKILL_EXIT = -9
_CATEGORIES = (
    "resolver_entry_frame_observed",
    "libinfo_frame_observed",
    "dns_service_frame_observed",
    "mach_message_frame_observed",
    "synchronization_frame_observed",
)
_FRAME = re.compile(r"^[ \t+!|:]*[1-9][0-9]*[ \t]+([A-Za-z_][A-Za-z0-9_.$:]*) \(in ([^()\s]+)\)(?:[ \t].*)?$")


def stack_projection(data: bytes, pid: int) -> dict[str, bool]:
    """Accept only this child's complete sample call graph, never its headers."""
    if len(data) > _STACK_BYTES or type(pid) is not int or pid <= 0:
        raise ValueError("native_stack_projection_bounds")
    text = data.decode("utf-8", errors="strict")
    identities = re.findall(r"(?m)^Process:[ \t]+[^\r\n]*\[([0-9]+)\][ \t]*$", text)
    if identities != [str(pid)] or text.count("\nCall graph:\n") != 1:
        raise ValueError("native_stack_identity_or_graph_missing")
    graph = text.split("\nCall graph:\n", 1)[1]
    end = re.search(r"(?m)^(?:Total number in stack|Sort by top of stack|Binary Images:)", graph)
    if end is None:
        raise ValueError("native_stack_graph_incomplete")
    frames = [match.groups() for line in graph[: end.start()].splitlines() if (match := _FRAME.fullmatch(line))]
    if not frames:
        raise ValueError("native_stack_frames_missing")
    result: dict[str, bool] = dict.fromkeys(_CATEGORIES, False)
    for symbol, library in frames:
        if library == "libsystem_info.dylib":
            result["libinfo_frame_observed"] = True
            result["resolver_entry_frame_observed"] |= symbol in {"gethostbyaddr", "gethostbyaddr_r"}
        if library in {"libsystem_dnssd.dylib", "libdns_services.dylib"}:
            result["dns_service_frame_observed"] |= symbol in {
                "DNSServiceQueryRecord",
                "DNSServiceProcessResult",
                "DNSServiceGetAddrInfo",
            }
        if library == "libsystem_kernel.dylib":
            result["mach_message_frame_observed"] |= symbol in {
                "mach_msg",
                "mach_msg2_trap",
                "mach_msg_overwrite",
                "mach_msg2_internal",
            }
            result["synchronization_frame_observed"] |= symbol in {
                "__psynch_mutexwait",
                "__psynch_cvwait",
                "__ulock_wait",
                "__ulock_wait2",
                "semaphore_wait_trap",
                "semaphore_timedwait_trap",
            }
    return result


def _stop_owned(process: subprocess.Popen[bytes]) -> bool:
    """Kill this unreaped child's private process group, then reap the child."""
    # Do not poll first: keeping the child unreaped also prevents its numeric
    # PID/process-group identity being recycled before group containment.
    group_stopped = True
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        group_stopped = False
        with suppress(OSError):
            process.kill()
    try:
        _ = process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        return False
    return group_stopped


def _read_streams(
    process: subprocess.Popen[bytes],
    deadline: float,
    limit: int,
    on_stdout: Callable[[bytes], None] | None = None,
) -> tuple[str, bytes, bytes]:
    assert process.stdout is not None and process.stderr is not None
    retained = {"stdout": bytearray(), "stderr": bytearray()}
    names: dict[int, str] = {}
    status = "completed"
    with selectors.DefaultSelector() as selector:
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(stream.fileno(), False)
            _ = selector.register(stream, selectors.EVENT_READ)
            names[stream.fileno()] = name
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "deadline_exceeded"
                break
            for key, _events in selector.select(remaining):
                try:
                    chunk = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    _ = selector.unregister(key.fd)
                    continue
                name = names[key.fd]
                destination = retained[name]
                available = limit - len(destination)
                destination.extend(chunk[:available])
                if len(chunk) > available:
                    status = "output_bound"
                    break
                if name == "stdout" and on_stdout is not None:
                    on_stdout(bytes(destination))
            if status != "completed":
                break
    return status, bytes(retained["stdout"]), bytes(retained["stderr"])


def _sample(pid: int, deadline: float) -> tuple[str, bytes, bytes, int | None, bool]:
    """Use the system sampler without elevation or a plaintext output file."""
    if time.monotonic() >= deadline:
        return "deadline_exceeded", b"", b"", None, True
    try:
        process = subprocess.Popen(
            ["/usr/bin/sample", str(pid), "1", "1", "-file", "/dev/stdout"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        return "unavailable", b"", b"", None, True
    status, stdout, stderr = "failed", b"", b""
    cleanup = False
    try:
        status, stdout, stderr = _read_streams(process, deadline, _STACK_BYTES)
    except (OSError, ValueError):
        status = "failed"
    finally:
        # The sampler gets an earlier acquisition deadline than the probe,
        # leaving its containment allowance inside the existing five seconds.
        cleanup = _stop_owned(process)
        assert process.stdout is not None and process.stderr is not None
        process.stdout.close()
        process.stderr.close()
    if status == "completed" and process.returncode not in {0, _SIGKILL_EXIT}:
        status = "failed"
    return status if cleanup else "cleanup_incomplete", stdout, stderr, process.returncode, cleanup


def _sample_report(
    captured: tuple[str, bytes, bytes, int | None, bool],
    pid: int,
) -> tuple[dict[str, object], dict[str, object]]:
    status, stdout, stderr, code, cleanup = captured
    if code is None:
        exit_observation = "not_observed"
    elif code == 0:
        exit_observation = "zero_exit_observed"
    elif status == "completed" and code == _SIGKILL_EXIT:
        exit_observation = "sigkill_exit_observed_after_output"
    else:
        exit_observation = "nonzero_exit_observed"
    if status == "completed" and (code not in {0, _SIGKILL_EXIT} or not cleanup):
        status = "failed"
    projection: dict[str, bool | None] = dict.fromkeys(_CATEGORIES)
    if status == "completed":
        try:
            projection.update(stack_projection(stdout, pid))
        except ValueError:
            status = "invalid_output"
    public: dict[str, object] = {
        "status": status,
        "observation_missing": status != "completed",
        "collector_cleanup_complete": cleanup,
        "process_successful_exit_observed": code == 0,
        "process_exit_observation": exit_observation,
        "frame_scope": "sampled_call_graph_presence_only",
        **projection,
        "stdout_bytes_retained": len(stdout),
        "stderr_bytes_retained": len(stderr),
    }
    private: dict[str, object] = {
        "schema": "hol-guard.resolver-native-stack-private.v1",
        "status": status,
        "probe_pid": pid,
        "returncode": code,
        "collector_cleanup_complete": cleanup,
        "process_exit_observation": exit_observation,
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
    }
    return public, private


def observed_libc_probe(
    query: str,
    marker: str,
    *,
    deadline: float,
) -> tuple[str, bytes, int | None, dict[str, object], dict[str, object]]:
    """Sample at most once, after the fixed call-start marker, without a retry."""
    missing: dict[str, object] = {
        "status": "call_not_observed",
        "observation_missing": True,
        "collector_cleanup_complete": True,
        **dict.fromkeys(_CATEGORIES),
    }
    if sys.platform != "darwin":
        return "failed", b"", None, {**missing, "status": "not_macos"}, {}
    if time.monotonic() >= deadline:
        return "deadline_exceeded", b"", None, missing, {}
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", query],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        return "failed", b"", None, missing, {}
    future = None
    status, stdout, code = "failed", b"", None
    public, private = missing, {}
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:

            def started(output: bytes) -> None:
                nonlocal future, public
                if future is not None or not output.startswith(marker.encode("ascii") + b"\n"):
                    return
                if output.count(b"\n") > 1:
                    public = {**missing, "status": "probe_already_completed"}
                    return
                # One second of sampling plus bounded acquisition and cleanup
                # must fit inside this phase. Never start a new five-second wait.
                if deadline - time.monotonic() < 2.0:
                    public = {**missing, "status": "insufficient_budget"}
                    return
                # No poll/wait reaps the probe until the sampler has finished.
                # Even if the resolver exits now, its PID cannot be reused.
                future = executor.submit(_sample, process.pid, deadline - 0.75)

            try:
                status, stdout, _stderr = _read_streams(process, deadline, _PROBE_BYTES, started)
            finally:
                if future is not None:
                    public, private = _sample_report(future.result(), process.pid)
    except (OSError, ValueError):
        status = "failed"
    finally:
        cleanup = _stop_owned(process)
        code = process.returncode
        assert process.stdout is not None and process.stderr is not None
        process.stdout.close()
        process.stderr.close()
        if not cleanup:
            status = "cleanup_incomplete"
        elif status == "completed" and code == _SIGKILL_EXIT:
            # Completed stdout is not proof that the probe itself exited
            # successfully. Its result must never become a successful lookup.
            status = "sigkill_exit_observed_after_output"
        elif status == "completed" and code != 0:
            status = "failed"
        public["probe_cleanup_complete"] = cleanup
    return status, stdout, code, public, private
