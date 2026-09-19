"""Bound identity-command streams without changing child file-size limits.

Xcode discovery may write ordinary tool caches. A process-wide RLIMIT_FSIZE
would constrain those writes too. This collector bounds only the two pipes;
its cleanup observes the directly owned child, never descendant retirement.
"""

from __future__ import annotations

import hashlib
import os
import selectors
import subprocess
import time
from typing import Any

OUTPUT_LIMIT = 128 * 1024
IDENTITY_SECONDS = 5.0
_ERROR_PHRASES = {
    "file_size_limit": "file size limit exceeded",
    "sdk_unavailable": "cannot be located",
    "developer_directory_unavailable": "invalid active developer path",
    "tool_unavailable": "unable to find utility",
    "subcommand_failed": "failed with exit code",
}


def _retire(child: subprocess.Popen[bytes], result: dict[str, Any]) -> None:
    if child.returncode is not None:
        result["direct_child_reaped"] = True
        return
    result["termination_attempted"] = True
    try:
        child.kill()
    except OSError as error:
        result["kill_error"] = type(error).__name__
        result["kill_errno"] = error.errno
    try:
        result["return_code"] = child.wait(timeout=1.0)
        result["direct_child_reaped"] = True
    except (OSError, subprocess.TimeoutExpired) as error:
        result["cleanup_error"] = type(error).__name__


def _capture(arguments: tuple[str, ...], *, timeout: float = IDENTITY_SECONDS) -> dict[str, Any]:
    started = time.monotonic()
    deadline = started + timeout
    result: dict[str, Any] = {
        "argv": list(arguments),
        "status": "unavailable",
        "return_code": None,
        "termination_attempted": False,
        "completed_without_intervention": False,
        "direct_child_reaped": False,
        "descendant_retirement_verified": False,
        "process_file_size_limit_modified": False,
    }
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    child: subprocess.Popen[bytes] | None = None
    try:
        child = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with selectors.DefaultSelector() as selector:
            for label, stream in (("stdout", child.stdout), ("stderr", child.stderr)):
                if stream is None:
                    raise OSError("capture pipe unavailable")
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(arguments, timeout)
                events = selector.select(remaining)
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(arguments, timeout)
                for key, _events in events:
                    target = captured[key.data]
                    try:
                        block = os.read(key.fd, min(16 * 1024, OUTPUT_LIMIT + 1 - len(target)))
                    except BlockingIOError:
                        continue
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    target.extend(block)
                    if len(target) >= OUTPUT_LIMIT:
                        result["status"] = "output_limit"
                        result["limited_stream"] = key.data
                        break
                if result["status"] == "output_limit":
                    break
        if result["status"] != "output_limit":
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(arguments, timeout)
            result["return_code"] = child.wait(timeout=remaining)
            result["direct_child_reaped"] = True
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(arguments, timeout)
            result["status"] = "completed"
            result["completed_without_intervention"] = True
    except subprocess.TimeoutExpired:
        result["status"] = "deadline_exceeded"
    except (OSError, subprocess.SubprocessError) as error:
        result["error_category"] = type(error).__name__
        result["errno"] = getattr(error, "errno", None)
    finally:
        if child is not None:
            if not result["direct_child_reaped"]:
                _retire(child, result)
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
    elapsed = time.monotonic() - started
    if elapsed >= timeout and result["status"] == "completed":
        result["status"] = "deadline_exceeded"
        result["completed_without_intervention"] = False
    result["elapsed_ms"] = round(elapsed * 1000, 3)
    for label, buffer in captured.items():
        data = bytes(buffer)
        result[label + "_bytes"] = len(data)
        result[label + "_sha256"] = hashlib.sha256(data).hexdigest()
        result[label] = data[:OUTPUT_LIMIT].decode("utf-8", errors="replace")
        result[label + "_truncated"] = result.get("limited_stream") == label
    stderr = result["stderr"].lower()
    result["stderr_classes"] = [label for label, phrase in _ERROR_PHRASES.items() if phrase in stderr]
    return result
