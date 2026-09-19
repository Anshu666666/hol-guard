"""Bound one source-controlled no-fork lookup child; never certify descendants."""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
import time
from typing import Any

LOOKUP_SECONDS = 5.0
CAPTURE_BYTES = 16 * 1024


def _limit_output() -> None:
    import resource

    _soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit = CAPTURE_BYTES if hard == resource.RLIM_INFINITY else min(CAPTURE_BYTES, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def run_lookup(arguments: tuple[str, ...]) -> tuple[dict[str, Any], bytes]:
    """Retain exact child outcome, bounded metadata and the private parser input."""
    started = time.monotonic()
    deadline = started + LOOKUP_SECONDS
    report: dict[str, Any] = {
        "status": "unavailable",
        "return_code": None,
        "pid": None,
        "deadline_seconds": LOOKUP_SECONDS,
        "termination_attempted": False,
        "direct_child_reaped": False,
        "descendant_retirement_verified": False,
        "service_quiescence_verified": False,
    }
    process = None
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                preexec_fn=_limit_output,
                close_fds=True,
            )
            report["pid"] = process.pid
            report["return_code"] = process.wait(timeout=max(0, deadline - time.monotonic()))
            report.update(status="completed", direct_child_reaped=True)
        except subprocess.TimeoutExpired:
            report["status"] = "deadline_exceeded"
        except (OSError, subprocess.SubprocessError) as error:
            report.update(error_type=type(error).__name__, errno=getattr(error, "errno", None))
        finally:
            if process is not None and not report["direct_child_reaped"]:
                report["termination_attempted"] = True
                try:
                    # Popen retains this direct child; no numeric PID/group is
                    # accepted from output, and no descendant claim is made.
                    process.kill()
                except OSError as error:
                    report["kill_errno"] = error.errno
                try:
                    report["return_code"] = process.wait(timeout=1.0)
                    report["direct_child_reaped"] = True
                except (OSError, subprocess.TimeoutExpired) as error:
                    report["cleanup_error"] = type(error).__name__
            elapsed = time.monotonic() - started
            if elapsed >= LOOKUP_SECONDS and report["status"] == "completed":
                report["status"] = "deadline_exceeded"
            data = b""
            for name, stream in (("stdout", stdout), ("stderr", stderr)):
                stream.seek(0)
                captured = stream.read(CAPTURE_BYTES + 1)
                report[name + "_bytes"] = len(captured)
                report[name + "_sha256"] = hashlib.sha256(captured).hexdigest()
                if name == "stdout":
                    data = captured[:CAPTURE_BYTES]
                if len(captured) >= CAPTURE_BYTES:
                    report["output_limit"] = True
            report["elapsed_ms"] = round(elapsed * 1000, 3)
    return report, data


def clean_completion(report: dict[str, Any]) -> bool:
    return (
        report.get("status") == "completed"
        and report.get("return_code") == 0
        and report.get("direct_child_reaped") is True
        and report.get("termination_attempted") is False
        and report.get("stderr_bytes") == 0
        and not any(key in report for key in ("cleanup_error", "kill_errno", "output_limit", "error_type"))
    )
