"""One explicit native resolver-cache experiment before either immutable arm.

Apple mDNSResponder-2600.100.147 handles SIGHUP by purging cached records and
restarting queries. The launchd service target avoids selecting a process by
an unowned numeric PID or executable-name search. No service is restarted,
and no hosts, hostname, resolver configuration, artifact, or deadline is edited.

https://github.com/apple-oss-distributions/mDNSResponder/blob/
d89f8d1d0e001b810d6c055aa2a57b768bcf9aa2/mDNSMacOSX/daemon.c
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from typing import Any

from .native_loopback_lookup import hosts_mapping_witness

_SIGNAL = ("/usr/bin/sudo", "-n", "/bin/launchctl", "kill", "SIGHUP", "system/com.apple.mDNSResponder")
_DNS = ("/usr/sbin/scutil", "--dns")
_LOOKUPS = {
    "getfqdn": "socket.getfqdn('127.0.0.1')",
    "gethostbyaddr": "socket.gethostbyaddr('127.0.0.1')[0]",
    "getnameinfo": "socket.getnameinfo(('127.0.0.1', 0), socket.NI_NAMEREQD | socket.NI_NUMERICSERV)[0]",
}


def _fixed_command(arguments: tuple[str, ...], *, limit: int) -> tuple[dict[str, Any], bytes]:
    """Bound fixed system commands; retain only status and output digests."""
    started = time.monotonic()
    report: dict[str, Any] = {"status": "unavailable", "return_code": None}
    stdout = stderr = b""
    try:
        completed = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False)
        stdout, stderr = completed.stdout, completed.stderr
        report.update(status="completed" if completed.returncode == 0 else "failed", return_code=completed.returncode)
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        report["status"] = "deadline_exceeded"
    except OSError as error:
        report["errno"] = error.errno
    if len(stdout) + len(stderr) > limit:
        report["status"] = "size_limit"
    if time.monotonic() - started >= 5:
        report["status"] = "deadline_exceeded"
    report.update(
        stdout_bytes=len(stdout),
        stderr_bytes=len(stderr),
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        elapsed_ms=round((time.monotonic() - started) * 1000, 3),
    )
    return report, stdout if report["status"] == "completed" else b""


def libc_probe(operation: str) -> dict[str, Any]:
    expression = _LOOKUPS[operation]
    code = (
        "import json,socket; "
        f"name={expression}; "
        "print(json.dumps({'loopback_label': name in ('127.0.0.1', 'localhost', "
        "'hol-guard-qualification.localhost')}))"
    )
    report, stdout = _fixed_command((sys.executable, "-I", "-c", code), limit=4096)
    report.update(operation=operation, loopback_label=False)
    if report["status"] == "completed":
        try:
            value = json.loads(stdout)
            if not isinstance(value, dict) or type(value.get("loopback_label")) is not bool:
                raise ValueError("invalid fixed lookup evidence")
            report["loopback_label"] = value["loopback_label"]
        except (ValueError, TypeError):
            report["status"] = "invalid_child_evidence"
    return report


def _hosts_eligible(report: dict[str, Any]) -> bool:
    mapping = report.get("mapping", {})
    return (
        report.get("status") == "read"
        and report.get("expected_directory_trusted") is True
        and report.get("file_trusted") is True
        and mapping.get("exact_ipv4_localhost_present") is True
        and mapping.get("exact_ipv6_localhost_present") is True
        and all(
            mapping.get(key) == 0
            for key in (
                "duplicate_ipv4_localhost_records",
                "duplicate_ipv6_localhost_records",
                "localhost_conflicts",
                "malformed",
            )
        )
    )


def _libc_completed(rows: list[dict[str, Any]]) -> bool:
    return len(rows) == 3 and all(row["status"] == "completed" and row["loopback_label"] is True for row in rows)


def refresh_native_cache(
    original_probe: dict[str, object], *, progress: Callable[[dict[str, Any]], None] | None = None
) -> dict[str, Any]:
    """Record one controlled intervention; never retry or qualify an arm."""
    report: dict[str, Any] = {
        "schema": "hol-guard.native-loopback-cache-experiment.v1",
        "environment_scope": "disposable_ci_runner_both_arms",
        "mechanism": "launchd_mdns_sighup",
        "signal_attempts": 0,
        "qualification_sample": False,
        "qualification_pass": False,
        "baseline_artifact_modified": False,
        "runtime_patched": False,
        "fixture_deadline_changed": False,
        "original_probe": original_probe,
        "libc_recovered": False,
    }
    if (
        sys.platform != "darwin"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_OS") != "macOS"
        or not os.environ.get("GITHUB_RUN_ID", "").isdigit()
    ):
        return report | {"status": "not_disposable_macos_ci"}
    if original_probe.get("status") == "completed":
        return report | {"status": "lookup_already_completed"}
    report["hosts_before"] = hosts_mapping_witness()
    report["dns_before"], _ = _fixed_command(_DNS, limit=256 * 1024)
    if not _hosts_eligible(report["hosts_before"]) or report["dns_before"]["status"] != "completed":
        return report | {"status": "configuration_witness_unavailable"}
    report["libc_before"] = [libc_probe(operation) for operation in _LOOKUPS]
    if _libc_completed(report["libc_before"]):
        return report | {"status": "completed_before_intervention"}
    report["signal_attempts"] = 1
    report["status"] = "native_signal_pending"
    if progress is not None:
        progress(report)
    report["signal"], _ = _fixed_command(_SIGNAL, limit=4096)
    report["status"] = "native_signal_completed"
    if progress is not None:
        progress(report)
    # Fixed order and one pass, even if the native service rejects the signal.
    # Each fresh libc child keeps the existing five-second diagnostic bound.
    report["libc_after"] = [libc_probe(operation) for operation in _LOOKUPS]
    report["hosts_after"] = hosts_mapping_witness()
    report["dns_after"], _ = _fixed_command(_DNS, limit=256 * 1024)
    report["hosts_unchanged"] = report["hosts_before"] == report["hosts_after"]
    report["dns_configuration_unchanged"] = (
        report["dns_after"]["status"] == "completed"
        and report["dns_before"]["stdout_sha256"] == report["dns_after"]["stdout_sha256"]
    )
    report["libc_recovered"] = (
        report["signal"]["status"] == "completed"
        and report["hosts_unchanged"]
        and report["dns_configuration_unchanged"]
        and _libc_completed(report["libc_after"])
    )
    report["status"] = "experiment_finished"
    return report
