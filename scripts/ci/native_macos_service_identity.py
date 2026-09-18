"""Read the actual Apple resolver service identity on a disposable macOS runner.

This diagnostic never signals, starts, stops, or reconfigures a service. A
launchd label is read from the trusted fixed plist before it is used in the one
read-only service query. The Apple code requirement is documented at:
https://developer.apple.com/library/archive/documentation/Security/Conceptual/
CodeSigningGuide/RequirementLang/RequirementLang.html
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import plistlib
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError

_PLIST = Path("/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist")
_EXECUTABLE = Path("/usr/sbin/mDNSResponder")
_OUTPUT_LIMIT = 128 * 1024
_PLIST_LIMIT = 128 * 1024
_EXECUTABLE_LIMIT = 128 * 1024 * 1024
_LABEL = re.compile(r"com\.apple\.mDNSResponder(?:\.reloaded)?\Z")
# codesign treats an unprefixed requirement operand as a filename. The leading
# equals sign selects inline source, as in Apple's documented -R="anchor apple".
_ANCHOR = ("/usr/bin/codesign", "--verify", "--strict", "-R", "=anchor apple", str(_EXECUTABLE))


def _limit_child_output() -> None:
    import resource

    # Only this single-threaded diagnostic CLI uses preexec_fn. The kernel
    # bounds both regular-file captures, including unexpected system output.
    _soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit = _OUTPUT_LIMIT if hard == resource.RLIM_INFINITY else min(_OUTPUT_LIMIT, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def _capture(arguments: tuple[str, ...], *, timeout: float = 5.0) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {
        "argv": list(arguments),
        "status": "unavailable",
        "return_code": None,
        "termination_attempted": False,
        "completed_without_intervention": False,
    }
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        child: subprocess.Popen[bytes] | None = None
        try:
            child = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                preexec_fn=_limit_child_output,
            )
            result["return_code"] = child.wait(timeout=timeout)
            result["status"] = "completed"
            result["completed_without_intervention"] = True
        except subprocess.TimeoutExpired:
            result["status"] = "deadline_exceeded"
            result["termination_attempted"] = True
            if child is not None:
                try:
                    child.kill()
                    result["return_code"] = child.wait(timeout=1.0)
                except (OSError, subprocess.TimeoutExpired) as error:
                    result["cleanup_error"] = type(error).__name__
        except (OSError, subprocess.SubprocessError) as error:
            result["error_category"] = type(error).__name__
            result["errno"] = getattr(error, "errno", None)
        elapsed = time.monotonic() - started
        if elapsed >= timeout:
            result["status"] = "deadline_exceeded"
            result["completed_without_intervention"] = False
        for label, stream in (("stdout", stdout), ("stderr", stderr)):
            stream.seek(0)
            data = stream.read(_OUTPUT_LIMIT + 1)
            result[label + "_bytes"] = len(data)
            result[label + "_sha256"] = hashlib.sha256(data).hexdigest()
            result[label] = data[:_OUTPUT_LIMIT].decode("utf-8", errors="replace")
            if len(data) >= _OUTPUT_LIMIT:
                result["status"] = "output_limit"
                result["completed_without_intervention"] = False
        result["elapsed_ms"] = round(elapsed * 1000, 3)
    return result


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    )


def _trusted_file(path: Path, maximum: int, *, keep_bytes: bool = False) -> tuple[dict[str, Any], bytes]:
    result: dict[str, Any] = {"path": str(path), "status": "unavailable", "trusted": False}
    try:
        for parent in reversed(path.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return result | {"status": "untrusted_ancestor", "ancestor": str(parent)}, b""
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
            before = os.fstat(stream.fileno())
            result.update(
                device=before.st_dev,
                inode=before.st_ino,
                uid=before.st_uid,
                gid=before.st_gid,
                mode=stat.S_IMODE(before.st_mode),
                size=before.st_size,
                mtime_ns=before.st_mtime_ns,
                ctime_ns=before.st_ctime_ns,
                links=before.st_nlink,
            )
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != 0
                or before.st_mode & 0o022
                or not 0 < before.st_size <= maximum
            ):
                return result | {"status": "untrusted_file"}, b""
            digest = hashlib.sha256()
            chunks = bytearray()
            total = 0
            while chunk := stream.read(min(64 * 1024, maximum + 1 - total)):
                total += len(chunk)
                if total > maximum:
                    return result | {"status": "file_byte_limit"}, b""
                digest.update(chunk)
                if keep_bytes:
                    chunks.extend(chunk)
            after = os.fstat(stream.fileno())
            if _identity(before) != _identity(after) or _identity(after) != _identity(path.lstat()):
                return result | {"status": "file_changed"}, b""
            if total != before.st_size:
                return result | {"status": "file_changed"}, b""
            return result | {"status": "read", "trusted": True, "sha256": digest.hexdigest()}, bytes(chunks)
    except OSError as error:
        return result | {"status": "read_failed", "errno": error.errno}, b""


def _service(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "invalid_plist", "valid": False}
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ExpatError, ValueError, TypeError, OverflowError):
        return result
    if not isinstance(value, dict):
        return result
    label, arguments, program = value.get("Label"), value.get("ProgramArguments"), value.get("Program")
    if isinstance(label, str):
        result["observed_label"] = label[:256]
    if not isinstance(label, str) or _LABEL.fullmatch(label) is None:
        return result | {"status": "unsupported_service_label"}
    if program is not None and not isinstance(program, str):
        return result | {"status": "invalid_program"}
    if (
        not isinstance(arguments, list)
        or not 1 <= len(arguments) <= 64
        or any(not isinstance(argument, str) or len(argument) > 4096 or "\0" in argument for argument in arguments)
    ):
        return result | {"status": "invalid_program_arguments"}
    result.update(program=program, program_arguments=arguments)
    if arguments[0] != str(_EXECUTABLE) or program not in (None, str(_EXECUTABLE)):
        return result | {"status": "unexpected_executable"}
    return result | {"status": "validated", "valid": True, "label": label, "service_target": "system/" + label}


def _printed_identity(capture: dict[str, Any], service: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"service_label_matches": False, "program_matches": False, "pid": None}
    if capture["status"] != "completed" or capture["return_code"] != 0:
        return result
    lines = capture["stdout"].splitlines()
    result["service_label_matches"] = bool(lines and lines[0] == service["service_target"] + " = {")
    programs = [line.removeprefix("\tprogram = ") for line in lines if line.startswith("\tprogram = ")]
    result["program_matches"] = programs == [str(_EXECUTABLE)]
    pids = [line.removeprefix("\tpid = ") for line in lines if line.startswith("\tpid = ")]
    if len(pids) == 1 and pids[0].isdigit() and 0 < int(pids[0]) <= 2**31 - 1:
        result["pid"] = int(pids[0])
    return result


def collect() -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.macos-service-identity.v1",
        "scope": "read_only_host_service_identity_no_qualification_cohort",
        "qualification_pass": False,
        "cache_effect_verified": False,
        "ownership_verified": False,
        "running_process_identity_verified": False,
        "service_intervention_attempted": False,
        "security_configuration_modified": False,
        "service_identity_verified": False,
        "workflow_commit": os.environ.get("GITHUB_SHA"),
        "workflow_run": os.environ.get("GITHUB_RUN_ID"),
        "workflow_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "command_deadline_seconds": 5.0,
        "command_capture_limit_bytes": _OUTPUT_LIMIT,
    }
    if (
        sys.platform != "darwin"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_OS") != "macOS"
        or not os.environ.get("GITHUB_RUN_ID", "").isdigit()
    ):
        return report | {"status": "not_disposable_macos_ci"}
    report["plist_before"], data = _trusted_file(_PLIST, _PLIST_LIMIT, keep_bytes=True)
    if report["plist_before"]["trusted"] is not True:
        return report | {"status": "plist_untrusted"}
    report["service"] = _service(data)
    if report["service"]["valid"] is not True:
        return report | {"status": "service_selection_failed"}
    report["executable_before"], _ = _trusted_file(_EXECUTABLE, _EXECUTABLE_LIMIT)
    if report["executable_before"]["trusted"] is not True:
        return report | {"status": "executable_untrusted"}
    report["apple_signature"] = _capture(_ANCHOR)
    report["launchd_service"] = _capture(
        (
            "/usr/bin/sudo",
            "-n",
            "/bin/launchctl",
            "print",
            report["service"]["service_target"],
        )
    )
    report["printed_identity"] = _printed_identity(report["launchd_service"], report["service"])
    report["plist_after"], _ = _trusted_file(_PLIST, _PLIST_LIMIT)
    report["executable_after"], _ = _trusted_file(_EXECUTABLE, _EXECUTABLE_LIMIT)
    report["files_unchanged"] = all(
        report[name + "_before"] == report[name + "_after"] for name in ("plist", "executable")
    )
    signature = report["apple_signature"]
    identity = report["printed_identity"]
    report["service_identity_verified"] = (
        report["files_unchanged"]
        and signature["status"] == "completed"
        and signature["return_code"] == 0
        and identity["service_label_matches"]
        and identity["program_matches"]
    )
    return report | {"status": "identity_verified" if report["service_identity_verified"] else "identity_unverified"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    report = collect()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0 if report["service_identity_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
