"""Observe developer selection only after a retained SDK identity failure.

Apple TN2339 documents xcode-select --print-path. This never retries xcrun,
changes selection, or turns the preceding failed preparation into success.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import stat
import sys
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci import native_macos_resolver_path as original
from scripts.ci.native_macos_python_resolver_child import file_sha
from scripts.ci.native_macos_python_resolver_path import read_report
from scripts.ci.native_macos_resolver_tool_capture import _capture

COMMAND = ("/usr/bin/xcode-select", "--print-path")
PLIST_LIMIT = 256 * 1024


def failed_identity_capture(value: Any) -> bool:
    if not isinstance(value, dict) or value.get("operation") != "clang" or value.get("direct_child_reaped") is not True:
        return False
    status = value.get("status")
    if not isinstance(status, str) or status not in {"completed", "unavailable", "deadline_exceeded", "output_limit"}:
        return False
    completed = status == "completed"
    if value.get("completed_without_intervention") is not completed:
        return False
    return (
        not completed
        or (type(value.get("return_code")) is int and value["return_code"] != 0)
        or (type(value.get("stderr_bytes")) is int and value["stderr_bytes"] > 0)
    )


def environment_identity() -> dict[str, Any]:
    result = {}
    for name in ("DEVELOPER_DIR", "SDKROOT"):
        value = os.environ.get(name)
        if value is None:
            result[name] = {"present": False}
            continue
        raw = value.encode("utf-8", errors="surrogateescape")
        shape = (
            "over_limit"
            if len(raw) > 4096
            else "empty"
            if not raw
            else "absolute_path"
            if value.startswith("/")
            else "relative_or_sdk_name"
        )
        result[name] = {"present": True, "bytes": len(raw), "shape": shape, "sha256": hashlib.sha256(raw).hexdigest()}
    return result


def selected_path(data: bytes) -> Path:
    if not 1 < len(data) <= 4096 or not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise ValueError("selection framing")
    value = data[:-1].decode("utf-8")
    if not value.startswith("/") or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("selection format")
    path = Path(value)
    if any(part in {"", ".", ".."} for part in value.split("/")[1:]):
        raise ValueError("selection components")
    return path


def selection_shape(path: Path) -> str:
    if str(path) == "/Library/Developer/CommandLineTools":
        return "command_line_tools"
    if path.name == "Developer" and path.parent.name == "Contents" and path.parent.parent.suffix == ".app":
        return "xcode_developer"
    return "other_absolute"


def stable_bytes(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= PLIST_LIMIT:
            raise ValueError("plist boundary")
        data = stream.read(PLIST_LIMIT + 1)
        after = os.fstat(stream.fileno())

        def fields(value: os.stat_result) -> tuple[int, ...]:
            return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns

        if len(data) != before.st_size or fields(before) != fields(after) or fields(after) != fields(path.stat()):
            raise ValueError("plist changed")
    return data


def bundle_identity(selection: Path) -> dict[str, Any]:
    # Unsupported locations are observed as such, never searched or guessed.
    if selection_shape(selection) != "xcode_developer" or not selection.is_relative_to("/Applications"):
        return {"status": "unsupported_selection_shape"}
    resolved = selection.resolve(strict=True)
    if selection_shape(resolved) != "xcode_developer" or not resolved.is_relative_to("/Applications"):
        return {"status": "unsupported_resolved_selection"}
    path = resolved.parent / "Info.plist"
    data = stable_bytes(path)
    try:
        parsed = plistlib.loads(data)
    except (plistlib.InvalidFileException, ExpatError) as error:
        raise ValueError("plist encoding") from error
    if not isinstance(parsed, dict):
        raise ValueError("plist object")
    result: dict[str, Any] = {
        "status": "observed",
        "plist_bytes": len(data),
        "plist_sha256": hashlib.sha256(data).hexdigest(),
        "resolved_selection_sha256": hashlib.sha256(os.fsencode(resolved)).hexdigest(),
        "bundle_identifier_matches_xcode": parsed.get("CFBundleIdentifier") == "com.apple.dt.Xcode",
    }
    for key, pattern in (
        ("CFBundleShortVersionString", r"[0-9]{1,4}(?:\.[0-9]{1,4}){0,3}"),
        ("CFBundleVersion", r"[0-9]{1,8}(?:\.[0-9]{1,4}){0,3}"),
        ("DTXcodeBuild", r"[0-9]{1,3}[A-Z][0-9]{1,6}[a-z]?"),
    ):
        value = parsed.get(key)
        result[key + "_valid"] = isinstance(value, str) and re.fullmatch(pattern, value) is not None
        if result[key + "_valid"]:
            result[key] = value
    return result


def collect(prepared: dict[str, Any], prepared_sha: str) -> dict[str, Any]:
    report: dict[str, Any] = original._base() | {
        "schema": "hol-guard.macos-xcode-selection.v1",
        "status": "unavailable",
        "stage": "failure_admission",
        "prepared_sha256": prepared_sha,
        "original_sdk_failure_preserved": True,
        "xcrun_retried": False,
        "selection_modified": False,
        "selection_requeried": False,
        "xcrun_stall_cause_proven": False,
        "observation_complete": False,
    }
    failure = prepared.get("identity_command_failure")
    if (
        not original._eligible()
        or prepared.get("status") != "identity_failed"
        or prepared.get("stage") != "tool_identity"
        or prepared.get("diagnostic_passed") is not False
        or prepared.get("qualification_pass") is not False
        or any(prepared.get(key) != report[key] for key in ("workflow_commit", "workflow_run", "workflow_attempt"))
        or not failed_identity_capture(failure)
    ):
        return report | {"status": "original_failure_not_admitted"}
    try:
        report["stage"] = "source_binding"
        report["source_before"] = original.source_identity()
        if report["source_before"] != prepared.get("source"):
            raise ValueError("source mismatch")
        report["python_sha256"] = file_sha(Path(sys.executable))
        report["xcode_select_sha256"] = file_sha(Path(COMMAND[0]))
        report["environment_before"] = environment_identity()
        report["stage"] = "selected_directory"
        capture = _capture(COMMAND)
        report["capture"] = {key: value for key, value in capture.items() if key not in {"stdout", "stderr", "argv"}}
        if (
            capture.get("completed_without_intervention") is not True
            or capture.get("status") != "completed"
            or type(capture.get("return_code")) is not int
            or capture["return_code"] != 0
            or capture.get("direct_child_reaped") is not True
            or capture.get("termination_attempted") is not False
            or capture.get("stderr_bytes") != 0
            or any(capture.get(key) for key in ("stdout_truncated", "stderr_truncated"))
            or any(key in capture for key in ("limited_stream", "error_category", "kill_error", "cleanup_error"))
        ):
            return report | {"status": "selection_command_failed"}
        # The shared capture returns replacement-decoded text. Recover a path
        # only if strict UTF-8 round-tripping matches the original byte digest.
        if not isinstance(capture.get("stdout"), str):
            raise ValueError("selection capture schema")
        selected_bytes = capture["stdout"].encode("utf-8")
        if len(selected_bytes) != capture.get("stdout_bytes") or hashlib.sha256(
            selected_bytes
        ).hexdigest() != capture.get("stdout_sha256"):
            raise ValueError("selection capture bytes")
        selection = selected_path(selected_bytes)
        report["selection_shape"] = selection_shape(selection)
        report["stage"] = "selected_bundle"
        report["bundle_before"] = bundle_identity(selection)
        report["bundle_unchanged"] = bundle_identity(selection) == report["bundle_before"]
        report["selected_xcode_bundle_identity_verified"] = (
            report["bundle_before"].get("status") == "observed"
            and report["bundle_before"].get("bundle_identifier_matches_xcode") is True
            and report["bundle_unchanged"]
        )
        report["environment_unchanged"] = environment_identity() == report["environment_before"]
        report["source_unchanged"] = original.source_identity() == report["source_before"]
        report["python_unchanged"] = file_sha(Path(sys.executable)) == report["python_sha256"]
        report["xcode_select_unchanged"] = file_sha(Path(COMMAND[0])) == report["xcode_select_sha256"]
        report["observation_complete"] = all(
            report[key]
            for key in (
                "bundle_unchanged",
                "environment_unchanged",
                "source_unchanged",
                "python_unchanged",
                "xcode_select_unchanged",
            )
        )
        report.update(status="observation_finished", stage="complete")
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        report.update(status="observation_failed", error_type=type(error).__name__)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = original._base() | {"schema": "hol-guard.macos-xcode-selection.v1", "status": "admission_failed"}
    try:
        prepared, digest = read_report(args.prepared)
        report = collect(prepared, digest)
        report["prepared_unchanged"] = file_sha(args.prepared, maximum=64 * 1024) == digest
        if not report["prepared_unchanged"]:
            report["observation_complete"] = False
    except (OSError, ValueError, RecursionError) as error:
        report.update(error_type=type(error).__name__, observation_complete=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    pending = args.output.with_suffix(".pending")
    pending.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    pending.replace(args.output)
    return 0 if report.get("observation_complete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
