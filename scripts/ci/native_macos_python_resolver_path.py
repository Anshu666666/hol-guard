"""Additional fixed Python/libc controls; original resolver reports remain separate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci import native_macos_resolver_path as original
from scripts.ci.native_macos_python_resolver_child import file_sha, runtime_identity
from scripts.ci.native_macos_python_resolver_evidence import MODES, macho_identity, parse_comparison
from scripts.ci.native_macos_resolver_capture import clean_completion, run_lookup

CHILD = Path(__file__).with_name("native_macos_python_resolver_child.py")
BRIDGE_FLAGS = (*original.COMPILE_FLAGS, "-dynamiclib")


def original_admission(prior: dict[str, Any], prepared: dict[str, Any]) -> str | None:
    current = original._base()
    if (
        prepared.get("status") != "prepared"
        or any(
            prior.get(key) != current[key] or prepared.get(key) != current[key]
            for key in ("workflow_commit", "workflow_run", "workflow_attempt")
        )
        or not isinstance(prior.get("source_before"), dict)
        or prior["source_before"] != prepared.get("source")
        or prior.get("tools_before") != prepared.get("tools")
    ):
        return "source_or_run_binding"
    if prior.get("status") != "experiment_finished" or prior.get("stage") != "complete":
        return "original_sequence_incomplete"
    if any(prior.get(key) is not True for key in ("source_unchanged", "tools_unchanged", "binary_unchanged")):
        return "original_binding_unproved"
    rows = prior.get("rows")
    if not isinstance(rows, list) or len(rows) != len(original.MODES):
        return "original_sequence_incomplete"
    for row, mode in zip(rows, original.MODES, strict=True):
        if not isinstance(row, dict) or row.get("mode") != mode or not isinstance(row.get("capture"), dict):
            return "original_sequence_incomplete"
        capture = row["capture"]
        if (
            type(capture.get("pid")) is not int
            or not 0 < capture["pid"] < 2**31
            or capture.get("direct_child_reaped") is not True
        ):
            return "original_child_retirement_unproved"
    return None


def read_report(path: Path) -> tuple[dict[str, Any], str]:
    before = file_sha(path, maximum=64 * 1024)
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 + 1)
    if (
        len(data) > 64 * 1024
        or file_sha(path, maximum=64 * 1024) != before
        or hashlib.sha256(data).hexdigest() != before
    ):
        raise ValueError("report boundary")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("report format")
    return value, before


def bridge_identity(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not 0 < before.st_size <= 256 * 1024 * 1024:
            raise ValueError("bridge size")
        header = stream.read(32)
        if len(header) != 32:
            raise ValueError("bridge header")
        size = struct.unpack("<I", header[20:24])[0]
        if size > 1024 * 1024 or size > before.st_size - 32:
            raise ValueError("bridge command limit")
        commands = stream.read(size)
        identity = macho_identity(header + commands)
        digest = hashlib.sha256(header + commands)
        remaining = before.st_size - len(header) - len(commands)
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                raise ValueError("bridge truncated")
            digest.update(block)
            remaining -= len(block)
        if stream.read(1):
            raise ValueError("bridge grew")
        after = os.fstat(stream.fileno())

        def fields(item: os.stat_result) -> tuple[int, ...]:
            return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns

        if fields(before) != fields(after) or fields(after) != fields(path.stat()):
            raise ValueError("bridge changed")
    return {"sha256": digest.hexdigest(), **identity}


def collect(
    prepared: dict[str, Any], bridge: Path, prior: dict[str, Any], save: Callable[[dict[str, Any]], None]
) -> dict[str, Any]:
    report: dict[str, Any] = original._base() | {
        "schema": "hol-guard.macos-python-resolver-path.v1",
        "scope": "additional_source_bound_python_libc_controls",
        "status": "unavailable",
        "stage": "platform",
        "rows": [],
        "bridge_compile_flags": list(BRIDGE_FLAGS),
        "link_library": "libSystem",
        "link_mode": "compiler_default",
    }
    if (
        not original._eligible()
        or prepared.get("status") != "prepared"
        or any(prepared.get(key) != report[key] for key in ("workflow_commit", "workflow_run", "workflow_attempt"))
    ):
        return report
    refusal = original_admission(prior, prepared)
    if refusal:
        return report | {"status": "original_report_refused", "stage": "original_admission", "reason": refusal}
    try:
        report["stage"] = "source_and_tool_binding"
        report["source_before"] = original.source_identity()
        report["tools_before"] = original.tool_identity()
        if report["source_before"] != prepared["source"] or report["tools_before"] != prepared["tools"]:
            raise ValueError("build inputs changed")
        report["runtime_before"] = runtime_identity()
        runtime = report["runtime_before"]
        if (
            runtime["python_sha256"] != report["tools_before"]["python_sha256"]
            or runtime["socket_sha256"] != report["tools_before"]["python_socket_module_sha256"]
            or runtime["child_source_sha256"]
            != report["source_before"]["sha256"][str(CHILD.relative_to(original.ROOT))]
        ):
            raise ValueError("Python runtime binding")
        report["bridge_before"] = bridge_identity(bridge)
        bound_bridge = report["bridge_before"]
        report["stage"] = "additional_controls"
        save(report)
        for mode in MODES:
            capture, data = run_lookup(
                (
                    sys.executable,
                    "-I",
                    str(CHILD),
                    "--mode",
                    mode,
                    "--bridge",
                    str(bridge),
                    "--bridge-sha256",
                    bound_bridge["sha256"],
                )
            )
            metadata = parse_comparison(data, mode, capture["pid"], runtime, bound_bridge)
            report["rows"].append(
                {
                    "mode": mode,
                    "capture": capture,
                    "metadata": metadata,
                    "lookup_passed": clean_completion(capture) and metadata["complete"] and metadata["loopback_label"],
                }
            )
            save(report)
            if capture["pid"] is not None and not capture["direct_child_reaped"]:
                report["status"] = "direct_child_cleanup_unproved"
                return report
        report["stage"] = "final_binding"
        report["source_unchanged"] = original.source_identity() == report["source_before"]
        report["tools_unchanged"] = original.tool_identity() == report["tools_before"]
        report["runtime_unchanged"] = runtime_identity() == runtime
        report["bridge_unchanged"] = bridge_identity(bridge) == bound_bridge
        identities = [
            row["metadata"]["records"][3]
            for row in report["rows"][2:]
            if row["metadata"]["valid"] and row["metadata"]["complete"]
        ]
        report["loaded_images_consistent"] = len(identities) == 2 and identities[0] == identities[1]
        report["diagnostic_passed"] = all(
            report[key]
            for key in (
                "source_unchanged",
                "tools_unchanged",
                "runtime_unchanged",
                "bridge_unchanged",
                "loaded_images_consistent",
            )
        ) and all(row["lookup_passed"] for row in report["rows"])
        report.update(status="experiment_finished", stage="complete")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="diagnostic_failed", error_type=type(error).__name__)
        if isinstance(error, original.IdentityCommandError):
            report["identity_command_failure"] = error.metadata
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--bridge", type=Path)
    parser.add_argument("--original-report", type=Path, required=True)
    parser.add_argument("--admit-original", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    prior_sha: str | None = None

    def save(report: dict[str, Any]) -> None:
        if prior_sha is not None:
            report["original_report_sha256"] = prior_sha
        pending = args.output.with_suffix(".pending")
        pending.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        pending.replace(args.output)

    report: dict[str, Any] = original._base() | {
        "schema": "hol-guard.macos-python-resolver-admission.v1",
        "stage": "original_admission",
        "status": "unavailable",
    }
    try:
        prepared, _prepared_sha = read_report(args.prepared)
        prior, prior_sha = read_report(args.original_report)
        report["original_report_sha256"] = prior_sha
        refusal = original_admission(prior, prepared)
        if not original._eligible() or refusal:
            report.update(status="original_report_refused", reason=refusal or "platform")
        elif args.admit_original:
            report.update(status="admitted")
        elif args.bridge is None:
            report.update(status="bridge_argument_missing")
        else:
            report = collect(prepared, args.bridge.resolve(strict=True), prior, save)
            report["original_report_sha256"] = prior_sha
            try:
                report["original_report_unchanged"] = file_sha(args.original_report, maximum=64 * 1024) == prior_sha
            except (OSError, ValueError) as error:
                report["original_report_unchanged"] = False
                report["original_report_binding_error"] = type(error).__name__
            if not report["original_report_unchanged"]:
                report["diagnostic_passed"] = False
    except (OSError, ValueError, RecursionError) as error:
        report.update(status="admission_failed", error_type=type(error).__name__, diagnostic_passed=False)
    save(report)
    return 0 if (report["status"] == "admitted" if args.admit_original else report["diagnostic_passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
