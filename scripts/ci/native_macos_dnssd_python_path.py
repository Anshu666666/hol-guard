"""Append two DNS-SD controls after the bound original and Python/libc reports."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci import native_macos_resolver_path as original
from scripts.ci.native_macos_dnssd_python_child import CALL_POLICY, MODES, runtime_identity
from scripts.ci.native_macos_dnssd_python_evidence import parse_comparison
from scripts.ci.native_macos_python_resolver_child import file_sha
from scripts.ci.native_macos_python_resolver_evidence import MODES as PREVIOUS_MODES
from scripts.ci.native_macos_python_resolver_path import BRIDGE_FLAGS, bridge_identity, original_admission, read_report
from scripts.ci.native_macos_resolver_capture import clean_completion, run_lookup

CHILD = Path(__file__).with_name("native_macos_dnssd_python_child.py")


def previous_admission(
    prepared: dict[str, Any], prior: dict[str, Any], current: dict[str, Any], prior_sha: str
) -> str | None:
    refusal = original_admission(prior, prepared)
    if refusal:
        return refusal
    if (
        any(current.get(key) != prepared.get(key) for key in ("workflow_commit", "workflow_run", "workflow_attempt"))
        or current.get("source_before") != prepared.get("source")
        or current.get("tools_before") != prepared.get("tools")
        or current.get("original_report_sha256") != prior_sha
    ):
        return "previous_source_or_run_binding"
    if current.get("status") != "experiment_finished" or current.get("stage") != "complete":
        return "previous_sequence_incomplete"
    if any(
        current.get(key) is not True
        for key in (
            "source_unchanged",
            "tools_unchanged",
            "runtime_unchanged",
            "bridge_unchanged",
            "original_report_unchanged",
        )
    ):
        return "previous_binding_unproved"
    rows = current.get("rows")
    if not isinstance(rows, list) or len(rows) != len(PREVIOUS_MODES):
        return "previous_sequence_incomplete"
    for row, mode in zip(rows, PREVIOUS_MODES, strict=True):
        if not isinstance(row, dict) or row.get("mode") != mode or not isinstance(row.get("capture"), dict):
            return "previous_sequence_incomplete"
        capture = row["capture"]
        if (
            type(capture.get("pid")) is not int
            or not 0 < capture["pid"] < 2**31
            or capture.get("direct_child_reaped") is not True
        ):
            return "previous_child_retirement_unproved"
    return None


def collect(
    prepared: dict[str, Any], bridge: Path, previous: dict[str, Any], save: Callable[[dict[str, Any]], None]
) -> dict[str, Any]:
    report: dict[str, Any] = original._base() | {
        "schema": "hol-guard.macos-dnssd-python-path.v1",
        "scope": "additional_source_bound_dnssd_python_controls",
        "status": "unavailable",
        "stage": "platform",
        "rows": [],
        "call_policy": CALL_POLICY,
        "bridge_compile_flags": list(BRIDGE_FLAGS),
        "link_library": "libSystem",
        "link_mode": "compiler_default",
        "internal_library_thread_census_claimed": False,
    }
    if not original._eligible():
        return report
    try:
        report["stage"] = "source_and_tool_binding"
        report["source_before"] = original.source_identity()
        report["tools_before"] = original.tool_identity()
        if report["source_before"] != prepared["source"] or report["tools_before"] != prepared["tools"]:
            raise ValueError("build inputs changed")
        report["runtime_before"] = runtime_identity()
        runtime = report["runtime_before"]
        if {key: value for key, value in runtime.items() if key != "dnssd_child_source_sha256"} != previous.get(
            "runtime_before"
        ) or runtime["dnssd_child_source_sha256"] != report["source_before"]["sha256"][
            str(CHILD.relative_to(original.ROOT))
        ]:
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
            for row in report["rows"]
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
    parser.add_argument("--original-report", type=Path, required=True)
    parser.add_argument("--python-report", type=Path, required=True)
    parser.add_argument("--bridge", type=Path)
    parser.add_argument("--admit-previous", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = original._base() | {
        "schema": "hol-guard.macos-dnssd-python-admission.v1",
        "stage": "previous_admission",
        "status": "unavailable",
    }
    pins: dict[str, str] = {}

    def save(current: dict[str, Any]) -> None:
        current.update(pins)
        pending = args.output.with_suffix(".pending")
        pending.write_text(json.dumps(current, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        pending.replace(args.output)

    try:
        prepared, _ = read_report(args.prepared)
        prior, prior_sha = read_report(args.original_report)
        previous, previous_sha = read_report(args.python_report)
        pins.update(original_report_sha256=prior_sha, python_report_sha256=previous_sha)
        refusal = previous_admission(prepared, prior, previous, prior_sha)
        if not original._eligible() or refusal:
            report.update(status="previous_report_refused", reason=refusal or "platform")
        elif args.admit_previous:
            report.update(status="admitted")
        elif args.bridge is None:
            report.update(status="bridge_argument_missing")
        else:
            report = collect(prepared, args.bridge.resolve(strict=True), previous, save)
            for label, path, digest in (
                ("original", args.original_report, prior_sha),
                ("python", args.python_report, previous_sha),
            ):
                try:
                    report[label + "_report_unchanged"] = file_sha(path, maximum=64 * 1024) == digest
                except (OSError, ValueError) as error:
                    report[label + "_report_unchanged"] = False
                    report[label + "_report_binding_error"] = type(error).__name__
                if not report[label + "_report_unchanged"]:
                    report["diagnostic_passed"] = False
    except (OSError, ValueError, RecursionError) as error:
        report.update(status="admission_failed", error_type=type(error).__name__, diagnostic_passed=False)
    save(report)
    return 0 if (report["status"] == "admitted" if args.admit_previous else report["diagnostic_passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
