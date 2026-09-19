"""Append four bounded call observations after all eleven preceding lookup children."""

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
from scripts.ci.native_macos_dnssd_phase_child import CALL_POLICY, MODES, runtime_identity
from scripts.ci.native_macos_dnssd_phase_evidence import EXTRA_RUNTIME_KEY, parse_trace
from scripts.ci.native_macos_dnssd_phase_identity import CPU_TYPES, binary_identity
from scripts.ci.native_macos_dnssd_python_path import previous_admission as admit_python
from scripts.ci.native_macos_python_resolver_child import file_sha
from scripts.ci.native_macos_python_resolver_path import read_report
from scripts.ci.native_macos_resolver_capture import clean_completion, run_lookup

CHILD = Path(__file__).with_name("native_macos_dnssd_phase_child.py")
CONTROLS = tuple((context, mode) for context in ("standalone", "python") for mode in MODES)
BRIDGE_FLAGS = (*original.COMPILE_FLAGS, "-dynamiclib", "-DHOL_GUARD_PHASE_LIBRARY")


def previous_admission(
    prepared: dict[str, Any], prior: dict[str, Any], python: dict[str, Any], dnssd: dict[str, Any],
    original_sha: str, python_sha: str,
) -> str | None:
    refusal = admit_python(prepared, prior, python, original_sha)
    if refusal:
        return refusal
    if (
        any(dnssd.get(key) != prepared.get(key) for key in ("workflow_commit", "workflow_run", "workflow_attempt"))
        or dnssd.get("source_before") != prepared.get("source")
        or dnssd.get("tools_before") != prepared.get("tools")
        or dnssd.get("original_report_sha256") != original_sha
        or dnssd.get("python_report_sha256") != python_sha
    ):
        return "dnssd_source_or_run_binding"
    if dnssd.get("status") != "experiment_finished" or dnssd.get("stage") != "complete":
        return "dnssd_sequence_incomplete"
    if any(dnssd.get(key) is not True for key in (
        "source_unchanged", "tools_unchanged", "runtime_unchanged", "bridge_unchanged",
        "original_report_unchanged", "python_report_unchanged",
    )):
        return "dnssd_binding_unproved"
    rows = dnssd.get("rows")
    if not isinstance(rows, list) or len(rows) != len(MODES):
        return "dnssd_sequence_incomplete"
    for row, mode in zip(rows, MODES, strict=True):
        if not isinstance(row, dict) or row.get("mode") != mode or not isinstance(row.get("capture"), dict):
            return "dnssd_sequence_incomplete"
        capture = row["capture"]
        if (
            type(capture.get("pid")) is not int or not 0 < capture["pid"] < 2**31
            or capture.get("direct_child_reaped") is not True
        ):
            return "dnssd_child_retirement_unproved"
    return None


def collect(
    prepared: dict[str, Any], binary: Path, bridge: Path, previous: dict[str, Any],
    save: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    report: dict[str, Any] = original._base() | {
        "schema": "hol-guard.macos-dnssd-phase-path.v2",
        "scope": "four_source_bound_direct_child_call_observations",
        "status": "unavailable", "stage": "platform", "rows": [], "observation_complete": False,
        "call_policy": CALL_POLICY, "standalone_compile_flags": list(original.COMPILE_FLAGS),
        "bridge_compile_flags": list(BRIDGE_FLAGS), "link_library": "libSystem", "link_mode": "compiler_default",
        "internal_library_thread_census_claimed": False, "callback_record_limit": 16,
    }
    if not original._eligible():
        return report
    try:
        report["stage"] = "source_and_tool_binding"
        report["source_before"] = original.source_identity()
        report["tools_before"] = original.tool_identity()
        if report["source_before"] != prepared["source"] or report["tools_before"] != prepared["tools"]:
            raise ValueError("build inputs changed")
        runtime = runtime_identity()
        report["runtime_before"] = runtime
        if (
            {key: value for key, value in runtime.items() if key != EXTRA_RUNTIME_KEY} != previous.get("runtime_before")
            or runtime[EXTRA_RUNTIME_KEY] != report["source_before"]["sha256"][str(CHILD.relative_to(original.ROOT))]
        ):
            raise ValueError("Python runtime binding")
        report["binary_before"] = binary_identity(binary, 2)
        report["bridge_before"] = binary_identity(bridge, 6)
        expected_cpu = CPU_TYPES.get(report["tools_before"]["machine"])
        if expected_cpu is None or any(report[key]["cpu_type"] != expected_cpu for key in ("binary_before", "bridge_before")):
            raise ValueError("helper architecture")
        report["stage"] = "additional_controls"
        save(report)
        for context, mode in CONTROLS:
            identity = report["bridge_before" if context == "python" else "binary_before"]
            argv = (
                (sys.executable, "-I", str(CHILD), "--mode", mode, "--bridge", str(bridge),
                 "--bridge-sha256", identity["sha256"])
                if context == "python" else (str(binary), mode)
            )
            capture, data = run_lookup(argv)
            metadata = parse_trace(data, mode, capture["pid"], runtime, identity, python=context == "python")
            report["rows"].append({
                "context": context, "mode": mode, "capture": capture, "metadata": metadata,
                "lookup_passed": clean_completion(capture) and metadata["complete"] and metadata["loopback_label"],
            })
            save(report)
            if capture["pid"] is not None and not capture["direct_child_reaped"]:
                report["status"] = "direct_child_cleanup_unproved"
                return report
        report["stage"] = "final_binding"
        report["source_unchanged"] = original.source_identity() == report["source_before"]
        report["tools_unchanged"] = original.tool_identity() == report["tools_before"]
        report["runtime_unchanged"] = runtime_identity() == runtime
        report["binary_unchanged"] = binary_identity(binary, 2) == report["binary_before"]
        report["bridge_unchanged"] = binary_identity(bridge, 6) == report["bridge_before"]
        identities = [
            record for row in report["rows"] for record in row["metadata"]["records"] if record["kind"] == "identity"
        ]
        report["initial_loaded_images_consistent"] = len(identities) == 4 and all(
            all(record[key] == identities[0][key] for key in ("libinfo_uuid", "dnssd_uuid", "cpu_type"))
            for record in identities
        )
        report["observation_complete"] = all(report[key] for key in (
            "source_unchanged", "tools_unchanged", "runtime_unchanged", "binary_unchanged", "bridge_unchanged",
            "initial_loaded_images_consistent",
        )) and all(
            row["capture"]["direct_child_reaped"] and row["metadata"]["valid"]
            and row["capture"].get("status") in ("completed", "deadline_exceeded")
            and row["capture"].get("stderr_bytes") == 0
            and not any(key in row["capture"] for key in ("cleanup_error", "kill_errno", "output_limit", "error_type"))
            and not row["metadata"].get("partial_line") and not row["metadata"].get("trace_overflow")
            for row in report["rows"]
        )
        report["diagnostic_passed"] = report["observation_complete"] and all(row["lookup_passed"] for row in report["rows"])
        report.update(status="experiment_finished", stage="complete")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report.update(status="diagnostic_failed", error_type=type(error).__name__)
        if isinstance(error, original.IdentityCommandError):
            report["identity_command_failure"] = error.metadata
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("prepared", "original-report", "python-report", "dnssd-report", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--bridge", type=Path)
    parser.add_argument("--admit-previous", action="store_true")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = original._base() | {
        "schema": "hol-guard.macos-dnssd-phase-admission.v2", "status": "unavailable",
        "stage": "previous_admission", "observation_complete": False,
    }
    pins: dict[str, str] = {}

    def save(current: dict[str, Any]) -> None:
        current.update(pins)
        pending = args.output.with_suffix(".pending")
        pending.write_text(json.dumps(current, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        pending.replace(args.output)

    try:
        paths = {"prepared": args.prepared, "original": args.original_report, "python": args.python_report, "dnssd": args.dnssd_report}
        loaded = {label: read_report(path) for label, path in paths.items()}
        pins.update({label + "_report_sha256": digest for label, (_, digest) in loaded.items()})
        prepared, prior, python, dnssd = (loaded[label][0] for label in ("prepared", "original", "python", "dnssd"))
        refusal = previous_admission(prepared, prior, python, dnssd, loaded["original"][1], loaded["python"][1])
        if not original._eligible() or refusal:
            report.update(status="previous_report_refused", reason=refusal or "platform")
        elif args.admit_previous:
            report.update(status="admitted")
        elif args.binary is None or args.bridge is None:
            report.update(status="binary_arguments_missing")
        else:
            report = collect(prepared, args.binary.absolute(), args.bridge.absolute(), dnssd, save)
            for label, path in paths.items():
                try:
                    report[label + "_report_unchanged"] = file_sha(path, maximum=64 * 1024) == loaded[label][1]
                except (OSError, ValueError) as error:
                    report[label + "_report_unchanged"] = False
                    report[label + "_report_binding_error"] = type(error).__name__
                if not report[label + "_report_unchanged"]:
                    report["diagnostic_passed"] = report["observation_complete"] = False
    except (OSError, ValueError, RecursionError) as error:
        report.update(status="admission_failed", error_type=type(error).__name__, diagnostic_passed=False)
    save(report)
    return 0 if (report["status"] == "admitted" if args.admit_previous else report["diagnostic_passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
