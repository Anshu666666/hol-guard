"""Compare six newly observed direct, dlopen and Python children; never qualification."""

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
from scripts.ci.native_macos_dnssd_endpoint_binding import historical_admission, source_identity, tool_identity
from scripts.ci.native_macos_dnssd_endpoint_child import RUNTIME_KEY, runtime_identity
from scripts.ci.native_macos_dnssd_endpoint_evidence import parse_context
from scripts.ci.native_macos_dnssd_phase_identity import CPU_TYPES, binary_identity
from scripts.ci.native_macos_python_resolver_child import file_sha
from scripts.ci.native_macos_python_resolver_path import read_report
from scripts.ci.native_macos_resolver_capture import clean_completion, run_lookup

CHILD = Path(__file__).with_name("native_macos_dnssd_endpoint_child.py")
CONTROLS = tuple(
    (context, mode) for context in ("standalone", "native_dlopen", "python") for mode in ("dns_simple", "dns_shared")
)


def base() -> dict[str, Any]:
    return original._base() | {
        "schema": "hol-guard.macos-dnssd-endpoint-context.v1",
        "status": "unavailable",
        "stage": "platform",
        "scope": "six_new_read_only_direct_child_endpoint_and_loader_observations",
        "rows": [],
        "observation_complete": False,
        "cause_proved": False,
        "same_OFD_claimed": False,
        "daemon_acceptance_claimed": False,
        "internal_library_thread_census_claimed": False,
        "prior_children_replayed": False,
        "current_runtime_equal_to_historical_claimed": False,
    }


def prepare() -> dict[str, Any]:
    report = base()
    if not original._eligible():
        return report
    try:
        report["stage"] = "source_and_historical_binding"
        report["source"] = source_identity()
        report["historical"] = historical_admission()
        report["stage"] = "fresh_sdk_and_runtime"
        report["tools"] = tool_identity()
        report["runtime"] = runtime_identity()
        if report["runtime"][RUNTIME_KEY] != report["source"]["added_files"][str(CHILD.relative_to(original.ROOT))]:
            raise ValueError("runtime source mismatch")
        report.update(status="prepared", stage="complete")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report.update(status="admission_failed", error_type=type(error).__name__)
        if isinstance(error, original.IdentityCommandError):
            report["identity_command_failure"] = error.metadata
    return report


def identities(binary: Path, host: Path, bridge: Path, machine: str) -> dict[str, Any]:
    result = {
        "standalone": binary_identity(binary, 2),
        "native_dlopen": binary_identity(host, 2),
        "bridge": binary_identity(bridge, 6),
    }
    cpu = CPU_TYPES.get(machine)
    if cpu is None or any(row["cpu_type"] != cpu for row in result.values()):
        raise ValueError("binary architecture")
    return result


def collect(
    prepared: dict[str, Any], binary: Path, host: Path, bridge: Path, save: Callable[[dict[str, Any]], None]
) -> dict[str, Any]:
    report = base()
    if (
        not original._eligible()
        or prepared.get("status") != "prepared"
        or any(prepared.get(key) != report[key] for key in ("workflow_commit", "workflow_run", "workflow_attempt"))
    ):
        report.update(status="prepared_report_refused")
        return report
    try:
        report["stage"] = "fresh_source_tool_and_image_binding"
        report["source_before"], report["tools_before"] = source_identity(), tool_identity()
        report["runtime_before"], report["historical_before"] = runtime_identity(), historical_admission()
        if any(report[key + "_before"] != prepared[key] for key in ("source", "tools", "runtime", "historical")):
            raise ValueError("prepared bindings changed")
        machine = report["tools_before"]["machine"]
        before = identities(binary, host, bridge, machine)
        report["images_before"] = before
        report["stage"] = "six_new_children"
        save(report)
        for context, mode in CONTROLS:
            if identities(binary, host, bridge, machine) != before:
                raise ValueError("image changed before child")
            arguments = (
                (str(binary), mode)
                if context == "standalone"
                else (str(host), str(bridge), mode)
                if context == "native_dlopen"
                else (
                    sys.executable,
                    "-I",
                    "-B",
                    str(CHILD),
                    "--mode",
                    mode,
                    "--bridge",
                    str(bridge),
                    "--bridge-sha256",
                    before["bridge"]["sha256"],
                )
            )
            capture, data = run_lookup(arguments)
            executable = {} if context == "python" else before[context]
            observer = before["standalone" if context == "standalone" else "bridge"]
            metadata = parse_context(
                data,
                mode,
                capture["pid"],
                report["runtime_before"],
                context,
                executable,
                observer,
                report["tools_before"]["loader_flags"]["effective"],
            )
            report["rows"].append(
                {
                    "context": context,
                    "mode": mode,
                    "capture": capture,
                    "metadata": metadata,
                    "lookup_passed": clean_completion(capture) and metadata["complete"] and metadata["loopback_label"],
                }
            )
            save(report)
            if capture["pid"] is not None and not capture["direct_child_reaped"]:
                report.update(status="direct_child_cleanup_unproved")
                return report
        report["stage"] = "final_binding"
        report["source_after"], report["tools_after"] = source_identity(), tool_identity()
        report["runtime_after"], report["historical_after"] = runtime_identity(), historical_admission()
        report["images_after"] = identities(binary, host, bridge, machine)
        for key in ("source", "tools", "runtime", "historical", "images"):
            report[key + "_unchanged"] = report[key + "_after"] == report[key + "_before"]
        report["observation_complete"] = all(
            report[key + "_unchanged"] for key in ("source", "tools", "runtime", "historical", "images")
        ) and all(
            row["capture"]["direct_child_reaped"]
            and row["capture"].get("status") in ("completed", "deadline_exceeded")
            and row["capture"].get("stderr_bytes") == 0
            and not any(key in row["capture"] for key in ("cleanup_error", "kill_errno", "output_limit", "error_type"))
            and row["metadata"]["valid"]
            and not row["metadata"].get("partial_line")
            and not row["metadata"].get("trace_overflow")
            and (row["capture"]["status"] != "completed" or row["metadata"]["complete"])
            and row["metadata"]["endpoint"]["observation_complete"]
            for row in report["rows"]
        )
        report["comparison"] = [
            {
                "mode": mode,
                "contexts": [
                    {
                        "context": row["context"],
                        "capture_status": row["capture"]["status"],
                        "last_observed_boundary": row["metadata"].get("last_observed_boundary"),
                        "lookup_passed": row["lookup_passed"],
                        "endpoint": row["metadata"].get("endpoint"),
                    }
                    for row in report["rows"]
                    if row["mode"] == mode
                ],
                "causal_conclusion": "unproved",
            }
            for mode in ("dns_simple", "dns_shared")
        ]
        report["diagnostic_passed"] = report["observation_complete"] and all(
            row["lookup_passed"] for row in report["rows"]
        )
        report.update(status="experiment_finished", stage="complete")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report.update(status="diagnostic_failed", error_type=type(error).__name__)
        if isinstance(error, original.IdentityCommandError):
            report["identity_command_failure"] = error.metadata
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--host", type=Path)
    parser.add_argument("--bridge", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save(report: dict[str, Any]) -> None:
        pending = args.output.with_suffix(".pending")
        pending.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        pending.replace(args.output)

    if args.prepare:
        report = prepare()
    elif any(value is None for value in (args.prepared, args.binary, args.host, args.bridge)):
        report = base() | {"status": "binary_arguments_missing"}
    else:
        try:
            prepared, prepared_sha = read_report(args.prepared)
            report = collect(prepared, args.binary.absolute(), args.host.absolute(), args.bridge.absolute(), save)
            report["prepared_report_sha256"] = prepared_sha
            report["prepared_report_unchanged"] = file_sha(args.prepared, 64 * 1024) == prepared_sha
            if not report["prepared_report_unchanged"]:
                report["diagnostic_passed"] = report["observation_complete"] = False
                report["status"] = "prepared_report_changed"
        except (OSError, ValueError, TypeError, RecursionError) as error:
            report = base() | {"status": "prepared_read_failed", "error_type": type(error).__name__}
    save(report)
    return 0 if (report["status"] == "prepared" if args.prepare else report["diagnostic_passed"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
