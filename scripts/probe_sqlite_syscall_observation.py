"""Bounded Linux SQLite tracing feasibility; never installed qualification.

Raw trace stays in bounded process memory. The report contains only metadata,
finite-control results and normalized counters, never file or SQL contents.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.sqlite_syscall_probe_supervision import RAW_CALLS, _run_child
from scripts.sqlite_syscall_trace_diagnostics import SyntaxDiagnostics

PAYLOAD_SENTINEL = b"rsp131-private-value-never-in-observer-report"
PRIVATE_MARKER = b"rsp131-private"
_LINE = re.compile(r"^(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?(.*)$")
_CALL = re.compile(r"^([a-z][a-z0-9_]*)\((.*)\)\s+=\s+(.+)$")


def parse_calls(
    trace: bytes, owner_pid: int, diagnostics: SyntaxDiagnostics | None = None
) -> tuple[list[tuple[int, str, str, str]], bool]:
    """Retain no raw lines in returned errors; incomplete pairs fail closed."""
    calls: list[tuple[int, str, str, str]] = []
    pending: dict[int, str] = {}
    valid = True
    for line in trace.decode("utf-8", errors="replace").splitlines():
        match = _LINE.fullmatch(line)
        if match is None:
            if diagnostics is not None:
                diagnostics.record("invalid_prefix", line)
            valid = False
            continue
        tid = int(match[1] or match[2] or owner_pid)
        body = match[3]
        if body.endswith(" <unfinished ...>"):
            if diagnostics is not None and tid in pending:
                diagnostics.record("duplicate_unfinished", line)
            valid &= tid not in pending
            pending[tid] = body.removesuffix(" <unfinished ...>")
            continue
        if body.startswith("<... "):
            resumed = re.fullmatch(r"<\.\.\. ([a-z][a-z0-9_]*) resumed>(.*)", body)
            prefix = pending.pop(tid, None)
            if resumed is None or prefix is None or not prefix.startswith(resumed[1] + "("):
                if diagnostics is not None:
                    reason = (
                        "malformed_resumed"
                        if resumed is None
                        else "unmatched_resumed"
                        if prefix is None
                        else "mismatched_resumed"
                    )
                    diagnostics.record(reason, line)
                valid = False
                continue
            body = prefix + resumed[2]
        call = _CALL.fullmatch(body)
        if call is not None:
            calls.append((tid, call[1], call[2], call[3]))
        elif not (body.startswith(("+++ ", "--- ", "strace: Process "))):
            if diagnostics is not None:
                diagnostics.record("unrecognized_record", line)
            valid = False
    if diagnostics is not None:
        for prefix in pending.values():
            diagnostics.record("dangling_unfinished", prefix)
    return calls, valid and not pending


def raw_write_arguments_only(calls: list[tuple[int, str, str, str]]) -> bool:
    numbers = r"-?(?:0x[0-9a-f]+|[0-9]+)"
    raw = re.compile(numbers + r"(?:, " + numbers + r")*")
    writes = [arguments for _tid, name, arguments, _result in calls if name in RAW_CALLS.split(",")]
    return bool(writes) and all(raw.fullmatch(arguments) is not None for arguments in writes)


def _integer(value: str) -> int | None:
    token = value.split()[0].split("<", 1)[0]
    try:
        return int(token, 16 if token.startswith("0x") else 10)
    except ValueError:
        return None


def descriptor_witness(calls: list[tuple[int, str, str, str]], root: Path, child: dict[str, Any]) -> dict[str, object]:
    """Only the serial main-thread FD controls are admitted by this witness.

    Concurrent SQLite calls remain a format feasibility observation; this
    deliberately does not claim their complete per-file lifetime attribution.
    """
    owner = child["identity"]["pid"]
    descriptors = child["descriptors"]
    active: dict[int, str] = {}
    counts = {"a_write_bytes": 0, "a_sync_success": 0, "b_pwrite_bytes": 0, "b_sync_success": 0, "bad_sync": 0}
    opened: list[tuple[str, int]] = []
    valid = True
    for tid, name, arguments, result in calls:
        if tid != owner:
            continue
        returned = _integer(result)
        if name in {"open", "openat"} and returned is not None and returned >= 0:
            roles = [role for role in ("a", "b") if f'"{root}/descriptor-{role}"' in arguments]
            if roles:
                valid &= returned not in active
                active[returned] = roles[0]
                opened.append((roles[0], returned))
            elif returned in active:
                valid = False
        first = _integer(arguments.split(",", 1)[0])
        if first is None:
            continue
        if (
            name in {"dup", "dup2", "dup3", "fcntl"}
            and first in active
            and (name != "fcntl" or "F_DUPFD" in arguments)
            and returned is not None
            and returned >= 0
        ):
            valid &= returned not in active
            active[returned] = active[first]
        if name == "write" and active.get(first) == "a" and returned is not None and returned >= 0:
            counts["a_write_bytes"] += returned
        if name == "pwrite64" and active.get(first) == "b" and returned is not None and returned >= 0:
            counts["b_pwrite_bytes"] += returned
        if name in {"fsync", "fdatasync"}:
            role = active.get(first)
            if role in {"a", "b"} and returned == 0:
                counts[f"{role}_sync_success"] += 1
            if first == descriptors["invalid_sync_fd"] and returned == -1 and "EBADF" in result:
                counts["bad_sync"] += 1
        if name == "close" and returned == 0:
            active.pop(first, None)
    expected = descriptors["expected_bytes"]
    checks = {
        "complete_serial_descriptor_lifetimes": valid and not active,
        "expected_open_reuse": opened == [("a", descriptors["first_fd"]), ("b", descriptors["second_fd"])],
        "different_file_identity": descriptors["first_identity"] != descriptors["second_identity"],
        "actual_fd_reused": descriptors["fd_reused"] is True,
        "a_write_exact": counts["a_write_bytes"] == descriptors["write_bytes"] == expected,
        "b_pwrite_exact": counts["b_pwrite_bytes"] == descriptors["pwrite_bytes"] == expected,
        "a_duplicate_sync_exact": counts["a_sync_success"] == 1,
        "b_sync_exact": counts["b_sync_success"] == 1,
        "real_bad_sync_exact": counts["bad_sync"] == 1
        and descriptors["invalid_sync_errno"] == descriptors["invalid_sync_expected"],
    }
    return {"checks": checks, "counts": counts, "passed": all(checks.values())}


def _redact_descriptors(result: dict[str, Any]) -> None:
    child = result.get("child")
    if not isinstance(child, dict) or not isinstance(child.get("descriptors"), dict):
        return
    raw = child["descriptors"]
    identities = [raw["first_identity"], raw["second_identity"]]
    child["descriptors"] = {
        key: raw[key]
        for key in (
            "fd_reused",
            "write_bytes",
            "pwrite_bytes",
            "expected_bytes",
            "invalid_sync_errno",
            "invalid_sync_expected",
        )
    }
    child["descriptors"]["different_file_identity"] = identities[0] != identities[1]
    child["descriptors"]["file_identity_sha256"] = hashlib.sha256(json.dumps(identities).encode()).hexdigest()


def _child_control_checks(result: dict[str, Any]) -> dict[str, bool]:
    child = result.get("child")
    if not isinstance(child, dict) or not {"identity", "sqlite", "descriptors"}.issubset(child):
        return {"child_control_report_complete": False}
    identity, sqlite, descriptors = (child[key] for key in ("identity", "sqlite", "descriptors"))
    return {
        "direct_pid_start_parent_and_group": identity["pid"] == result["launch_pid"]
        and identity["start_ticks"] == result["launch_start_ticks"]
        and identity["parent_pid"] == result["caller_pid"]
        and identity["process_group"] == result["launch_pid"],
        "complete_successful_contained_child": result["returncode"] == 0
        and result["contained"]
        and result["streams_complete"]
        and result["leader_reaped"]
        and result["supervisor_failure"] is None
        and not result["timed_out"],
        "real_sqlite_wal_concurrency_readback": sqlite["journal_mode"] == "wal"
        and sqlite["rows"] == 7
        and not sqlite["worker_failures"]
        and sqlite["checkpoint"][0] == 0,
        "real_sqlite_readonly_error": sqlite["readonly_error"] == 8,
        "serial_descriptor_operations": descriptors["fd_reused"]
        and descriptors["first_identity"] != descriptors["second_identity"]
        and descriptors["write_bytes"] == descriptors["pwrite_bytes"] == descriptors["expected_bytes"]
        and descriptors["invalid_sync_errno"] == descriptors["invalid_sync_expected"],
    }


def run_probe() -> dict[str, object]:
    source_files = [
        Path(__file__),
        Path(__file__).with_name("sqlite_syscall_probe_child.py"),
        Path(__file__).with_name("sqlite_syscall_probe_supervision.py"),
        Path(__file__).with_name("sqlite_syscall_trace_diagnostics.py"),
    ]
    report: dict[str, Any] = {
        "schema": "guard.sqlite-syscall-feasibility.v1",
        "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files},
        "python_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        "installed_workload": False,
        "rsp131_qualified": False,
        "physical_device_bytes_measured": False,
        "sqlite_file_lifetime_attribution_complete": False,
        "observer_overhead_quantified": False,
        "raw_trace_exported": False,
    }
    strace = shutil.which("strace")
    if sys.platform != "linux" or strace is None:
        return {**report, "status": "unavailable", "reason": "linux_strace_required"}
    report["strace_sha256"] = hashlib.sha256(Path(strace).read_bytes()).hexdigest()
    base = Path(tempfile.mkdtemp(prefix="rsp131-probe-"))
    safe_to_remove = False
    try:
        plain, observed = base / "plain", base / "observed"
        plain.mkdir(mode=0o700)
        observed.mkdir(mode=0o700)
        baseline, baseline_stderr = _run_child(plain, None)
        baseline["control_checks"] = _child_control_checks(baseline)
        report["baseline_controls_passed"] = all(baseline["control_checks"].values())
        if not baseline["contained"] or not baseline.get("reader_resources_retired"):
            _redact_descriptors(baseline)
            report.update(
                status="ambiguous", reason="baseline_containment_or_reader_retirement_unproved", baseline=baseline
            )
            return report
        measured, trace = _run_child(observed, strace)
        measured["control_checks"] = _child_control_checks(measured)
        safe_to_remove = (
            baseline["contained"]
            and measured["contained"]
            and baseline["reader_resources_retired"]
            and measured["reader_resources_retired"]
        )
        report["baseline"] = baseline
        report["observed"] = measured
        denied = any(
            b"strace:" in line
            and b"ptrace" in line.lower()
            and (b"Operation not permitted" in line or b"Permission denied" in line)
            for line in trace.splitlines()
        )
        if denied:
            report.update(status="denied", reason="tracing_permission_denied")
        elif not isinstance(baseline["child"], dict) or not isinstance(measured["child"], dict):
            report.update(status="ambiguous", reason="child_report_unavailable")
        elif "identity" not in measured["child"] or "identity" not in baseline["child"]:
            report.update(status="ambiguous", reason="child_control_failed")
        else:
            actual = measured["child"]
            identity = actual["identity"]
            syntax = SyntaxDiagnostics()
            calls, parsed = parse_calls(trace, identity["pid"], syntax)
            report["trace_syntax_diagnostic"] = syntax.summary()
            serial = descriptor_witness(calls, observed, actual)
            sqlite_keys = (
                "sqlite_version",
                "sqlite_source_id",
                "compile_options_sha256",
                "journal_mode",
                "rows",
                "row_digest",
                "checkpoint",
                "readonly_error",
                "worker_failures",
            )
            checks = {
                "same_direct_child_pid": identity["pid"] == measured["launch_pid"],
                "same_start_identity": identity["start_ticks"] == measured["launch_start_ticks"],
                "same_direct_parent": identity["parent_pid"] == measured["caller_pid"],
                "same_owned_process_group": identity["process_group"] == measured["launch_pid"],
                "all_children_contained": baseline["contained"] and measured["contained"],
                "bounded_complete_streams": baseline["streams_complete"] and measured["streams_complete"],
                "successful_children": baseline["returncode"] == measured["returncode"] == 0,
                "complete_trace_syntax": parsed,
                "raw_data_buffers_suppressed": PRIVATE_MARKER not in trace
                and PRIVATE_MARKER not in baseline_stderr
                and raw_write_arguments_only(calls),
                "complete_synthetic_control_checks": report["baseline_controls_passed"]
                and all(measured["control_checks"].values()),
                "sqlite_results_unchanged": all(
                    actual["sqlite"][k] == baseline["child"]["sqlite"][k] for k in sqlite_keys
                ),
                "actual_sqlite_controls_passed": actual["sqlite"]["rows"] == 7
                and actual["sqlite"]["readonly_error"] == 8
                and not actual["sqlite"]["worker_failures"],
                "serial_fd_controls_passed": serial["passed"],
            }
            report.update(
                status="feasible" if all(checks.values()) else "ambiguous", checks=checks, descriptor_witness=serial
            )
        _redact_descriptors(baseline)
        _redact_descriptors(measured)
        encoded = json.dumps(report, sort_keys=True).encode()
        if PRIVATE_MARKER in encoded or str(base).encode() in encoded:
            raise RuntimeError("private observation escaped normalized report")
    finally:
        report["owned_scratch_retained"] = not safe_to_remove
        if safe_to_remove:
            shutil.rmtree(base)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = run_probe()
    descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "rsp131_qualified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
