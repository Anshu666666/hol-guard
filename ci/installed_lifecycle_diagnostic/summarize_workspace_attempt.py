"""Print bounded allowlisted facts from a completed workspace witness.

This reader imports no Guard code, starts no processes, and changes no witness
acceptance condition. Original receipt bytes remain untouched. Missing or
malformed evidence is printed as a fixed diagnostic state, never as a traceback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

PHASES = ("initial", "unchanged", "stricter_overlay", "coalesced_burst", "public_policy", "resident_restart")
OWNER_FLAGS = (
    "verified",
    "initial_children_empty",
    "enabled_before_spawn",
    "worker_exit_observed",
    "descendants_exhausted",
    "timed_out",
    "limit_exceeded",
    "containment_failed",
)
KNOWN_FAILURES = frozenset(
    {
        "observational_ownership_not_verified",
        "worker_receipt_missing",
        "collector_attempt_failed",
        "installed_members_changed",
        "witness_sources_changed",
        "collector_installed_identity",
        "installed_members_changed_during_worker",
        "copied_helper_changed",
        "production_import_escaped_installed_package",
    }
)
EXCEPTIONS = frozenset(
    {
        "AssertionError",
        "ChildProcessError",
        "FileNotFoundError",
        "KeyError",
        "OSError",
        "PermissionError",
        "ProcessLookupError",
        "RuntimeError",
        "TimeoutError",
        "TypeError",
        "ValueError",
    }
)
ERROR_CATEGORIES = EXCEPTIONS | {
    "AttributeError",
    "BlockingIOError",
    "BrokenPipeError",
    "ConnectionError",
    "ConnectionAbortedError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "FileExistsError",
    "ImportError",
    "InterruptedError",
    "IsADirectoryError",
    "ModuleNotFoundError",
    "NotADirectoryError",
    "NotImplementedError",
    "JSONDecodeError",
    "GuardConfigSourceError",
    "CodexHookIntegrityError",
    "Failure",
    "AccessDenied",
    "NoSuchProcess",
    "ZombieProcess",
}
# These are identifiers in the pinned source, never arbitrary receipt strings.
ERROR_ORIGINS = frozenset(
    f"{module}.{routine}"
    for module, routines in {
        "native_slo_workspace": ("_cell", "_control"),
        "native_slo_daemon_fixture": (
            "__init__",
            "__enter__",
            "_receive",
            "control",
            "_serve",
            "_serve_session",
            "close",
        ),
        "native_slo_resources": ("_psutil", "__init__", "__enter__", "_sample", "_inventory"),
        "native_slo_session": ("__init__", "__enter__", "start", "close", "_request"),
        "native_slo_workspace_server": (
            "__init__",
            "dispatch",
            "startup_failure",
            "phase",
            "_ack",
            "_chain",
            "_probe",
            "_overlay",
        ),
        "native_slo_mixed_witness": ("__init__", "__enter__"),
        "native_slo_mixed_receipt_reader": ("__init__",),
        "native_slo_qualification_scenarios": ("validate_receipt_profile",),
        "native_slo_workspace_trace": ("startup_rows", "validate_trace"),
        "config_source_io": (
            "capture_guard_config",
            "_posix_parent_chain",
            "_capture_in_parent",
            "_validate_file",
            "_directory_identity",
            "_read_descriptor",
            "_verify_missing_parent",
        ),
        "server": ("__init__", "start", "_begin_owned_service", "_complete_owned_service_after_listen"),
        "socket": ("getfqdn",),
        "http.server": ("HTTPServer.server_bind",),
        "socketserver": ("TCPServer.server_bind", "TCPServer.server_activate"),
    }.items()
    for routine in routines
)
STARTUP_STAGES = (
    "spawn",
    "construct",
    "construct_workspace",
    "construct_store",
    "construct_daemon",
    "register_workspace",
    "start",
    "fault",
    "serve",
    "cleanup",
)
ERROR_MESSAGES = {
    ("RuntimeError", "workspace installed witness setup failed"): "workspace_start_failed",
    (
        "RuntimeError",
        "workspace qualification requires exact installed native authority",
    ): "workspace_native_authority_rejected",
    ("RuntimeError", "workspace observer must precede publisher startup"): "workspace_publisher_already_started",
    ("RuntimeError", "workspace initial compilation cache must be empty"): "workspace_initial_cache_not_empty",
    ("RuntimeError", "workspace registration was not accepted"): "workspace_registration_rejected",
    ("RuntimeError", "workspace registration count mismatch"): "workspace_registration_mismatch",
    (
        "RuntimeError",
        "qualification resources require the pinned psutil development dependency",
    ): "psutil_dependency_unavailable",
    ("RuntimeError", "candidate binding-aware receipt getter unavailable"): "receipt_getter_unavailable",
    ("RuntimeError", "native_installed_slo_failed: native policy was not ready"): "native_policy_not_ready",
    (
        "RuntimeError",
        "native_installed_slo_failed: native readiness exceeded budget",
    ): "native_readiness_budget_exceeded",
    **{
        ("RuntimeError", message): message.replace(" ", "_")
        for message in (
            "workspace phase starting authority unavailable",
            "workspace resident containment failed",
            "workspace unnotified reconciliation deadline",
            "workspace authenticated acknowledgment deadline",
            "workspace observed publication chain deadline",
            "workspace observed compilation count invalid",
            "adapter request failed",
            "adapter response exceeded bound",
            "adapter response was not JSON",
        )
    },
    (
        "RuntimeError",
        "native_installed_slo_failed: adapter response was not an object",
    ): "adapter_response_not_object",
    **{
        ("RuntimeError", message): message.replace(" ", "_")
        for message in (
            "daemon fixture did not acknowledge readiness",
            "daemon fixture process containment failed",
            "daemon fixture cleanup was not acknowledged",
            "daemon fixture operation failed",
            "daemon fixture invalid progress stage",
            "daemon fixture invalid startup evidence",
            "daemon fixture invalid failure evidence",
            "daemon fixture unavailable",
        )
    },
    **{
        ("RuntimeError", f"daemon fixture {condition} at {stage}"): f"daemon_{condition.replace(' ', '_')}_{stage}"
        for condition in ("deadline", "stream unavailable")
        for stage in STARTUP_STAGES
    },
    **{
        ("Failure", code): code
        for code in (
            "unexpected_disposable_home",
            "private_directory_identity",
            "registration_after_publisher_start",
            "preexisting_compact_socket_directory",
            "private_registry_write",
        )
    },
    **{
        ("GuardConfigSourceError", code): code
        for code in (
            "guard_config_parent_not_directory",
            "guard_config_not_regular",
            "guard_config_link_count",
            "guard_config_too_large",
            "guard_config_descriptor_io_unavailable",
            "guard_config_parent_changed",
            "guard_config_changed",
            "guard_config_name_invalid",
            "guard_config_scope_changed",
            "guard_config_scope_rejected",
            "guard_config_source_unavailable",
        )
    },
}
ERROR_DIGEST_CODES = {
    (category, hashlib.sha256(message.encode()).hexdigest()): code
    for (category, message), code in ERROR_MESSAGES.items()
}
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 32768


class ProjectionError(ValueError):
    """An invalid selected field, with no receipt content in the exception."""


def require(condition: bool) -> None:
    if not condition:
        raise ProjectionError()


def mapping(value: Any) -> dict[str, Any]:
    require(type(value) is dict)
    return value


def flag(value: Any) -> bool | None:
    require(value is None or type(value) is bool)
    return value


def integer(value: Any, low: int = 0, high: int = 1048576) -> int | None:
    require(value is None or (type(value) is int and low <= value <= high))
    return value


def status(value: Any) -> str | None:
    require(value is None or value in ("passed", "failed"))
    return value


def sha(value: Any) -> str | None:
    require(value is None or (type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None))
    return value


def failure_counts(value: Any) -> dict[str, Any]:
    require(type(value) is list and len(value) <= 64)
    require(all(type(item) is str for item in value))
    return {
        "count": len(value),
        "known_codes": [item for item in value if item in KNOWN_FAILURES],
        "other_count": sum(item not in KNOWN_FAILURES for item in value),
    }


def exception_kind(value: Any) -> str | None:
    if value is None:
        return None
    return value if type(value) is str and value in EXCEPTIONS else "other_exception"


def error_location(value: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    origin = value.get(prefix + "origin")
    return {
        "origin": origin if type(origin) is str and origin in ERROR_ORIGINS else None,
        "line": integer(value.get(prefix + "line"), 1, 1048576),
        "errno": integer(value.get(prefix + "errno"), 0, 4095),
    }


def error_detail(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    detail = mapping(value)
    if detail.get("schema") != "hol-guard.native-qualification-failure.v1":
        return {"state": "unavailable"}
    category = detail.get("category")
    category = category if type(category) is str and category in ERROR_CATEGORIES else None
    digest = sha(detail.get("diagnostic_digest"))
    stack = detail.get("startup_stack", [])
    require(type(stack) is list and len(stack) <= 8)
    causes = []
    count = integer(detail.get("config_cause_count"), 0, 3)
    for index in range(1, (count or 0) + 1):
        prefix = f"config_cause_{index}_"
        cause = detail.get(prefix + "category")
        causes.append(
            {
                "category": cause if type(cause) is str and cause in ERROR_CATEGORIES else None,
                **error_location(detail, prefix),
                "winerror": integer(detail.get(prefix + "winerror"), 0, 0xFFFFFFFF),
            }
        )
    return {
        "state": "projected",
        "category": category,
        "known_message_code": ERROR_DIGEST_CODES.get((category, digest)),
        **error_location(detail),
        "startup_stack": [error_location(mapping(row)) for row in stack],
        "config_diagnostic_available": flag(detail.get("config_diagnostic_available")),
        "config_causes": causes,
        **{
            name: flag(detail.get(name))
            for name in ("config_cause_cycle", "config_cause_truncated", "config_cause_unavailable")
        },
        "workspace_observation_present": detail.get("workspace_observation") is not None,
    }


def cell_failure(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    detail = mapping(value)
    return {
        "primary": error_detail(detail.get("primary", detail)),
        "trace_failure": error_detail(detail.get("trace_failure")),
        "startup_trace_retained": flag(detail.get("startup_trace_retained")),
    }


def timing_recorded(cell: dict[str, Any], name: str) -> bool:
    if name not in cell:
        return False
    value = cell[name]
    require(type(value) in (int, float) and 0 <= value <= 86400000)
    return True


def main_receipt(value: dict[str, Any]) -> dict[str, Any]:
    require(value.get("schema") == "installed-workspace-publication-witness.v1")
    worker_failures = value.get("worker_failures")
    owner = mapping(value.get("owned_descendant_boundary", {}))
    streams = mapping(value.get("bounded_streams", {}))
    cleanup = mapping(value.get("cleanup", {}))
    projected_owner: dict[str, Any] = {name: flag(owner.get(name)) for name in OWNER_FLAGS}
    for name in ("termination_signals_sent", "adopted_signalled_exits", "reaped_process_count"):
        projected_owner[name] = integer(owner.get(name))
    projected_owner["worker_return_code"] = integer(owner.get("worker_return_code"), -64, 255)
    projected_owner["exit_statuses_sha256"] = sha(owner.get("exit_statuses_sha256"))
    for name in ("observation_failure", "cleanup_failure"):
        projected_owner[name] = exception_kind(owner.get(name))
    return {
        "result": status(value.get("result")),
        "failures": failure_counts(value.get("failures", [])),
        "worker_returncode": integer(value.get("worker_returncode"), -64, 255),
        "worker_result": status(value.get("worker_result")),
        "worker_failures": None if worker_failures is None else failure_counts(worker_failures),
        "ownership": projected_owner,
        "streams": {name: integer(streams.get(name), 0, 256 * 1024) for name in ("stdout_bytes", "stderr_bytes")},
        "stream_hashes": {name: sha(streams.get(name)) for name in ("stdout_sha256", "stderr_sha256")},
        "installed_members_unchanged": flag(value.get("installed_members_unchanged")),
        "harness_sources_unchanged": flag(value.get("harness_sources_unchanged")),
        "complete_receipt_bindings_passed": flag(value.get("complete_receipt_bindings_passed")),
        "implemented_checks_passed": flag(value.get("implemented_checks_passed")),
        "cleanup": {
            name: flag(cleanup.get(name))
            for name in ("owned_descendants_exhausted", "private_material_removed", "failure_material_retained")
        },
    }


def worker_receipt(value: dict[str, Any]) -> dict[str, Any]:
    require(value.get("schema") == "installed-workspace-worker.v1")
    return {
        "result": status(value.get("result")),
        "failures": failure_counts(value.get("failures", [])),
        "complete_receipt_bindings_passed": flag(value.get("complete_receipt_bindings_passed")),
        "implemented_checks_passed": flag(value.get("implemented_checks_passed")),
        "installed_members_unchanged": flag(value.get("installed_members_unchanged")),
    }


def collector_receipt(value: dict[str, Any]) -> dict[str, Any]:
    require(value.get("scope") == "installed_workspace_publication_diagnostic")
    cells = value.get("cells", [])
    require(type(cells) is list and len(cells) <= 3)
    projected = []
    seen = set()
    for cell_value in cells:
        cell = mapping(cell_value)
        count = cell.get("registered_workspaces")
        require(type(count) is int and count in (1, 10, 100) and count not in seen)
        seen.add(count)
        phases = cell.get("phases", [])
        require(type(phases) is list and len(phases) <= 6)
        phase_rows = []
        for index, phase_value in enumerate(phases):
            phase = mapping(phase_value)
            # Failed control replies may omit their phase label; the offered
            # ordinal still maps to the unchanged six-phase source contract.
            require(phase.get("phase") is None or phase["phase"] == PHASES[index])
            phase_rows.append(
                {
                    "offered_phase": PHASES[index],
                    "label_present": phase.get("phase") is not None,
                    "failure_present": phase.get("failure") is not None,
                    "failure": error_detail(phase.get("failure")),
                    **{
                        name: flag(phase.get(name))
                        for name in (
                            "passed",
                            "installed_runtime_matches",
                            "first_native_receipt_matches",
                            "authenticated_ack",
                            "cache_feature_checks_passed",
                        )
                    },
                }
            )
        unvisited = cell.get("unvisited_phases")
        require(type(unvisited) is list and len(unvisited) <= 6)
        offered = 6 - len(unvisited)
        require(unvisited == list(PHASES[offered:]) and len(phases) <= offered)
        final = mapping(cell.get("final", {}))
        observation = mapping(final.get("complete_receipt_identity_observation", {}))
        require("resources" not in cell or type(cell["resources"]) is dict)
        projected.append(
            {
                "registered_workspaces": count,
                "passed": flag(cell.get("passed")),
                "fixture_contained": flag(cell.get("fixture_contained")),
                "failure_present": cell.get("failure") is not None,
                "construction": {
                    "startup_time_recorded": timing_recorded(cell, "startup_ms"),
                    "readiness_time_recorded": timing_recorded(cell, "startup_readiness_ms"),
                    "resources_recorded": "resources" in cell,
                    "retained_startup_events": integer(cell.get("retained_startup_events"), 0, 256),
                    "failure": cell_failure(cell.get("failure")),
                },
                "phases": phase_rows,
                "offered_phases": offered,
                "unvisited_phases": unvisited,
                "final": {
                    **{
                        name: flag(final.get(name))
                        for name in (
                            "passed",
                            "receipt_bindings_validated",
                            "cache_feature_checks_passed",
                            "writer_drained",
                        )
                    },
                    **{
                        name: integer(final.get(name), 0, 6)
                        for name in (
                            "completed_phases",
                            "receipt_count",
                            "committed_receipts",
                        )
                    },
                    "complete_receipt_observation_passed": flag(observation.get("passed")),
                    "complete_receipt_count": integer(observation.get("receipt_count"), 0, 6),
                },
            }
        )
    return {
        **{
            name: flag(value.get(name))
            for name in (
                "declared_matrix_visited",
                "implemented_checks_passed",
                "authority_checks_passed",
            )
        },
        "cells": projected,
        "ledger_binding": {
            "records": integer(mapping(value.get("ledger", {})).get("records"), 0, 350000),
            "bytes": integer(mapping(value.get("ledger", {})).get("bytes"), 0, 256 * 1024 * 1024),
            "sha256": sha(mapping(value.get("ledger", {})).get("sha256")),
        },
    }


def publisher_ledger(rows: list[dict[str, Any]]) -> dict[str, Any]:
    require(bool(rows) and rows[0].get("kind") == "matrix_offer")
    counts = rows[0].get("counts")
    require(type(counts) is list and all(type(count) is int for count in counts) and counts == [1, 10, 100])
    cells: dict[int, dict[str, Any]] = {}
    active = None
    for row in rows[1:]:
        count = row.get("registered_workspaces")
        require(type(count) is int and count in (1, 10, 100))
        kind = row.get("kind")
        if kind == "cell_offer":
            require(count not in cells and active is None)
            active = count
            cells[count] = {
                "registered_workspaces": count,
                "cell_offer_present": True,
                "cell_terminal_present": False,
                "workspace_start_offer_present": False,
                "workspace_start_terminal_present": False,
                "workspace_start": None,
            }
            continue
        require(active == count and count in cells)
        cell = cells[count]
        if kind == "cell_terminal":
            cell["cell_terminal_present"] = True
            active = None
        elif kind in ("control_offer", "control_terminal"):
            operation = row.get("operation")
            require(operation in ("workspace_start", "workspace_phase", "workspace_finish", "workspace_page"))
            if operation != "workspace_start":
                continue
            if kind == "control_offer":
                require(not cell["workspace_start_offer_present"])
                cell["workspace_start_offer_present"] = True
            else:
                require(cell["workspace_start_offer_present"] and not cell["workspace_start_terminal_present"])
                cell["workspace_start_terminal_present"] = True
                result = mapping(row.get("result"))
                require(result.get("status") in ("completed", "failed"))
                cell["workspace_start"] = {
                    "status": result["status"],
                    "passed": flag(result.get("passed")),
                    "failure": error_detail(result.get("failure")),
                }
        else:
            require(kind in ("publisher_event", "phase_identity"))
    return {"records": len(rows), "cells": list(cells.values())}


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        require(name not in result)
        result[name] = value
    return result


def read_receipt(path: Path, projector: Any, *, json_lines: bool = False) -> dict[str, Any]:
    record: dict[str, Any] = {"state": "unavailable"}
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_FILE_BYTES)
            data = handle.read(MAX_FILE_BYTES + 1)
            after = os.fstat(handle.fileno())
        record.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            not stat.S_ISREG(after.st_mode)
            or any(getattr(info, field) != getattr(after, field) for field in identity_fields)
            or len(data) != info.st_size
        ):
            record["state"] = "changed_during_read"
            return record
        if json_lines:
            lines = data.splitlines(keepends=True)
            require(0 < len(lines) <= 4096 and data.endswith(b"\n") and all(len(line) <= 8192 for line in lines))
            value: Any = [mapping(json.loads(line, object_pairs_hook=strict_object)) for line in lines]
        else:
            value = mapping(json.loads(data, object_pairs_hook=strict_object))
        record.update(state="projected", facts=projector(value))
    except (OSError, ValueError, TypeError, RecursionError):
        record["state"] = "unavailable_or_invalid"
    return record


def summary(directory: Path) -> dict[str, Any]:
    collector = read_receipt(directory / "collector-report.json", collector_receipt)
    ledger = read_receipt(directory / "publisher-ledger.jsonl", publisher_ledger, json_lines=True)
    if ledger["state"] == "projected":
        binding = collector.get("facts", {}).get("ledger_binding", {})
        if binding != {"records": ledger["facts"]["records"], "bytes": ledger["bytes"], "sha256": ledger["sha256"]}:
            ledger.pop("facts")
            ledger["state"] = "collector_binding_unavailable_or_mismatched"
    return {
        "schema": "workspace-ownership-log-summary.v2",
        "qualification_claimed": False,
        "original_acceptance_unchanged": True,
        "witness": read_receipt(directory / "receipt.json", main_receipt),
        "worker": read_receipt(directory / "worker-receipt.json", worker_receipt),
        "collector": collector,
        "publisher_ledger": ledger,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempt-directory", type=Path, required=True)
    args = parser.parse_args()
    result = summary(args.attempt_directory)
    content = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if len(content.encode("ascii")) > MAX_LOG_BYTES:
        print('{"schema":"workspace-ownership-log-summary.v2","state":"summary_bound_exceeded"}')
        return 1
    print(content)
    return int(
        any(result[name]["state"] != "projected" for name in ("witness", "worker", "collector", "publisher_ledger"))
    )


if __name__ == "__main__":
    raise SystemExit(main())
