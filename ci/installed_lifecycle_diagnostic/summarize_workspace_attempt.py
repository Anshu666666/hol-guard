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
        projected.append(
            {
                "registered_workspaces": count,
                "passed": flag(cell.get("passed")),
                "fixture_contained": flag(cell.get("fixture_contained")),
                "failure_present": cell.get("failure") is not None,
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
    }


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        require(name not in result)
        result[name] = value
    return result


def read_receipt(path: Path, projector: Any) -> dict[str, Any]:
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
        value = mapping(json.loads(data, object_pairs_hook=strict_object))
        record.update(state="projected", facts=projector(value))
    except (OSError, ValueError, TypeError, RecursionError):
        record["state"] = "unavailable_or_invalid"
    return record


def summary(directory: Path) -> dict[str, Any]:
    return {
        "schema": "workspace-ownership-log-summary.v1",
        "qualification_claimed": False,
        "original_acceptance_unchanged": True,
        "witness": read_receipt(directory / "receipt.json", main_receipt),
        "worker": read_receipt(directory / "worker-receipt.json", worker_receipt),
        "collector": read_receipt(directory / "collector-report.json", collector_receipt),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempt-directory", type=Path, required=True)
    args = parser.parse_args()
    result = summary(args.attempt_directory)
    content = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if len(content.encode("ascii")) > MAX_LOG_BYTES:
        print('{"schema":"workspace-ownership-log-summary.v1","state":"summary_bound_exceeded"}')
        return 1
    print(content)
    return int(any(result[name]["state"] != "projected" for name in ("witness", "worker", "collector")))


if __name__ == "__main__":
    raise SystemExit(main())
