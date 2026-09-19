"""Admit only the complete, source-bound twelve-call inode feasibility control."""

from __future__ import annotations

import errno
import json
from typing import Any

MAX_BYTES = 256 * 1024
MAX_RECORDS = 64
ARCH = 0xC000003E
OPTIONS = 0x1000DF
NUMBERS = {"write": 1, "dup": 32, "fsync": 74, "close": 3, "dup2": 33, "pwrite64": 18, "fdatasync": 75}
LIMITS = {
    "installed_workload": False,
    "rsp131_qualified": False,
    "sqlite_ingestion_observed": False,
    "physical_device_bytes_measured": False,
}
TERMINAL_KEYS = {
    "sequence", "kind", "feasible", "failure", "failure_errno", "child_reaped", "child_exit_code",
    "child_signal", "calls", "exit_event", "output_lost", "owned_files_removed", "fixed_control_readback_matches", *LIMITS,
}
ENTRY_KEYS = {
    "sequence", "kind", "call_id", "pid", "call", "number", "fd", "target_fd", "role",
    "dev", "ino", "requested", "offset", "duplicate_closed_before_resume",
}
EXIT_KEYS = {"sequence", "kind", "call_id", "pid", "call", "result", "error", "result_descriptor_bound"}


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _integer(value: Any, lower: int = 0, upper: int = 2**63 - 1) -> bool:
    return type(value) is int and lower <= value <= upper


def decode(data: bytes) -> list[dict[str, Any]]:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_BYTES or not data.endswith(b"\n"):
        raise ValueError("capture_size_or_partial_line")
    lines = data.splitlines()
    if not 1 <= len(lines) <= MAX_RECORDS or any(not line or len(line) > 1664 for line in lines):
        raise ValueError("record_count_or_size")
    records: list[dict[str, Any]] = []
    for sequence, line in enumerate(lines, 1):
        row = json.loads(line.decode("ascii"), object_pairs_hook=_object)
        if (
            not isinstance(row, dict) or not isinstance(row.get("kind"), str)
            or type(row.get("sequence")) is not int or row["sequence"] != sequence
        ):
            raise ValueError("record_shape_or_sequence")
        records.append(row)
    return records


def _terminal(row: dict[str, Any]) -> None:
    if (
        set(row) != TERMINAL_KEYS or row["kind"] != "terminal"
        or any(row[key] is not False for key in LIMITS)
        or any(type(row[key]) is not bool for key in (
            "feasible", "child_reaped", "exit_event", "output_lost", "owned_files_removed", "fixed_control_readback_matches",
        ))
        or not isinstance(row["failure"], str) or not 1 <= len(row["failure"]) <= 80
        or any(char not in "abcdefghijklmnopqrstuvwxyz_" for char in row["failure"])
        or not _integer(row["failure_errno"], 0, 4095)
        or not _integer(row["child_exit_code"], -1, 255) or not _integer(row["child_signal"], 0, 64)
        or not _integer(row["calls"], 0, 12)
    ):
        raise ValueError("terminal_contract")


def _specifications(fd_a: int, fd_b: int, alias: int) -> list[tuple[str, int, int, int, int, int]]:
    return [
        ("write", fd_a, -1, 1, 9, 0), ("dup", fd_a, -1, 1, 0, 0),
        ("fsync", alias, -1, 1, 0, 0), ("close", fd_a, -1, 1, 0, 0),
        ("dup2", fd_b, fd_a, 2, 0, 0), ("pwrite64", fd_a, -1, 2, 11, 7),
        ("fdatasync", fd_a, -1, 2, 0, 0), ("close", fd_a, -1, 2, 0, 0),
        ("fsync", fd_a, -1, 0, 0, 0), ("write", alias, -1, 1, 5, 0),
        ("close", alias, -1, 1, 0, 0), ("close", fd_b, -1, 2, 0, 0),
    ]


def validate(
    data: bytes, *, collector_pid: int, returncode: int | None,
    capture_complete: bool, owned_group_retired: bool,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.rsp131-owned-inode-feasibility.v1",
        "valid": False, "feasible": False, "status": "refused", **LIMITS,
        "observed_syscall_return_bytes": None, "successful_fsync_calls": None,
        "successful_fdatasync_calls": None, "failed_sync_calls": None,
        "process_tree_qualification": False, "observer_overhead_quantified": False,
        "physical_rewrite_bytes": None, "sqlite_vfs_metrics": None,
    }
    try:
        records = decode(data)
        report["records"] = records
        terminal = records[-1]
        _terminal(terminal)
        report["terminal"] = terminal
        if not terminal["feasible"]:
            report["status"] = "observed_refusal"
            report["reason"] = terminal["failure"]
            # A retained refusal carries no successful or complete-trace credit.
            return report
        if (
            type(returncode) is not int or returncode != 0
            or capture_complete is not True or owned_group_retired is not True
            or terminal["failure"] != "none" or terminal["failure_errno"] != 0
            or terminal["child_exit_code"] != 0 or terminal["child_signal"] != 0
            or terminal["calls"] != 12 or terminal["output_lost"]
            or any(terminal[key] is not True for key in ("child_reaped", "exit_event", "owned_files_removed", "fixed_control_readback_matches"))
        ):
            raise ValueError("incomplete_capture_or_retirement")
        begin = records[0]
        if set(begin) != {
            "sequence", "kind", "schema", "pid", "parent_pid", "fd_a", "fd_b",
            "a_dev", "a_ino", "b_dev", "b_ino", "single_thread_control",
        } or begin["kind"] != "begin" or type(begin["schema"]) is not int or begin["schema"] != 1:
            raise ValueError("begin_contract")
        if (
            not _integer(collector_pid, 1, 2**31 - 1) or begin["parent_pid"] != collector_pid
            or not _integer(begin["parent_pid"], 1, 2**31 - 1)
            or not _integer(begin["pid"], 1, 2**31 - 1) or begin["pid"] == collector_pid
            or begin["single_thread_control"] is not True
            or not _integer(begin["fd_a"], 3, 1024) or not _integer(begin["fd_b"], 3, 1024)
            or begin["fd_a"] == begin["fd_b"]
            or any(not _integer(begin[key], 1, 2**64 - 1) for key in ("a_dev", "a_ino", "b_dev", "b_ino"))
        ):
            raise ValueError("process_or_initial_identity")
        identities = {0: (0, 0), 1: (begin["a_dev"], begin["a_ino"]), 2: (begin["b_dev"], begin["b_ino"])}
        if identities[1] == identities[2]:
            raise ValueError("fixture_inode_collision")
        admitted = records[1]
        if admitted != {
            "sequence": 2, "kind": "admitted", "options": OPTIONS, "arch": ARCH,
            "both_initial_descriptors_bound": True, "duplicate_closed_before_resume": True,
        } or any(type(admitted[key]) is not int for key in ("options", "arch")) or any(
            admitted[key] is not True for key in ("both_initial_descriptors_bound", "duplicate_closed_before_resume")
        ):
            raise ValueError("kernel_admission")
        position = 2
        if records[position]["kind"] == "bootstrap_exit":
            if records[position] != {"sequence": position + 1, "kind": "bootstrap_exit", "result": 0, "error": 0}:
                raise ValueError("bootstrap_exit")
            if type(records[position]["result"]) is not int or type(records[position]["error"]) is not int:
                raise ValueError("bootstrap_type")
            position += 1
        fd_a, fd_b, alias, pid = begin["fd_a"], begin["fd_b"], -1, begin["pid"]
        live = {fd_a: 1, fd_b: 2}
        accepted = {1: 0, 2: 0}
        syncs = {"fsync": 0, "fdatasync": 0, "failed": 0}
        for call_id in range(1, 13):
            entry, returned = records[position : position + 2]
            position += 2
            call, fd, target, role, requested, offset = _specifications(fd_a, fd_b, alias)[call_id - 1]
            if set(entry) != ENTRY_KEYS or set(returned) != EXIT_KEYS:
                raise ValueError("call_shape")
            integer_fields = ("call_id", "pid", "number", "fd", "target_fd", "role", "dev", "ino", "requested", "offset")
            if any(type(entry[key]) is not int for key in integer_fields):
                raise ValueError("entry_integer")
            if any(type(returned[key]) is not int for key in ("call_id", "pid", "result", "error")):
                raise ValueError("exit_integer")
            if (
                entry["kind"] != "entry" or returned["kind"] != "exit"
                or any(row["call_id"] != call_id or row["pid"] != pid or row["call"] != call for row in (entry, returned))
                or entry["number"] != NUMBERS[call]
                or (entry["fd"], entry["target_fd"], entry["role"], entry["requested"], entry["offset"])
                != (fd, target, role, requested, offset)
                or (entry["dev"], entry["ino"]) != identities[role]
                or entry["duplicate_closed_before_resume"] is not True
                or live.get(fd, 0) != role
            ):
                raise ValueError("event_identity_or_pairing")
            result, error = returned["result"], returned["error"]
            expected_result = -errno.EBADF if role == 0 else target if call == "dup2" else requested
            if call == "dup":
                if not _integer(result, 3, 1024) or result in live or error:
                    raise ValueError("dup_lifetime")
                alias = result
                live[alias] = role
            elif result != expected_result or error != (errno.EBADF if role == 0 else 0):
                raise ValueError("control_result")
            if returned["result_descriptor_bound"] is not (call in {"dup", "dup2"}):
                raise ValueError("returned_descriptor_identity")
            if call == "dup2":
                if target in live:
                    raise ValueError("unexpected_target_lifetime")
                live[target] = role
            elif call == "close":
                del live[fd]
            elif call in {"write", "pwrite64"}:
                accepted[role] += result
            elif call in {"fsync", "fdatasync"}:
                syncs["failed" if error else call] += 1
        if live or len(records) != position + 3:
            raise ValueError("incomplete_fd_lifetimes_or_extra_events")
        if records[position] != {"sequence": position + 1, "kind": "exit_group_entry", "pid": pid, "code": 0}:
            raise ValueError("exit_entry")
        if records[position + 1] != {"sequence": position + 2, "kind": "exit_event", "pid": pid, "status": 0}:
            raise ValueError("exit_event")
        for row, key in ((records[position], "code"), (records[position + 1], "status")):
            if type(row[key]) is not int or type(row["pid"]) is not int:
                raise ValueError("exit_type")
        report.update(
            valid=True, feasible=True, status="finite_owned_child_feasible",
            observed_syscall_return_bytes={"owned_a": accepted[1], "owned_b": accepted[2]},
            successful_fsync_calls=syncs["fsync"], successful_fdatasync_calls=syncs["fdatasync"],
            failed_sync_calls=syncs["failed"], observed_call_pairs=12,
            inode_bound_temporary_duplicates_closed=True,
        )
    except (ValueError, UnicodeError, TypeError, KeyError, IndexError, RecursionError) as error:
        report["reason"] = str(error) if isinstance(error, ValueError) and len(str(error)) <= 80 else type(error).__name__
    return report
