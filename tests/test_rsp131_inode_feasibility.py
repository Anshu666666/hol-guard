"""Finite malformed-event controls; these fixtures provide no kernel evidence."""

from __future__ import annotations

import copy
import errno
import json

import pytest

from scripts.ci.rsp131_inode_probe.evidence import validate


def records(*, bootstrap: bool = True) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = [
        {
            "kind": "begin", "schema": 1, "pid": 4322, "parent_pid": 4321,
            "fd_a": 4, "fd_b": 5, "a_dev": 2049, "a_ino": 100,
            "b_dev": 2049, "b_ino": 101, "single_thread_control": True,
        },
        {
            "kind": "admitted", "options": 0x1000DF, "arch": 0xC000003E,
            "both_initial_descriptors_bound": True, "duplicate_closed_before_resume": True,
        },
    ]
    if bootstrap:
        rows.append({"kind": "bootstrap_exit", "result": 0, "error": 0})
    # Independent fixed control transcript: fd4 becomes B while alias3 remains A.
    operations = [
        ("write", 1, 4, -1, 1, 9, 0, 9, 0),
        ("dup", 32, 4, -1, 1, 0, 0, 3, 0),
        ("fsync", 74, 3, -1, 1, 0, 0, 0, 0),
        ("close", 3, 4, -1, 1, 0, 0, 0, 0),
        ("dup2", 33, 5, 4, 2, 0, 0, 4, 0),
        ("pwrite64", 18, 4, -1, 2, 11, 7, 11, 0),
        ("fdatasync", 75, 4, -1, 2, 0, 0, 0, 0),
        ("close", 3, 4, -1, 2, 0, 0, 0, 0),
        ("fsync", 74, 4, -1, 0, 0, 0, -errno.EBADF, errno.EBADF),
        ("write", 1, 3, -1, 1, 5, 0, 5, 0),
        ("close", 3, 3, -1, 1, 0, 0, 0, 0),
        ("close", 3, 5, -1, 2, 0, 0, 0, 0),
    ]
    for call_id, (call, number, fd, target, role, count, offset, result, error) in enumerate(operations, 1):
        rows.append({
            "kind": "entry", "call_id": call_id, "pid": 4322, "call": call,
            "number": number, "fd": fd, "target_fd": target, "role": role,
            "dev": 2049 if role else 0, "ino": {0: 0, 1: 100, 2: 101}[role],
            "requested": count, "offset": offset, "duplicate_closed_before_resume": True,
        })
        rows.append({
            "kind": "exit", "call_id": call_id, "pid": 4322, "call": call,
            "result": result, "error": error, "result_descriptor_bound": call in {"dup", "dup2"},
        })
    rows.extend([
        {"kind": "exit_group_entry", "pid": 4322, "code": 0},
        {"kind": "exit_event", "pid": 4322, "status": 0},
        {
            "kind": "terminal", "feasible": True, "failure": "none", "failure_errno": 0,
            "child_reaped": True, "child_exit_code": 0, "child_signal": 0, "calls": 12,
            "exit_event": True, "output_lost": False, "owned_files_removed": True, "fixed_control_readback_matches": True,
            "installed_workload": False, "rsp131_qualified": False,
            "sqlite_ingestion_observed": False, "physical_device_bytes_measured": False,
        },
    ])
    return resequence(rows)


def resequence(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    for index, row in enumerate(rows, 1):
        row["sequence"] = index
    return rows


def encoded(rows: list[dict[str, object]]) -> bytes:
    return b"".join(json.dumps(row, sort_keys=True).encode("ascii") + b"\n" for row in rows)


def admit(data: bytes, **changes: object) -> dict[str, object]:
    arguments: dict[str, object] = {
        "collector_pid": 4321, "returncode": 0, "capture_complete": True, "owned_group_retired": True,
    }
    arguments.update(changes)
    return validate(data, **arguments)  # type: ignore[arg-type]


def assert_refused(report: dict[str, object]) -> None:
    assert report["valid"] is False
    assert report["feasible"] is False
    assert report["rsp131_qualified"] is False
    assert report["installed_workload"] is False
    assert report["observed_syscall_return_bytes"] is None
    assert report["successful_fsync_calls"] is None
    assert report["successful_fdatasync_calls"] is None
    assert report["sqlite_vfs_metrics"] is None
    assert report["physical_rewrite_bytes"] is None


@pytest.mark.parametrize("bootstrap", [False, True])
def test_complete_finite_transcript_is_narrowly_admitted(bootstrap: bool) -> None:
    report = admit(encoded(records(bootstrap=bootstrap)))
    assert report["valid"] is True
    assert report["feasible"] is True
    assert report["observed_syscall_return_bytes"] == {"owned_a": 14, "owned_b": 11}
    assert report["successful_fsync_calls"] == 1
    assert report["successful_fdatasync_calls"] == 1
    assert report["failed_sync_calls"] == 1
    assert report["installed_workload"] is False
    assert report["rsp131_qualified"] is False
    assert report["sqlite_ingestion_observed"] is False
    assert report["physical_device_bytes_measured"] is False
    assert report["observer_overhead_quantified"] is False


@pytest.mark.parametrize(("index", "field", "value"), [
    (0, "parent_pid", 999), (0, "pid", True), (0, "single_thread_control", 1),
    (0, "fd_b", 4), (0, "b_ino", 100), (0, "a_ino", 0),
    (1, "options", 1), (1, "arch", 0x40000003), (1, "both_initial_descriptors_bound", 1),
    (1, "duplicate_closed_before_resume", False),
    (2, "result", False), (2, "error", errno.EINTR),
    (3, "pid", 4323), (3, "number", 2), (3, "requested", 10),
    (3, "duplicate_closed_before_resume", False), (3, "dev", 999),
    (3, "ino", 101), (3, "fd", True), (3, "role", 2),
    (4, "result", 8), (4, "result", -errno.EIO), (4, "error", errno.EIO),
    (6, "result", 4), (6, "result_descriptor_bound", False),
    (11, "target_fd", 5), (12, "result", 5), (13, "ino", 100), (13, "offset", 8),
    (19, "role", 1), (20, "error", errno.EPERM), (20, "result", 0),
    (21, "ino", 101), (21, "fd", 4),
    (-3, "code", True), (-2, "status", 1), (-2, "pid", 4323),
    (-1, "calls", 11), (-1, "child_reaped", False), (-1, "child_exit_code", 70),
    (-1, "child_signal", 9), (-1, "exit_event", False), (-1, "output_lost", True),
    (-1, "owned_files_removed", False), (-1, "fixed_control_readback_matches", False), (-1, "rsp131_qualified", True),
    (-1, "physical_device_bytes_measured", True),
])
def test_identity_pairing_errors_never_produce_metrics(index: int, field: str, value: object) -> None:
    changed = records()
    changed[index][field] = value
    assert_refused(admit(encoded(changed)))


@pytest.mark.parametrize("lost", ["entry", "exit", "pair", "terminal", "exit_event", "begin"])
def test_missing_records_refuse_even_after_resequencing(lost: str) -> None:
    changed = records()
    indexes = {"entry": [3], "exit": [4], "pair": [3, 4], "terminal": [-1], "exit_event": [-2], "begin": [0]}[lost]
    indexes = [index if index >= 0 else len(changed) + index for index in indexes]
    for index in sorted(indexes, reverse=True):
        changed.pop(index)
    assert_refused(admit(encoded(resequence(changed))))


@pytest.mark.parametrize("kind", ["fork", "clone", "exec", "seccomp", "overflow", "signal", None, [], {}])
def test_unknown_or_extra_event_never_disappears(kind: object) -> None:
    changed = records()
    changed.insert(5, {"kind": kind})
    assert_refused(admit(encoded(resequence(changed))))


@pytest.mark.parametrize(("field", "value"), [
    ("collector_pid", 999), ("collector_pid", True), ("returncode", 1), ("returncode", None),
    ("returncode", False), ("capture_complete", False), ("capture_complete", 1),
    ("owned_group_retired", False), ("owned_group_retired", 1),
])
def test_external_capture_and_process_binding_is_required(field: str, value: object) -> None:
    assert_refused(admit(encoded(records()), **{field: value}))


@pytest.mark.parametrize("damage", ["partial", "duplicate_key", "sequence_gap", "oversize", "empty", "non_ascii", "raw_buffer"])
def test_decoder_refuses_censoring_or_unrecognized_payload(damage: str) -> None:
    rows = records()
    data = encoded(rows)
    if damage == "partial":
        data = data[:-1]
    elif damage == "duplicate_key":
        data = data.replace(b'"kind": "begin"', b'"kind": "begin", "kind": "begin"', 1)
    elif damage == "sequence_gap":
        rows[4]["sequence"] = 999
        data = encoded(rows)
    elif damage == "oversize":
        data += b" " * (256 * 1024)
    elif damage == "empty":
        data = b""
    elif damage == "non_ascii":
        data += b"\xff\n"
    else:
        rows[3]["buffer"] = "not-an-admitted-record-field"
        data = encoded(rows)
    assert_refused(admit(data))


@pytest.mark.parametrize("error", [errno.EPERM, errno.EACCES, errno.ENOSYS, errno.EBADF])
def test_permission_and_identity_refusals_have_no_fallback(error: int) -> None:
    row = copy.deepcopy(records()[-1])
    row.update(sequence=1, feasible=False, failure="pidfd_getfd", failure_errno=error, calls=0, exit_event=False)
    report = admit(encoded([row]), returncode=1)
    assert_refused(report)
    assert report["status"] == "observed_refusal"
    assert report["terminal"]["failure_errno"] == error  # type: ignore[index]
