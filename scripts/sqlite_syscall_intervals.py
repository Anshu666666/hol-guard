"""Private call intervals for the existing bounded SQLite feasibility capture.

This is an additive consumer of the unchanged strict parser. Record positions
are ordering evidence, never timestamps or kernel file-reference acquisition
points. Arguments, descriptor numbers and task IDs stay in process memory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from scripts.probe_sqlite_syscall_observation import _CALL, _LINE, parse_calls
from scripts.sqlite_syscall_probe_supervision import MAX_STREAM_BYTES, TRACE_CALLS

MAX_RECORDS = 4096


@dataclass(frozen=True, repr=False)
class CallInterval:
    task: int
    name: str
    arguments: str
    result: str
    first_record: int
    last_record: int


@dataclass(frozen=True)
class IntervalResult:
    complete: bool
    reason: str | None
    records: int
    calls: tuple[CallInterval, ...] = field(default=(), repr=False)

    def summary(self) -> dict[str, object]:
        return {
            "physical_intervals_complete": self.complete,
            "reason": self.reason,
            "physical_records": self.records,
            "completed_calls": len(self.calls),
            "raw_arguments_exported": False,
            "kernel_reference_acquisition_order_proven": False,
        }


def call_intervals(trace: bytes, owner_pid: int, *, streams_complete: bool) -> IntervalResult:
    """Keep both ends of unfinished calls; never guess an entry at its return.

    The old parser must accept the entire capture first. This consumer adds
    physical-LF and same-task interval requirements without changing its
    acceptance or any existing feasibility gate. No partial prefix is returned
    after a failure, missing stream, invalid encoding or exhausted bound.
    """
    if type(owner_pid) is not int or owner_pid <= 0 or streams_complete is not True:
        return IntervalResult(False, "capture_or_owner_incomplete", 0)
    if not trace or len(trace) > MAX_STREAM_BYTES:
        return IntervalResult(False, "capture_byte_bound_or_empty", 0)
    records = trace.count(b"\n")
    if not trace.endswith(b"\n") or records > MAX_RECORDS:
        return IntervalResult(False, "physical_record_bound_or_unterminated", min(records, MAX_RECORDS))
    try:
        decoded = trace.decode("utf-8", errors="strict")
    except UnicodeError:
        return IntervalResult(False, "invalid_utf8", records)
    if any(
        character in decoded for character in ("\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")
    ):
        return IntervalResult(False, "non_lf_record_separator", records)
    try:
        strict, accepted = parse_calls(trace, owner_pid)
    except (ValueError, OverflowError):
        return IntervalResult(False, "strict_parser_rejected", records)
    if not accepted:
        return IntervalResult(False, "strict_parser_rejected", records)
    pending: dict[int, tuple[str, int]] = {}
    calls: list[CallInterval] = []
    for ordinal, line in enumerate(decoded[:-1].split("\n"), 1):
        match = _LINE.fullmatch(line)
        if match is None:
            return IntervalResult(False, "interval_reconstruction_mismatch", records)
        task, body = int(match[1] or match[2] or owner_pid), match[3]
        if task <= 0:
            return IntervalResult(False, "invalid_task_identity", records)
        first = ordinal
        if body.endswith(" <unfinished ...>"):
            if task in pending:
                return IntervalResult(False, "same_task_overlapping_calls", records)
            pending[task] = (body.removesuffix(" <unfinished ...>"), ordinal)
            continue
        if body.startswith("<... "):
            resumed = re.fullmatch(r"<\.\.\. ([a-z][a-z0-9_]*) resumed>(.*)", body)
            prior = pending.pop(task, None)
            if resumed is None or prior is None or not prior[0].startswith(resumed[1] + "("):
                return IntervalResult(False, "interval_reconstruction_mismatch", records)
            body, first = prior[0] + resumed[2], prior[1]
        call = _CALL.fullmatch(body)
        if call is not None:
            if task in pending:
                return IntervalResult(False, "same_task_overlapping_calls", records)
            calls.append(CallInterval(task, call[1], call[2], call[3], first, ordinal))
    projection = [(call.task, call.name, call.arguments, call.result) for call in calls]
    if pending or projection != strict:
        return IntervalResult(False, "interval_reconstruction_mismatch", records)
    return IntervalResult(True, None, records, tuple(calls))


def current_capture_boundary() -> dict[str, object]:
    """Describe actual source coverage; no caller can supply a success flag.

    Syscall presence alone is necessary, never sufficient, for a lifetime
    proof. In particular -yy path annotations are not inode/incarnation or
    namespace witnesses, and the existing child supplies only serial-control
    identities. Do not promote this report when the trace filter expands.
    """
    calls = frozenset(TRACE_CALLS.split(","))
    necessary_groups = {
        "descriptor_operations": frozenset({"open", "openat", "close", "dup", "dup2", "dup3", "fcntl"}),
        "thread_and_table_transitions": frozenset(
            {"clone", "clone3", "fork", "vfork", "unshare", "execve", "close_range"}
        ),
        "file_identity_observations": frozenset({"fstat", "newfstatat", "statx"}),
        "namespace_transitions": frozenset({"rename", "renameat", "renameat2", "unlink", "unlinkat", "link", "linkat"}),
        "truncate_and_mapping_transitions": frozenset({"ftruncate", "truncate", "mmap", "msync", "munmap"}),
    }
    return {
        "scope": "current_source_capture_boundary",
        "necessary_syscall_groups_present": {name: required <= calls for name, required in necessary_groups.items()},
        "sqlite_file_lifetime_attribution_complete": False,
        "sqlite_written_bytes": None,
        "sqlite_fsync_calls": None,
        "unavailable": (
            "initial_descriptor_and_task_table_identity_unproved",
            "all_descriptor_creation_transfer_and_retirement_unproved",
            "file_identity_and_incarnation_unproved",
            "namespace_role_binding_unproved",
            "kernel_reference_order_under_overlap_unproved",
            "mapped_or_async_write_coverage_unproved",
            "wal_checkpoint_phase_binding_unproved",
        ),
        "physical_device_bytes_measured": False,
        "observer_overhead_quantified": False,
        "installed_workload": False,
        "rsp131_qualified": False,
    }
