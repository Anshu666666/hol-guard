"""Strict private kernel records and source-interval reconstruction.

Input bytes and addresses stay in memory. There is deliberately no raw-input
file writer or command line. Successful decoding is not capture admission.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass

if __package__:
    from .admission import BOUNDS, FUNCTIONS
else:
    from admission import BOUNDS, FUNCTIONS  # pyright: ignore[reportImplicitRelativeImport]

WIRE = struct.Struct("<8I5Qq9Q7QQ5Q")
assert WIRE.size == 256
HOOKS = ("none", *FUNCTIONS)
KINDS = {
    1: "hook",
    2: "task_birth",
    3: "task_exec",
    4: "task_exit",
    5: "marker",
    6: "syscall",
    7: "snapshot",
    8: "slot",
    9: "controller",
}
REASONS = (
    "ring_loss",
    "event_limit",
    "map_limit",
    "kernel_read_failure",
    "frame_missing",
    "frame_depth",
    "frame_duplicate",
    "layout_invalid",
    "file_rebirth",
    "foreign_object",
    "inode_rebirth",
    "context_invalid",
    "context_depth",
    "context_unmatched",
    "deadline",
    "syscall_unmatched",
    "unsupported_syscall",
    "initial_table_invalid",
    "fd_limit",
    "file_origin_unproved",
    "task_rebirth",
    "unsupported_abi",
    "mm_changed",
)
TOTAL_FIELDS = (
    "ordinal",
    "emitted",
    "dropped",
    "reasons",
    "next_object",
    "task_births",
    "file_births",
    "file_retirements",
    "inode_retirements",
    "marker_entries",
    "marker_returns",
    "syscall_entries",
    "syscall_returns",
)
POINT_HOOKS = {"__fput", "security_file_free", "__destroy_inode", "__put_task_struct", "__mmdrop"}
CONSTRUCTORS = {"alloc_empty_file", "alloc_empty_file_noaccount", "alloc_empty_backing_file"}
U64 = (1 << 64) - 1


class StreamError(ValueError):
    """Fixed reason only; never interpolate a private event into an error."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise StreamError(reason)


def pointer_result(value: int) -> bool:
    return 0 < (value & U64) < (1 << 64) - 4095


@dataclass(frozen=True, repr=False)
class Record:
    kind: str
    phase: int
    hook: str
    flags: int
    ordinal: int
    call: int
    task: int
    mm: int
    table: int
    result: int
    args: tuple[int, ...]
    file_cookie: int
    inode_cookie: int
    file: int
    inode: int
    device: int
    inumber: int
    mode: int
    context: int
    extra: tuple[int, ...]

    @classmethod
    def decode(cls, raw: bytes) -> Record:
        require(type(raw) is bytes and len(raw) == WIRE.size, "record_size")
        v = WIRE.unpack(raw)
        abi, size, kind, phase, hook, flags, r0, r1 = v[:8]
        require(abi == 1 and size == 256 and not r0 and not r1, "record_header")
        require(kind in KINDS and phase in (1, 2, 3) and hook < len(HOOKS), "record_enum")
        require(0 < v[8] <= BOUNDS["private_events"] and v[10] != 0, "record_identity")
        require(flags in (0, 1, 2), "record_flags")
        require((kind == 1) == (hook != 0), "record_hook_kind")
        require(not (kind == 1 and phase == 3) or HOOKS[hook] in POINT_HOOKS, "point_hook_unsupported")
        require(kind not in (2, 3, 4, 5, 8, 9) or phase == 3, "record_phase")
        require(kind != 7 or phase in (1, 2), "snapshot_phase")
        return cls(
            kind=KINDS[kind],
            phase=phase,
            hook=HOOKS[hook],
            flags=flags,
            ordinal=v[8],
            call=v[9],
            task=v[10],
            mm=v[11],
            table=v[12],
            result=v[13],
            args=tuple(v[14:23]),
            file_cookie=v[23],
            inode_cookie=v[24],
            file=v[25],
            inode=v[26],
            device=v[27],
            inumber=v[28],
            mode=v[29],
            context=v[30],
            extra=tuple(v[31:36]),
        )


@dataclass(frozen=True, repr=False)
class Interval:
    entry: Record
    returned: Record

    @property
    def first(self) -> int:
        return self.entry.ordinal

    @property
    def last(self) -> int:
        return self.returned.ordinal

    def contains(self, other: Interval) -> bool:
        return self.first < other.first and other.last < self.last


@dataclass(frozen=True, repr=False)
class Snapshot:
    entry: Record
    returned: Record
    slots: tuple[Record, ...]


@dataclass(frozen=True, repr=False)
class Decoded:
    records: tuple[Record, ...]
    intervals: tuple[Interval, ...]
    snapshots: tuple[Snapshot, ...]
    counters: dict[str, int]


def decode_stream(chunks: Iterable[bytes], counters: dict[str, int]) -> Decoded:
    require(type(counters) is dict and set(counters) == set(TOTAL_FIELDS), "counter_schema")
    require(all(type(v) is int and 0 <= v <= U64 for v in counters.values()), "counter_type")
    require(counters["reasons"] < (1 << len(REASONS)), "counter_unknown_reason")
    require(not counters["reasons"] and not counters["dropped"], "producer_incomplete")
    require(0 < counters["ordinal"] <= BOUNDS["private_events"], "counter_event_limit")
    require(counters["next_object"] <= BOUNDS["private_events"], "counter_object_limit")
    records = []
    for raw in chunks:
        require(len(records) < BOUNDS["private_events"], "event_limit")
        records.append(Record.decode(raw))
    require(len(records) == counters["emitted"] == counters["ordinal"], "event_conservation")
    # Explicit producer ordinals, never delivery order, identify boundaries.
    records.sort(key=lambda r: r.ordinal)
    require([r.ordinal for r in records] == list(range(1, len(records) + 1)), "ordinal_duplicate_or_gap")
    counts = {
        "task_births": sum(r.kind == "task_birth" for r in records),
        "file_births": sum(
            r.kind == "hook" and r.phase == 2 and r.hook in CONSTRUCTORS and pointer_result(r.result) for r in records
        ),
        "file_retirements": sum(r.kind == "hook" and r.phase == 3 and r.hook == "security_file_free" for r in records),
        "inode_retirements": sum(r.kind == "hook" and r.phase == 3 and r.hook == "__destroy_inode" for r in records),
        "marker_entries": sum(r.kind == "marker" and r.args[0] == 1 for r in records),
        "marker_returns": sum(r.kind == "marker" and r.args[0] == 2 for r in records),
        "syscall_entries": sum(r.kind == "syscall" and r.phase == 1 for r in records),
        "syscall_returns": sum(r.kind == "syscall" and r.phase == 2 for r in records),
    }
    require(all(counters[k] == v for k, v in counts.items()), "operation_conservation")
    active: dict[tuple[str, int, str], list[Record]] = {}
    intervals: list[Interval] = []
    snapshot_entries: dict[int, Record] = {}
    snapshot_calls: set[int] = set()
    slot_rows: dict[int, list[Record]] = {}
    snapshots: list[Snapshot] = []
    marker_stack: dict[int, list[Record]] = {}
    for r in records:
        if r.kind in ("hook", "syscall") and r.phase != 3:
            key = (r.kind, r.task, r.hook)
            stack = active.setdefault(key, [])
            if r.phase == 1:
                require(r.call == r.ordinal and len(stack) < BOUNDS["helper_depth"], "call_entry_identity_or_depth")
                stack.append(r)
            else:
                require(bool(stack), "call_return_unmatched")
                first = stack.pop()
                require(
                    r.call == first.call and r.args == first.args and r.context == first.context, "call_return_identity"
                )
                require(r.mm == first.mm, "call_mm_changed")
                if r.kind == "hook":
                    require(r.table == first.table, "call_table_changed")
                    prototype = FUNCTIONS[r.hook]
                    require(not prototype.startswith("void(") or r.result == 0, "void_result_changed")
                    require(
                        not prototype.startswith("signed:32(") or -(1 << 31) <= r.result < (1 << 31),
                        "integer_return_width",
                    )
                intervals.append(Interval(first, r))
        elif r.kind == "marker":
            phase, method, role, logical, _ = r.args[:5]
            require(1 <= phase <= 4 and 1 <= method <= 20 and 0 <= role <= 8, "marker_shape")
            require(logical > 0 or method == 20, "marker_logical_identity")
            stack = marker_stack.setdefault(r.task, [])
            if phase == 1:
                require(
                    not r.result and r.context == r.ordinal and len(stack) < BOUNDS["sqlite_context_depth"],
                    "marker_entry",
                )
                stack.append(r)
            elif phase == 2:
                require(bool(stack), "marker_return_unmatched")
                first = stack.pop()
                require(
                    r.context == first.context and r.args[1:5] == first.args[1:5] and r.mm == first.mm,
                    "marker_return_identity",
                )
                intervals.append(Interval(first, r))
            else:
                require(bool(stack) and method == 11 and r.context == stack[-1].context, "checkpoint_marker_context")
        elif r.kind == "snapshot":
            if r.phase == 1:
                require(r.call not in snapshot_calls and r.args[0] in (1, 2, 3), "snapshot_entry")
                snapshot_calls.add(r.call)
                require(0 < r.args[1] <= BOUNDS["fd_slots_per_table"], "snapshot_slot_bound")
                require(r.table != 0, "snapshot_table_missing")
                snapshot_entries[r.call] = r
                slot_rows[r.call] = []
            else:
                require(r.call in snapshot_entries, "snapshot_return_unmatched")
                first = snapshot_entries.pop(r.call)
                rows = slot_rows.pop(r.call)
                require(
                    r.table == first.table and r.task == first.task and r.args[:2] == first.args[:2],
                    "snapshot_return_identity",
                )
                require([row.args[0] for row in rows] == list(range(first.args[1])), "snapshot_slots_incomplete")
                snapshots.append(Snapshot(first, r, tuple(rows)))
        elif r.kind == "slot":
            require(r.call in snapshot_entries, "snapshot_slot_unmatched")
            first = snapshot_entries[r.call]
            require(
                r.task == first.task and r.table == first.table and r.args[4] == first.args[0], "snapshot_slot_identity"
            )
            fd, opened, cloexec, pointer, _ = r.args[:5]
            require(fd < first.args[1] and opened in (0, 1) and cloexec in (0, 1), "snapshot_slot_shape")
            require(not pointer or (opened == 1 and r.file == pointer and r.file_cookie > 0), "snapshot_slot_file")
            require(pointer != 0 or (r.file == 0 and r.file_cookie == 0), "snapshot_null_file")
            require(first.args[0] != 1 or pointer != 0 or opened == 0, "copy_reserved_slot_not_cleared")
            slot_rows[r.call].append(r)
    require(not any(active.values()) and not any(marker_stack.values()), "unfinished_interval")
    require(not snapshot_entries and not slot_rows, "unfinished_snapshot")
    # Different hooks in one task must be properly nested. Separate tasks can
    # overlap freely; no sorting or adjacency rule invents their execution order.
    by_task: dict[int, list[Interval]] = {}
    for item in intervals:
        by_task.setdefault(item.entry.task, []).append(item)
    for rows in by_task.values():
        interval_stack: list[Interval] = []
        for item in sorted(rows, key=lambda item: item.first):
            while interval_stack and item.first > interval_stack[-1].last:
                interval_stack.pop()
            require(not interval_stack or item.last < interval_stack[-1].last, "crossing_same_task_intervals")
            interval_stack.append(item)
    return Decoded(tuple(records), tuple(intervals), tuple(snapshots), dict(counters))
