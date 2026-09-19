"""Finite Linux descriptor-lifetime model; not a trace identity authority.

Events below are internal, identity-bound model inputs. No producer currently
derives those identities from the feasibility capture. The aggregate therefore
always says capture_bound=False and cannot qualify SQLite attribution. This
separation prevents path text, child-reported thread IDs, or synthetic controls
from silently becoming proof of the missing observed file/table identities.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from itertools import pairwise

from scripts.sqlite_syscall_intervals import MAX_RECORDS

MAX_EVENTS = 2048
MAX_TASKS = 64
MAX_DESCRIPTORS = 256
MAX_VALUE = (1 << 63) - 1


class Operation(str, Enum):
    OPEN = "open"
    DUP = "dup"
    DUP2 = "dup2"
    DUP3 = "dup3"
    FCNTL_DUP = "fcntl_dup"
    FCNTL_DUP_CLOEXEC = "fcntl_dup_cloexec"
    SET_CLOEXEC = "set_cloexec"
    CLOSE = "close"
    CLONE = "clone"
    FORK = "fork"
    UNSHARE_FILES = "unshare_files"
    EXIT = "exit"
    WRITE = "write"
    PWRITE = "pwrite"
    WRITEV = "writev"
    PWRITEV = "pwritev"
    PWRITEV2 = "pwritev2"
    FSYNC = "fsync"
    FDATASYNC = "fdatasync"
    FTRUNCATE = "ftruncate"
    RENAME = "rename"
    UNLINK = "unlink"
    UNSUPPORTED = "unsupported"


class FileRole(str, Enum):
    DATABASE = "database"
    WAL = "wal"
    SHM = "shm"
    ROLLBACK_JOURNAL = "rollback_journal"
    DIRECTORY = "directory"
    OTHER = "other"


class ErrorClass(str, Enum):
    EBADF = "ebadf"
    EIO = "eio"
    EINTR = "eintr"
    ENOSPC = "enospc"
    EINVAL = "einval"
    ENOSYS = "enosys"
    OTHER = "other"


@dataclass(frozen=True, repr=False)
class FileIdentity:
    device: int
    inode: int
    incarnation: int


@dataclass(frozen=True, repr=False)
class LifetimeEvent:
    task: int
    operation: Operation
    first_record: int
    last_record: int
    returned: int = 0
    fd: int = -1
    target: int = -1
    requested: int | None = None
    identity: FileIdentity | None = None
    role: FileRole | None = None
    error: ErrorClass | None = None
    share_files: bool | None = None
    close_on_exec: bool = False


@dataclass(frozen=True, repr=False)
class _Descriptor:
    description: int
    identity: FileIdentity
    role: FileRole
    close_on_exec: bool


_WRITES = frozenset({Operation.WRITE, Operation.PWRITE, Operation.WRITEV, Operation.PWRITEV, Operation.PWRITEV2})
_VECTORS = frozenset({Operation.WRITEV, Operation.PWRITEV, Operation.PWRITEV2})
_SYNCS = frozenset({Operation.FSYNC, Operation.FDATASYNC})
_DUPS = frozenset({Operation.DUP, Operation.DUP2, Operation.DUP3, Operation.FCNTL_DUP, Operation.FCNTL_DUP_CLOEXEC})
_READ_ONLY_TABLE_OPERATIONS = _WRITES | _SYNCS | {Operation.FTRUNCATE}
_COUNTERS = (
    "write_calls",
    "successful_write_calls",
    "returned_write_bytes",
    "failed_write_calls",
    "partial_write_calls",
    "zero_write_calls",
    "write_request_bytes_unknown",
    "sync_calls",
    "successful_sync_calls",
    "failed_sync_calls",
    "truncate_calls",
    "failed_truncate_calls",
    "close_errors",
)


def _integer(value: object, *, minimum: int = 0, maximum: int = MAX_VALUE) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _identity_valid(identity: object) -> bool:
    return (
        isinstance(identity, FileIdentity)
        and all(_integer(value) for value in (identity.device, identity.inode))
        and _integer(identity.incarnation, minimum=1)
    )


def _shape_valid(event: LifetimeEvent) -> bool:
    return (
        isinstance(event.operation, Operation)
        and _integer(event.task, minimum=1)
        and _integer(event.first_record, minimum=1, maximum=MAX_RECORDS)
        and _integer(event.last_record, minimum=event.first_record, maximum=MAX_RECORDS)
        and _integer(event.returned, minimum=-1)
        and _integer(event.fd, minimum=-1)
        and _integer(event.target, minimum=-1)
        and (event.requested is None or _integer(event.requested))
        and (event.identity is None or _identity_valid(event.identity))
        and (event.role is None or isinstance(event.role, FileRole))
        and (event.error is None or isinstance(event.error, ErrorClass))
        and (event.share_files is None or type(event.share_files) is bool)
        and type(event.close_on_exec) is bool
        and ((event.returned == -1) == (event.error is not None))
    )


def _overlap(first: LifetimeEvent, second: LifetimeEvent) -> bool:
    return first.first_record <= second.last_record and second.first_record <= first.last_record


@dataclass
class _Model:
    root_task: int
    tasks: dict[int, int] = field(default_factory=dict)
    tables: dict[int, dict[int, _Descriptor]] = field(default_factory=dict)
    seen_tasks: set[int] = field(default_factory=set)
    used_slots: set[tuple[int, int]] = field(default_factory=set)
    identities: dict[FileIdentity, FileRole] = field(default_factory=dict)
    last_incarnations: dict[tuple[int, int], int] = field(default_factory=dict)
    totals: Counter[str] = field(default_factory=Counter)
    counts: dict[FileRole, Counter[str]] = field(default_factory=lambda: {role: Counter() for role in FileRole})
    next_table: int = 1

    def __post_init__(self) -> None:
        self.tasks[self.root_task] = 0
        self.tables[0] = {}
        self.seen_tasks.add(self.root_task)

    def _copy_table(self, table: dict[int, _Descriptor]) -> int:
        identifier = self.next_table
        self.next_table += 1
        self.tables[identifier] = dict(table)
        self.used_slots.update((identifier, fd) for fd in table)
        self.totals["table_copies"] += 1
        return identifier

    def _install(self, table_id: int, fd: int, descriptor: _Descriptor) -> str | None:
        table = self.tables[table_id]
        if fd not in table and len(table) >= MAX_DESCRIPTORS:
            return "descriptor_bound"
        self.totals["descriptor_bindings"] += 1
        self.totals["reused_descriptor_slots"] += (table_id, fd) in self.used_slots
        self.used_slots.add((table_id, fd))
        table[fd] = descriptor
        return None

    def _open(self, event: LifetimeEvent, table_id: int) -> str | None:
        if event.returned == -1:
            self.totals["failed_opens"] += 1
            return None
        if event.identity is None or event.role is None:
            return "open_file_identity_or_role_unproved"
        if event.returned in self.tables[table_id]:
            return "open_reuses_live_descriptor"
        if any(
            descriptor.identity.device == event.identity.device
            and descriptor.identity.inode == event.identity.inode
            and descriptor.identity.incarnation != event.identity.incarnation
            for table in self.tables.values()
            for descriptor in table.values()
        ):
            return "file_incarnation_conflicts_with_live_binding"
        inode = (event.identity.device, event.identity.inode)
        if event.identity in self.identities and self.last_incarnations.get(inode) != event.identity.incarnation:
            return "file_incarnation_revival"
        prior = self.identities.setdefault(event.identity, event.role)
        if prior != event.role:
            return "file_identity_role_conflict"
        # Incarnations are opaque identity tokens, not ordered generation
        # numbers. A new token may replace a retired object, but an earlier
        # object lifetime cannot reappear after a different incarnation.
        self.last_incarnations[inode] = event.identity.incarnation
        self.totals["opened_descriptions"] += 1
        descriptor = _Descriptor(self.totals["opened_descriptions"], event.identity, event.role, event.close_on_exec)
        return self._install(table_id, event.returned, descriptor)

    def _duplicate(self, event: LifetimeEvent, table_id: int) -> str | None:
        table = self.tables[table_id]
        if event.returned == -1:
            self.totals["failed_duplicates"] += 1
            return None
        source = table.get(event.fd)
        if source is None:
            return "duplicate_source_unknown"
        targeted = event.operation in {Operation.DUP2, Operation.DUP3}
        if targeted and (event.target < 0 or event.returned != event.target):
            return "duplicate_target_mismatch"
        if event.operation == Operation.DUP2 and event.fd == event.target:
            self.totals["duplicate_self_noops"] += 1
            return None
        if event.operation == Operation.DUP3 and event.fd == event.target:
            return "successful_dup3_self_invalid"
        if not targeted and event.returned in table:
            return "duplicate_reuses_live_descriptor"
        if event.operation in {Operation.FCNTL_DUP, Operation.FCNTL_DUP_CLOEXEC} and (
            event.target < 0 or event.returned < event.target
        ):
            return "fcntl_minimum_mismatch"
        cloexec = event.operation == Operation.FCNTL_DUP_CLOEXEC or (
            event.operation == Operation.DUP3 and event.close_on_exec
        )
        self.totals["duplicate_bindings"] += 1
        return self._install(table_id, event.returned, replace(source, close_on_exec=cloexec))

    def _task_transition(self, event: LifetimeEvent, table_id: int) -> str | None:
        if event.operation in {Operation.CLONE, Operation.FORK}:
            if event.returned == -1:
                self.totals["failed_task_creations"] += 1
                return None
            if event.returned <= 0 or event.returned in self.seen_tasks:
                return "task_identity_reused_or_invalid"
            if len(self.seen_tasks) >= MAX_TASKS:
                return "task_bound"
            shared = False if event.operation == Operation.FORK else event.share_files
            if shared is None:
                return "shared_table_relationship_unknown"
            child_table = table_id if shared else self._copy_table(self.tables[table_id])
            self.tasks[event.returned] = child_table
            self.seen_tasks.add(event.returned)
            self.totals["shared_table_creations"] += shared
            return None
        if event.operation == Operation.EXIT and event.returned != 0:
            return "task_retirement_result_invalid"
        if event.returned not in {-1, 0}:
            return "task_transition_result_invalid"
        if event.returned == -1:
            return None
        if event.operation == Operation.UNSHARE_FILES:
            self.tasks[event.task] = self._copy_table(self.tables[table_id])
        else:
            del self.tasks[event.task]
            self.totals["retired_tasks"] += 1
        if table_id not in self.tasks.values():
            del self.tables[table_id]
        return None

    def _io(self, event: LifetimeEvent, descriptor: _Descriptor) -> str | None:
        counts = self.counts[descriptor.role]
        if event.operation in _WRITES:
            if event.requested is None and event.operation not in _VECTORS:
                return "scalar_write_request_size_unknown"
            if event.returned >= 0 and event.requested is not None and event.returned > event.requested:
                return "write_return_exceeds_request"
            counts["write_calls"] += 1
            counts["write_request_bytes_unknown"] += event.requested is None
            if event.returned == -1:
                counts["failed_write_calls"] += 1
            else:
                counts["successful_write_calls"] += 1
                counts["returned_write_bytes"] += event.returned
                counts["zero_write_calls"] += event.returned == 0
                counts["partial_write_calls"] += event.requested is not None and event.returned < event.requested
            return None
        if event.returned not in {-1, 0}:
            return "io_result_invalid"
        if event.operation in _SYNCS:
            counts["sync_calls"] += 1
            counts["successful_sync_calls"] += event.returned == 0
            counts["failed_sync_calls"] += event.returned == -1
        else:
            if event.requested is None:
                return "truncate_size_unknown"
            counts["truncate_calls"] += 1
            counts["failed_truncate_calls"] += event.returned == -1
        return None

    def apply(self, event: LifetimeEvent) -> str | None:
        table_id = self.tasks.get(event.task)
        if table_id is None:
            return "task_table_identity_unknown"
        if event.operation == Operation.UNSUPPORTED:
            return "unsupported_lifetime_boundary"
        if event.operation == Operation.OPEN:
            return self._open(event, table_id)
        if event.operation in _DUPS:
            return self._duplicate(event, table_id)
        if event.operation in {Operation.CLONE, Operation.FORK, Operation.UNSHARE_FILES, Operation.EXIT}:
            return self._task_transition(event, table_id)
        if event.operation in {Operation.RENAME, Operation.UNLINK}:
            if event.returned not in {-1, 0}:
                return "namespace_result_invalid"
            if event.returned == 0:
                if event.identity is None or event.identity not in self.identities:
                    return "namespace_object_identity_unproved"
                # Namespace changes do not retarget existing open descriptions.
                # A later open requires its own independently bound identity.
                self.totals["successful_namespace_returns"] += 1
            return None
        table = self.tables[table_id]
        descriptor = table.get(event.fd)
        if descriptor is None:
            if event.returned == -1 and event.error == ErrorClass.EBADF:
                self.totals["unbound_bad_descriptor_errors"] += 1
                return None
            return "descriptor_identity_unknown"
        if event.operation in _READ_ONLY_TABLE_OPERATIONS:
            return self._io(event, descriptor)
        if event.returned not in {-1, 0}:
            return "descriptor_transition_result_invalid"
        if event.operation == Operation.CLOSE:
            if event.error == ErrorClass.EBADF:
                return "close_bad_descriptor_conflicts_with_live_binding"
            # Linux frees a valid FD even when the later close result is EIO,
            # ENOSPC or EINTR. Never retry or retain the old binding on error.
            del table[event.fd]
            self.counts[descriptor.role]["close_errors"] += event.returned == -1
        elif event.operation == Operation.SET_CLOEXEC:
            if event.returned == 0:
                table[event.fd] = replace(descriptor, close_on_exec=event.close_on_exec)
        else:
            return "unsupported_lifetime_boundary"
        return None


def evaluate_finite_model(events: Sequence[LifetimeEvent], *, root_task: int) -> dict[str, object]:
    """Evaluate only the supplied finite model; discard totals on ambiguity.

    The model starts with a known empty descriptor table. Unsupported exec,
    close_range, SCM_RIGHTS, pidfd_getfd, asynchronous/mapped writes and unknown
    initial descriptors must arrive as UNSUPPORTED, never be silently omitted.
    No actual capture adapter yet proves that this event stream is exhaustive.
    """
    result: dict[str, object] = {
        "scope": "finite_normalized_lifetime_model",
        "status": "unknown",
        "reason": None,
        "totals": None,
        "by_file_role": None,
        "capture_bound": False,
        "sqlite_file_lifetime_attribution_complete": False,
        "wal_checkpoint_phase_attribution_complete": False,
        "physical_device_bytes_measured": False,
        "observer_overhead_quantified": False,
        "installed_workload": False,
        "rsp131_qualified": False,
    }

    def unknown(reason: str) -> dict[str, object]:
        return {**result, "reason": reason}

    if not _integer(root_task, minimum=1) or not 1 <= len(events) <= MAX_EVENTS:
        return unknown("event_bound_or_root_invalid")
    if any(not isinstance(event, LifetimeEvent) or not _shape_valid(event) for event in events):
        return unknown("event_shape_invalid")
    if any(first.last_record >= second.last_record for first, second in pairwise(events)):
        return unknown("completion_order_invalid")
    occupied_boundaries: set[int] = set()
    for event in events:
        boundaries = {event.first_record, event.last_record}
        if occupied_boundaries & boundaries:
            return unknown("physical_record_boundary_reused")
        occupied_boundaries.update(boundaries)
    for index, first in enumerate(events):
        for second in events[index + 1 :]:
            if _overlap(first, second):
                if first.task == second.task:
                    return unknown("same_task_intervals_overlap")
                # Conservatively reject any overlapping lifetime mutation,
                # including across apparently separate tables. The observer
                # does not infer kernel FD lookup from trace printing order.
                if (
                    first.operation not in _READ_ONLY_TABLE_OPERATIONS
                    or second.operation not in _READ_ONLY_TABLE_OPERATIONS
                ):
                    return unknown("overlapping_lifetime_mutation")
    model = _Model(root_task)
    for event in events:
        reason = model.apply(event)
        if reason is not None:
            return unknown(reason)
    if model.tasks or model.tables:
        return unknown("task_retirement_incomplete")
    result.update(
        status="consistent_finite_model",
        totals={**model.totals, "bound_file_identities": len(model.identities)},
        by_file_role={
            role.value: {
                **{key: counts[key] for key in _COUNTERS},
                "failed_write_bytes": None if counts["failed_write_calls"] else 0,
                "partial_write_coverage_complete": counts["write_request_bytes_unknown"] == 0,
            }
            for role, counts in model.counts.items()
        },
    )
    return result
