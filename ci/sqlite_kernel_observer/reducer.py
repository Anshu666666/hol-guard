"""Finite semantics for the concrete private producer ABI.

This reducer cannot authenticate a host, attach a probe, or execute Guard.
Even a consistent supplied stream is explicitly not an observed measurement.
It conserves synchronous positive return bytes; device/SHM dirty bytes stay
unknown. Descriptor mutations retain intervals instead of guessed timestamps.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

if __package__:
    from .admission import TARGET_LAYOUT
    from .records import CONSTRUCTORS, U64, Decoded, Interval, Record, Snapshot, pointer_result, require
else:
    from admission import TARGET_LAYOUT  # pyright: ignore[reportImplicitRelativeImport]
    from records import (  # pyright: ignore[reportImplicitRelativeImport]
        CONSTRUCTORS,
        U64,
        Decoded,
        Interval,
        Record,
        Snapshot,
        pointer_result,
        require,
    )

ROLES = {
    1: "main_database",
    2: "wal",
    3: "main_journal",
    4: "temporary_database",
    5: "temporary_journal",
    6: "subjournal",
    7: "super_journal",
    8: "transient_database",
}
IO_HOOKS = {"vfs_write", "vfs_writev", "vfs_fsync_range"}
IO_SYSCALLS = {
    1: "vfs_write",
    18: "vfs_write",
    20: "vfs_writev",
    296: "vfs_writev",
    328: "vfs_writev",
    74: "vfs_fsync_range",
    75: "vfs_fsync_range",
}
REGULAR, DIRECTORY = 0o100000, 0o040000


@dataclass(repr=False)
class File:
    pointer: int
    birth: int
    owner: int
    origin: str
    inode: int = 0
    retiring: int = 0
    retired: int = 0
    selected: bool = False


@dataclass(repr=False)
class Task:
    birth: int
    controller: bool
    mm: int
    epoch: int
    table: int
    exited: bool = False
    files_detached: bool = False
    retired: bool = False


@dataclass(frozen=True, repr=False)
class Slot:
    cookie: int
    reserved: bool
    cloexec: bool


@dataclass(repr=False)
class Table:
    birth: int
    array: int
    slots: dict[int, Slot]
    closed: bool = False
    closed_at: int = 0
    initial: dict[int, Slot] = field(default_factory=dict)
    # Full event intervals, never a synthesized linearization timestamp.
    changes: list[tuple[int, int, int, Slot, Slot]] = field(default_factory=list)


class Reducer:
    def __init__(self, decoded: Decoded):
        self.stream = decoded
        self.files: dict[int, File] = {}
        self.file_pointers: dict[int, int] = {}
        self.inodes: dict[int, tuple[int, int, int, int]] = {}
        self.inode_pointers: dict[int, int] = {}
        self.dead_inodes: set[int] = set()
        self.tasks: dict[int, Task] = {}
        self.epochs: dict[int, int] = {}
        self.dead_epochs: set[int] = set()
        self.tables: dict[int, Table] = {}
        self.table_history: list[tuple[int, Table]] = []
        self.contexts = {i.entry.context: i for i in decoded.intervals if i.entry.kind == "marker"}
        self.calls = {i.entry.call: i for i in decoded.intervals if i.entry.kind == "hook"}
        self.snapshots = {s.entry.call: s for s in decoded.snapshots}
        self.pending_replacements: dict[tuple[int, int], Interval] = {}
        self.rows: dict[str, Counter[str]] = {}
        self.unknown_failed_attempts = 0
        self.shm_mappings = 0
        self.truncations = 0
        self.namespace_attempts = 0
        self.nested_helpers = 0
        self.child_returns: set[tuple[int, int]] = set()
        self.open_handles = 0

    def inode(self, r: Record) -> None:
        if not r.inode_cookie:
            require(r.inode == 0, "inode_cookie_missing")
            return
        require(r.inode != 0 and r.inode_cookie not in self.dead_inodes, "inode_retired_reappeared")
        previous = self.inode_pointers.get(r.inode)
        require(previous is None or previous == r.inode_cookie, "inode_pointer_reused_without_retirement")
        if r.inode_cookie in self.inodes:
            old = self.inodes[r.inode_cookie]
            require(old[0] == r.inode, "inode_cookie_pointer_changed")
            if r.mode:
                require(old[1:] == (r.device, r.inumber, r.mode & 0o170000), "inode_identity_changed")
        else:
            require(r.mode != 0, "inode_first_observation_incomplete")
            self.inodes[r.inode_cookie] = (r.inode, r.device, r.inumber, r.mode & 0o170000)
        self.inode_pointers[r.inode] = r.inode_cookie

    def observed_file(self, r: Record) -> None:
        if not r.file_cookie:
            require(r.file == 0, "file_cookie_missing")
            if r.inode_cookie:
                self.inode(r)
            return
        require(r.file != 0 and r.file_cookie <= self.stream.counters["next_object"], "file_cookie_bounds")
        previous = self.file_pointers.get(r.file)
        require(previous is None or previous == r.file_cookie, "file_pointer_reused_without_retirement")
        if r.file_cookie not in self.files:
            if r.kind == "hook" and r.phase == 2 and r.hook in CONSTRUCTORS:
                require(r.flags == 1 and pointer_result(r.result) and (r.result & U64) == r.file, "file_birth_shape")
                self.files[r.file_cookie] = File(r.file, r.ordinal, r.task, "observed_constructor")
            else:
                require(r.kind == "slot" and r.args[4] == 1 and r.flags == 2, "file_birth_missing")
                self.files[r.file_cookie] = File(r.file, r.ordinal, r.task, "left_censored_inherited")
        value = self.files[r.file_cookie]
        require(not value.retired and value.pointer == r.file, "file_retired_reappeared")
        require(r.flags == (1 if value.origin == "observed_constructor" else 2), "file_origin_changed")
        self.file_pointers[r.file] = r.file_cookie
        if r.inode_cookie:
            self.inode(r)
            require(value.inode in (0, r.inode_cookie), "file_inode_changed")
            value.inode = r.inode_cookie

    def constructor_controls(self) -> None:
        for call in self.calls.values():
            if call.entry.hook not in CONSTRUCTORS:
                continue
            security = [
                s
                for s in self.calls.values()
                if s.entry.hook == "security_file_alloc"
                and s.entry.task == call.entry.task
                and call.contains(s)
                and not any(
                    n.entry.hook in CONSTRUCTORS and n is not call and call.contains(n) and n.contains(s)
                    for n in self.calls.values()
                )
            ]
            require(len(security) <= 1, "constructor_security_ambiguous")
            if pointer_result(call.returned.result):
                require(
                    len(security) == 1
                    and security[0].returned.result == 0
                    and security[0].entry.args[0] == (call.returned.result & U64),
                    "constructor_security_unproved",
                )
            elif security:
                require(
                    security[0].returned.result < 0 and security[0].returned.result == call.returned.result,
                    "constructor_failed_result_disagrees",
                )
            else:
                require(call.returned.result in (-12, -23), "constructor_failure_without_source_path")
        for call in self.calls.values():
            if call.entry.hook != "security_file_free":
                continue
            parents = [
                s
                for s in self.calls.values()
                if s.entry.hook == "security_file_alloc" and s.entry.task == call.entry.task and s.contains(call)
            ]
            require(
                len(parents) == 1 and parents[0].returned.result < 0 and parents[0].entry.args[0] == call.entry.args[0],
                "failed_constructor_cleanup_unproved",
            )
            require(call.returned.result == 0, "void_result_changed")

    def install_snapshot(self, snapshot: Snapshot) -> None:
        entry = snapshot.entry
        mode = entry.args[0]
        call = self.calls.get(entry.call)
        require(call is not None, "snapshot_call_missing")
        assert call is not None
        expected = {1: "dup_fd", 2: "do_close_on_exec", 3: "close_files"}[mode]
        require(call.entry.hook == expected and call.entry.task == entry.task, "snapshot_wrong_source")
        if mode == 1:
            require(
                call.returned.ordinal < entry.ordinal and (call.returned.result & U64) == entry.table,
                "copy_snapshot_not_at_unpublished_return",
            )
            require(entry.args[3] == 1, "copy_snapshot_shared")
            previous = self.tables.get(entry.table)
            require(previous is None or previous.closed, "table_pointer_reused_without_retirement")
            self.tables[entry.table] = Table(
                entry.ordinal,
                entry.args[2],
                {
                    r.args[0]: Slot(r.file_cookie, bool(r.args[1] and not r.args[3]), bool(r.args[2]))
                    for r in snapshot.slots
                },
            )
            self.tables[entry.table].initial = dict(self.tables[entry.table].slots)
            self.table_history.append((entry.table, self.tables[entry.table]))
        else:
            require(
                call.entry.ordinal < entry.ordinal < snapshot.returned.ordinal < call.returned.ordinal,
                "snapshot_not_in_held_interval",
            )
            table = self.tables.get(entry.table)
            require(table is not None and not table.closed, "snapshot_unknown_table")
            assert table is not None
            if mode == 3:
                require(entry.args[3] == 0, "final_table_not_last_reference")
            else:
                owners = [
                    t for t in self.tasks.values() if not t.files_detached and not t.retired and t.table == entry.table
                ]
                require(len(owners) == 1, "exec_table_shared")
            for r in snapshot.slots:
                old = table.slots.get(r.args[0], Slot(0, False, False))
                # Absent slots may retain an unused CLOEXEC bitmap bit.
                require(
                    old.cookie == r.file_cookie and old.reserved == bool(r.args[1] and not r.args[3]),
                    "snapshot_slot_state_disagrees",
                )
                if old.cookie or old.reserved:
                    require(old.cloexec == bool(r.args[2]), "snapshot_cloexec_disagrees")
            for fd, old in tuple(table.slots.items()):
                if mode == 3 or old.cloexec:
                    self.change(call, fd, Slot(0, False, False))

    def change(self, call: Interval, fd: int, new: Slot, expected_cookie: int | None = None) -> None:
        table = self.tables.get(call.entry.table)
        if table is None:
            require(self.tasks[call.entry.task].controller, "descriptor_table_unknown")
            return
        require(not table.closed and 0 <= fd < 256, "descriptor_table_or_fd_invalid")
        old = table.slots.get(fd, Slot(0, False, False))
        if expected_cookie is not None:
            require(old.cookie == expected_cookie, "descriptor_held_file_disagrees")
        table.changes.append((call.first, call.last, fd, old, new))
        table.slots[fd] = new

    def event(self, r: Record) -> None:
        if r.kind in ("controller", "task_birth"):
            require(r.task not in self.tasks or self.tasks[r.task].retired, "task_rebirth")
            controller = r.kind == "controller" or bool(r.args[1])
            if r.kind == "task_birth":
                require(r.args[0] in self.tasks and not self.tasks[r.args[0]].retired, "task_parent_unknown")
                require(
                    r.table in self.tables or controller or r.table == self.tasks[r.args[0]].table,
                    "task_initial_table_unproved",
                )
            require(r.extra[4] > 0 and r.extra[4] not in self.dead_epochs, "address_space_epoch_missing")
            old = self.epochs.get(r.mm)
            require(old in (None, r.extra[4]), "address_space_pointer_reused")
            self.epochs[r.mm] = r.extra[4]
            self.tasks[r.task] = Task(r.call, controller, r.mm, r.extra[4], r.table)
            return
        if r.kind == "syscall" and r.phase == 3:
            task = self.tasks.get(r.task)
            birth = next(
                (
                    x
                    for x in self.stream.records
                    if x.kind == "task_birth" and x.task == r.task and task is not None and x.call == task.birth
                ),
                None,
            )
            require(
                task is not None
                and birth is not None
                and (r.task, r.call) not in self.child_returns
                and r.call == task.birth
                and r.result == 0
                and r.args[0] in (56, 57, 58, 435)
                and birth.args[2] == r.args[0]
                and birth.args[3] == 1
                and not any(
                    x.kind == "syscall" and x.task == r.task and x.phase == 1 and birth.ordinal < x.ordinal < r.ordinal
                    for x in self.stream.records
                ),
                "child_return_without_fork_branch",
            )
            assert birth is not None
            assert task is not None
            self.child_returns.add((r.task, r.call))
            return
        if r.kind == "task_exec":
            task = self.tasks.get(r.task)
            require(task is not None and not task.exited and r.call == task.birth, "exec_task_unknown")
            assert task is not None
            require(
                r.args[0] == task.mm and r.extra[4] > 0 and r.extra[4] not in self.dead_epochs, "exec_epoch_disagrees"
            )
            require(r.extra[4] != task.epoch, "exec_epoch_not_new")
            require(r.table in self.tables, "exec_table_unproved")
            task.mm, task.epoch, task.table = r.mm, r.extra[4], r.table
            self.epochs[r.mm] = r.extra[4]
            return
        if r.kind == "task_exit":
            task = self.tasks.get(r.task)
            require(task is not None and not task.exited and r.call == task.birth, "task_exit_unmatched")
            assert task is not None
            task.exited = True
            return
        if r.kind == "hook" and r.phase == 3:
            if r.hook == "__mmdrop":
                require(self.epochs.get(r.mm) == r.extra[4], "mm_retirement_unmatched")
                self.dead_epochs.add(r.extra[4])
                del self.epochs[r.mm]
            elif r.hook == "__put_task_struct":
                task = self.tasks.get(r.task)
                require(
                    task is not None and task.exited and task.files_detached and r.extra[0] == 1,
                    "task_retirement_before_exit_files",
                )
                assert task is not None
                task.retired = True
            elif r.hook == "__destroy_inode":
                require(self.inode_pointers.get(r.inode) == r.inode_cookie, "inode_retirement_unmatched")
                # A RETIRING file may keep a saved inode cookie after dput.
                require(
                    not any(
                        f.inode == r.inode_cookie and not f.retired and not f.retiring for f in self.files.values()
                    ),
                    "inode_retired_with_live_held_file",
                )
                self.dead_inodes.add(r.inode_cookie)
                del self.inode_pointers[r.inode]
            else:
                file = self.files.get(r.file_cookie)
                require(file is not None and not file.retired and file.pointer == r.file, "file_retirement_unmatched")
                assert file is not None
                require(file.inode == r.inode_cookie, "saved_inode_retirement_disagrees")
                if r.hook == "__fput":
                    require(not file.retiring and r.extra[0] == 0, "file_retirement_repeated")
                    file.retiring = r.ordinal
                else:
                    require(bool(file.retiring) == bool(r.extra[0]), "file_retirement_phase_disagrees")
                    require(file.inode == 0 or file.retiring > 0, "bound_file_freed_without_retiring")
                    require(
                        not any(
                            not table.closed and any(slot.cookie == r.file_cookie for slot in table.slots.values())
                            for table in self.tables.values()
                        ),
                        "file_retired_with_installed_descriptor",
                    )
                    file.retired = r.ordinal
                    del self.file_pointers[r.file]
            return
        if r.kind not in ("snapshot", "syscall"):
            self.observed_file(r)
        if r.kind == "snapshot" and r.phase == 2:
            self.install_snapshot(self.snapshots[r.call])
        if r.kind == "hook" and r.phase == 1 and r.hook in ("fd_install", "do_dup2"):
            call = self.calls[r.call]
            if r.hook == "fd_install":
                table = self.tables.get(r.table)
                require(table is not None or self.tasks[r.task].controller, "install_table_unproved")
                if table is not None:
                    old = table.slots.get(r.args[0], Slot(0, False, False))
                    require(old.reserved and not old.cookie and r.file_cookie > 0, "install_without_reservation")
                    self.change(call, r.args[0], Slot(r.file_cookie, False, old.cloexec), 0)
            elif call.returned.result >= 0:
                require(call.returned.result == r.args[2] and r.file_cookie > 0, "dup_result_disagrees")
                old_pointer = r.extra[0]
                old_cookie = self.file_pointers.get(old_pointer, 0)
                require(old_pointer == 0 or old_cookie > 0, "dup_old_file_unproved")
                self.change(call, r.args[2], Slot(r.file_cookie, False, bool(r.args[3] & 0o2000000)), old_cookie)
        if r.kind != "hook" or r.phase != 2:
            return
        call = self.calls[r.call]
        task = self.tasks.get(r.task)
        require(task is not None, "call_task_unobserved")
        assert task is not None
        args = call.entry.args
        if r.hook == "alloc_fd" and r.result >= 0:
            self.change(call, r.result, Slot(0, True, bool(args[2] & 0o2000000)), 0)
        elif r.hook == "put_unused_fd":
            self.change(call, args[0], Slot(0, False, False), 0)
        elif r.hook == "file_close_fd_locked" and pointer_result(r.result):
            self.change(call, args[1], Slot(0, False, False), r.file_cookie)
        elif r.hook == "set_close_on_exec":
            table = self.tables.get(r.table)
            if table is not None:
                old = table.slots.get(args[0], Slot(0, False, False))
                self.change(call, args[0], Slot(old.cookie, old.reserved, bool(args[1])), old.cookie)
        elif r.hook == "expand_fdtable" and r.result == 0:
            table = self.tables.get(r.table)
            if table is not None:
                require(table.array == call.entry.extra[0] and r.extra[0] != 0, "table_growth_identity_disagrees")
                table.array = r.extra[0]
        elif r.hook in ("do_close_on_exec", "close_files"):
            table = self.tables.get(r.table)
            require(table is not None and r.call in self.snapshots, "table_closure_snapshot_missing")
            assert table is not None
            table.closed = r.hook == "close_files"
            if table.closed:
                table.closed_at = r.ordinal
        elif r.hook in ("unshare_files", "__close_range"):
            if r.result == 0:
                require(r.hook != "__close_range" or not (args[2] & 4), "cloexec_range_unavailable")
                require(r.extra[0] in self.tables or task.controller, "unshare_new_table_unproved")
                task.table = r.extra[0]
        elif r.hook == "exit_files":
            require(args[0] == r.task and r.extra[0] == 0, "exit_files_not_detached")
            task.files_detached = True

    def run(self) -> dict[str, object]:
        self.constructor_controls()
        for record in self.stream.records:
            self.event(record)
        self.attribute()
        owned = [task for task in self.tasks.values() if not task.controller]
        selected_files = [file for file in self.files.values() if file.selected]
        return {
            "schema": "hol_sqlite_private_producer_reduction_v1",
            "supplied_stream_semantics_consistent": True,
            "input_origin": "untrusted_supplied_private_records",
            "actual_host_capture_authenticated": False,
            "selected_synchronous_attribution_proved": False,
            "all_owned_tasks_retired_in_supplied_stream": bool(owned) and all(t.retired for t in owned),
            "all_selected_files_retired_in_supplied_stream": bool(selected_files)
            and all(f.retired for f in selected_files),
            "selected_returned_io_model": {name: dict(sorted(row.items())) for name, row in sorted(self.rows.items())},
            "failed_attempts_without_held_file": self.unknown_failed_attempts,
            "successful_open_handles_not_closed": self.open_handles,
            "observed_nested_helpers_excluded_from_outer_totals": self.nested_helpers,
            "supplied_shared_index_mappings": self.shm_mappings,
            "shared_index_dirty_bytes_quantified": False,
            "shared_index_dirty_bytes": None,
            "truncate_attempts": self.truncations,
            "namespace_attempts": self.namespace_attempts,
            "full_sqlite_byte_attribution_complete": False,
            "physical_device_bytes": None,
            "parent_reaping_authenticated": False,
            "rsp131_qualified": False,
        }

    def attribute(self) -> None:
        logical: dict[tuple[int, int], int] = {}
        closed: set[tuple[int, int]] = set()
        successful: set[tuple[int, int]] = set()
        for context in sorted(self.contexts.values(), key=lambda row: row.first):
            entry = context.entry
            task = self.tasks.get(entry.task)
            require(task is not None and not task.controller, "sqlite_context_task_unproved")
            assert task is not None
            epoch_candidates = [
                r.extra[4]
                for r in self.stream.records
                if r.kind in ("task_birth", "task_exec")
                and r.task == entry.task
                and r.ordinal < entry.ordinal
                and r.mm == entry.mm
            ]
            require(bool(epoch_candidates), "sqlite_context_epoch_unproved")
            epoch = epoch_candidates[-1]
            method, role, token = entry.args[1:4]
            key = (epoch, token)
            if method == 1:
                require(role in ROLES and key not in logical, "sqlite_open_identity_invalid")
                logical[key] = role
                if context.returned.result == 0:
                    successful.add(key)
            elif method != 20:
                require(logical.get(key) == role and key not in closed, "sqlite_method_before_open_or_role_changed")
                if method == 2:
                    closed.add(key)
                else:
                    require(key in successful, "sqlite_method_after_failed_open")
        self.open_handles = len(successful - closed)
        for r in self.stream.records:
            if r.context and r.file_cookie:
                require(r.context in self.contexts, "held_file_context_unknown")
                self.files[r.file_cookie].selected = True
        for call in self.stream.intervals:
            if call.entry.kind != "syscall" or call.entry.args[0] not in IO_SYSCALLS:
                continue
            inside = [
                h
                for h in self.stream.intervals
                if h.entry.kind == "hook"
                and h.entry.hook in IO_HOOKS
                and h.entry.task == call.entry.task
                and call.contains(h)
            ]
            outer = [h for h in inside if not any(p is not h and p.contains(h) for p in inside)]
            require(len(outer) <= 1, "multiple_outer_helpers")
            if not call.entry.context:
                require(
                    not any(h.entry.file_cookie and self.files[h.entry.file_cookie].selected for h in inside),
                    "selected_io_outside_sqlite_context",
                )
                continue
            context = self.contexts.get(call.entry.context)
            require(context is not None and context.contains(call), "syscall_context_interval_disagrees")
            assert context is not None
            require(
                call.returned.result >= -4095 and call.returned.result not in (-512, -513, -514, -516),
                "restart_or_unknown_error_normalization",
            )
            if not outer:
                require(call.returned.result < 0, "positive_io_without_held_file")
                self.unknown_failed_attempts += 1
                continue
            selected = outer[0]
            require(selected.entry.hook == IO_SYSCALLS[call.entry.args[0]], "syscall_helper_disagrees")
            require(
                selected.entry.context == call.entry.context and selected.returned.result == call.returned.result,
                "syscall_helper_result_disagrees",
            )
            if call.entry.args[0] == 328:
                require(
                    selected.entry.args[4] & 0xFFFFFFFF == call.entry.args[6] & 0xFFFFFFFF, "pwritev2_flags_disagree"
                )
            if call.entry.args[0] in (74, 75):
                require(selected.entry.args[3] == int(call.entry.args[0] == 75), "sync_mode_disagrees")
            require(call.returned.result not in (-512, -513, -514, -516), "restart_normalization_unavailable")
            file = self.files.get(selected.entry.file_cookie)
            require(
                file is not None
                and file.origin == "observed_constructor"
                and file.birth < selected.first
                and (not file.retired or selected.last < file.retired),
                "held_file_lifetime_unproved",
            )
            assert file is not None
            require(file.inode != 0 and selected.entry.inode_cookie == file.inode, "held_inode_unproved")
            file.selected = True
            self.descriptor_binding(call, selected)
            kind = self.inodes[file.inode][3]
            role = context.entry.args[2]
            require(role in ROLES and kind in (REGULAR, DIRECTORY), "selected_file_role_or_type_unknown")
            require(kind != DIRECTORY or selected.entry.hook == "vfs_fsync_range", "directory_write_unavailable")
            name = "directory_sync" if kind == DIRECTORY else ROLES[role]
            row = self.rows.setdefault(name, Counter())
            row["attempts"] += 1
            row["failed_attempts"] += int(call.returned.result < 0)
            if selected.entry.hook == "vfs_fsync_range":
                require(call.returned.result <= 0, "sync_result_invalid")
                row["successful_syncs"] += int(call.returned.result == 0)
            elif call.returned.result >= 0:
                if call.entry.args[0] in (1, 18):
                    require(call.returned.result <= call.entry.args[3], "write_return_exceeds_request")
                row["positive_return_bytes"] += call.returned.result
            self.nested_helpers += len(inside) - len(outer)
        self.mapping_and_namespace_controls()

    def descriptor_binding(self, call: Interval, helper: Interval, fd: int | None = None) -> None:
        candidates = [
            table
            for pointer, table in self.table_history
            if pointer == call.entry.table
            and table.birth < call.first
            and (not table.closed_at or call.first < table.closed_at)
        ]
        require(len(candidates) == 1, "io_descriptor_table_unproved")
        table = candidates[0]
        require(not table.closed_at or call.last < table.closed_at, "io_crosses_table_retirement")
        fd = (call.entry.args[1] if fd is None else fd) & 0xFFFFFFFF
        require(fd < 256, "io_descriptor_outside_bound")
        state = table.initial.get(fd, Slot(0, False, False))
        possible = {state.cookie}
        for first, last, changed_fd, before, after in sorted(table.changes, key=lambda change: change[0]):
            if changed_fd != fd:
                continue
            if last < call.first:
                state = after
                possible = {after.cookie}
            elif first < helper.first:
                possible.update((before.cookie, after.cookie))
        require(helper.entry.file_cookie in possible, "io_held_file_not_in_descriptor_lifetime")

    def mapping_and_namespace_controls(self) -> None:
        for call in self.calls.values():
            entry = call.entry
            if entry.hook in ("vfs_rename", "vfs_unlink") and entry.context:
                require(entry.inode_cookie in self.inodes, "namespace_inode_unproved")
                require(
                    entry.hook != "vfs_rename" or not entry.extra[0] or entry.extra[1] in self.inodes,
                    "rename_replacement_inode_unknown",
                )
                self.namespace_attempts += 1
            if entry.hook == "do_truncate" and entry.context:
                require(
                    entry.file_cookie in self.files and self.files[entry.file_cookie].origin == "observed_constructor",
                    "truncate_held_file_unproved",
                )
                self.truncations += 1
            if entry.hook == "mprotect_fixup" and entry.file_cookie and call.returned.result == 0:
                require(not (entry.args[6] & 2 and entry.args[6] & 8), "writable_file_protection_change_unavailable")
            if entry.hook != "do_mmap" or not entry.args[0] or call.returned.result < 0:
                continue
            writable_shared = bool(entry.args[3] & 2) and (entry.args[4] & 15) in (1, 3)
            if not writable_shared:
                file = self.files.get(entry.file_cookie)
                require(not entry.context and not (file and file.selected), "sqlite_data_mapping_outside_shm")
                continue
            context = self.contexts.get(entry.context)
            require(
                context is not None and context.entry.args[1] == 14 and context.contains(call),
                "writable_mapping_outside_shm",
            )
            assert context is not None
            syscalls = [
                s
                for s in self.stream.intervals
                if s.entry.kind == "syscall"
                and s.entry.args[0] == 9
                and s.entry.task == entry.task
                and s.contains(call)
            ]
            require(
                len(syscalls) == 1
                and syscalls[0].entry.context == entry.context
                and syscalls[0].returned.result == call.returned.result,
                "mapping_syscall_unproved",
            )
            syscall = syscalls[0]
            require(syscall.entry.args[2:5] == entry.args[2:5], "mapping_syscall_scalars_disagree")
            self.descriptor_binding(syscall, call, syscall.entry.args[5])
            vmas = [
                v
                for v in self.calls.values()
                if v.entry.hook == "uprobe_mmap" and v.entry.task == entry.task and call.contains(v)
            ]
            require(len(vmas) == 1 and vmas[0].returned.result == 0, "final_vma_unproved")
            vma = vmas[0].entry
            file = self.files.get(vma.file_cookie)
            require(
                file is not None and file.origin == "observed_constructor" and vma.file_cookie == entry.file_cookie,
                "mapped_file_replaced_or_unproved",
            )
            assert file is not None
            begin = call.returned.result & U64
            # Exact target profile must bind the page size. The first supported
            # source profile is x86_64 with 4096-byte base pages only.
            page = TARGET_LAYOUT["base_page_bytes"]
            length = (entry.args[2] + page - 1) & ~(page - 1)
            require(0 < length <= U64 and begin + length <= U64 and begin % page == 0, "mapped_range_overflow")
            require(
                vma.extra[0] == entry.mm and vma.extra[1] <= begin < begin + length <= vma.extra[2],
                "mapped_vma_range_disagrees",
            )
            require(bool(vma.extra[3] & 2 and vma.extra[3] & 8), "mapped_vma_not_writable_shared")
            self.shm_mappings += 1
