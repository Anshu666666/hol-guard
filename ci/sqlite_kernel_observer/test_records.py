"""Finite private-wire semantics. Never load BPF, trace or import Guard."""

from __future__ import annotations

import copy
import json
import random
from dataclasses import replace
from typing import Any, cast

if __package__:
    from .records import (
        CONSTRUCTORS,
        HOOKS,
        KINDS,
        REASONS,
        TOTAL_FIELDS,
        WIRE,
        Interval,
        Record,
        StreamError,
        decode_stream,
        pointer_result,
    )
    from .reducer import Reducer
else:
    from records import (  # pyright: ignore[reportImplicitRelativeImport]
        CONSTRUCTORS,
        HOOKS,
        KINDS,
        REASONS,
        TOTAL_FIELDS,
        WIRE,
        Interval,
        Record,
        StreamError,
        decode_stream,
        pointer_result,
    )
    from reducer import Reducer  # pyright: ignore[reportImplicitRelativeImport]


KIND_ID = {name: value for value, name in KINDS.items()}


class Fixture:
    def __init__(self, variant=0):
        self.rows: list[dict[str, Any]] = []
        self.shift = variant * 0x1000000
        self.controller = self.ptr(0x1000)
        self.child = self.ptr(0x2000)
        self.mm = self.ptr(0x4000)
        self.table = self.ptr(0x6000)
        self.context = 0
        self.task = self.controller
        self.file_data: dict[int, dict[str, Any]] = {}

    def ptr(self, value):
        return value + self.shift

    def add(self, kind, phase=3, hook="none", **values):
        row: dict[str, Any] = dict(
            kind=kind,
            phase=phase,
            hook=hook,
            flags=0,
            ordinal=len(self.rows) + 1,
            call=0,
            task=self.task,
            mm=self.mm,
            table=self.table,
            result=0,
            args=[0] * 9,
            file_cookie=0,
            inode_cookie=0,
            file=0,
            inode=0,
            device=0,
            inumber=0,
            mode=0,
            context=self.context,
            extra=[0] * 5,
        )
        row.update(values)
        row["args"] = list(row["args"]) + [0] * (9 - len(row["args"]))
        row["extra"] = list(row["extra"]) + [0] * (5 - len(row["extra"]))
        self.rows.append(row)
        return row

    def begin(self, hook, args=(), **values):
        row = self.add("hook", 1, hook, args=args, **values)
        row["call"] = row["ordinal"]
        return row

    def end(self, entry, result=0, **values):
        return self.add(
            "hook",
            2,
            entry["hook"],
            call=entry["call"],
            args=entry["args"],
            task=entry["task"],
            mm=entry["mm"],
            table=entry["table"],
            context=entry["context"],
            result=result,
            **values,
        )

    def marker(self, phase, method, token=90, role=1, result=0):
        row = self.add("marker", args=(phase, method, role, token, 0), result=result)
        if phase == 1:
            self.context = row["ordinal"]
            row["context"] = self.context
        elif phase == 2:
            self.context = 0
        return row

    def details(self, cookie):
        return dict(self.file_data[cookie])

    def snapshot(self, call, mode, slots, refs):
        self.add("snapshot", 1, call=call["call"], args=(mode, len(slots), self.ptr(0x7000), refs))
        for fd, (cookie, cloexec) in enumerate(slots):
            self.add(
                "slot",
                call=call["call"],
                args=(fd, int(bool(cookie)), int(cloexec), self.file_data[cookie]["file"] if cookie else 0, mode),
                **(self.details(cookie) if cookie else {}),
            )
        self.add("snapshot", 2, call=call["call"], args=(mode, len(slots)))

    def allocate(self, cookie, fd):
        reservation = self.begin("alloc_fd", (0, 256, 0o2000002))
        self.end(reservation, fd)
        constructor = self.begin("alloc_empty_file", (2,))
        pointer = self.ptr(0x10000 + cookie * 256)
        security = self.begin("security_file_alloc", (pointer,))
        self.end(security)
        self.end(constructor, pointer, file=pointer, file_cookie=cookie, flags=1)
        self.file_data[cookie] = dict(
            file=pointer,
            file_cookie=cookie,
            inode=self.ptr(0x20000 + cookie * 256),
            inode_cookie=cookie + 100,
            device=1 + self.shift,
            inumber=200 + cookie + self.shift,
            mode=0o100600,
            flags=1,
        )
        opening = self.begin("do_dentry_open", (pointer, self.file_data[cookie]["inode"]))
        self.end(opening)
        install = self.begin("fd_install", (fd, pointer), **self.details(cookie))
        self.end(install)

    def close_fd(self, cookie, fd):
        close = self.begin("file_close_fd_locked", (self.table, fd))
        self.end(close, self.file_data[cookie]["file"], **self.details(cookie))

    def retire_file(self, cookie):
        data = self.file_data[cookie]
        saved = {k: data[k] for k in ("file", "file_cookie", "inode", "inode_cookie", "flags")}
        self.add("hook", hook="__fput", args=(data["file"],), extra=(0,), **saved)
        self.add("hook", hook="security_file_free", args=(data["file"],), extra=(1,), **saved)

    def syscall(self, number, args):
        row = self.add("syscall", 1, args=(number, *args))
        row["call"] = row["ordinal"]
        return row

    def syscall_end(self, entry, result):
        return self.add("syscall", 2, call=entry["call"], args=entry["args"], result=result)

    def shared_writes(self, cookie, generation):
        parent, mm = self.task, self.mm
        thread = self.ptr(0x2500)
        birth = 1100 + generation
        self.task = thread
        self.add("task_birth", call=birth, args=(parent, 0, 56, 1), extra=(0, 0, 0, 0, 2002 + generation * 2))
        self.add("syscall", call=birth, args=(56,))
        self.task = parent
        self.marker(1, 4)
        first_context = self.context
        first_syscall = self.syscall(18, (1, 0, 2, 0, 0, 0))
        first_write = self.begin("vfs_write", (self.file_data[cookie]["file"], 0, 2), **self.details(cookie))
        self.task, self.context = thread, 0
        self.marker(1, 4)
        second_syscall = self.syscall(18, (1, 0, 3, 0, 0, 0))
        second_write = self.begin("vfs_write", (self.file_data[cookie]["file"], 0, 3), **self.details(cookie))
        self.end(second_write, 3)
        self.syscall_end(second_syscall, 3)
        self.marker(2, 4)
        self.mm = 0
        self.add("task_exit", call=birth)
        detach = self.begin("exit_files", (thread,))
        self.end(detach, extra=(0,))
        self.add("hook", hook="__put_task_struct", call=birth, extra=(1,))
        self.task, self.mm, self.context = parent, mm, first_context
        self.end(first_write, 2)
        self.syscall_end(first_syscall, 2)
        self.marker(2, 4)

    def build(
        self, generation=0, *, no_helper_error=None, failed_constructor=False, shared_threads=False, duplicate=False
    ):
        self.file_data[30] = dict(
            file=self.ptr(0x8000),
            file_cookie=30,
            inode=self.ptr(0x9000),
            inode_cookie=130,
            device=1 + self.shift,
            inumber=200 + self.shift,
            mode=0o100600,
            flags=2,
        )
        self.task = self.controller
        self.mm = self.ptr(0x4000)
        self.table = self.ptr(0x6000)
        main, shm = 31 + 2 * generation, 32 + 2 * generation
        if generation == 0:
            self.add("controller", call=1000, extra=(0, 0, 0, 0, 2000))
        clone = self.begin("dup_fd", (self.table, 0xFFFFFFFF))
        self.table = self.ptr(0x6100)
        self.end(clone, self.table)
        self.snapshot(clone, 1, [(30, False), (0, False), (0, False), (0, False)], 1)
        old_mm = self.mm
        self.mm = self.ptr(0x4100)
        self.task = self.child
        self.add(
            "task_birth",
            call=1001 + generation,
            args=(self.controller, 0, 56, 1),
            extra=(0, 0, 0, 0, 2001 + generation * 2),
        )
        self.add("syscall", call=1001 + generation, args=(56,), result=0)
        unshare = self.begin("unshare_files")
        self.end(unshare, extra=(self.table,))
        exec_close = self.begin("do_close_on_exec", (self.table,))
        self.snapshot(exec_close, 2, [(30, False), (0, False), (0, False), (0, False)], 2)  # temporary procfs ref
        self.end(exec_close)
        self.add("hook", hook="__mmdrop", mm=self.mm, extra=(0, 0, 0, 0, 2001 + generation * 2))
        old_mm = self.mm
        self.mm = self.ptr(0x4200)
        self.add(
            "task_exec", call=1001 + generation, args=(old_mm, self.table), extra=(0, 0, 0, 0, 2002 + generation * 2)
        )
        if failed_constructor:
            self.marker(1, 1, token=91)
            constructor = self.begin("alloc_empty_file", (2,))
            pointer = self.ptr(0xDEAD0)
            security = self.begin("security_file_alloc", (pointer,))
            cleanup = self.begin("security_file_free", (pointer,))
            self.end(cleanup)
            self.end(security, -13)
            self.end(constructor, -13)
            self.marker(2, 1, token=91, result=14)
        self.marker(1, 1)
        self.allocate(main, 1)
        self.marker(2, 1)
        if duplicate:
            self.allocate(35 + generation * 2, 3)  # unrelated owned temporary descriptor
            old = 35 + generation * 2
            dup = self.begin(
                "do_dup2",
                (self.table, self.file_data[main]["file"], 3, 0o2000000),
                extra=(self.file_data[old]["file"], 1),
                **self.details(main),
            )
            self.retire_file(old)  # source do_dup2 releases old file before return
            self.end(dup, 3)
        if no_helper_error is not None:
            self.marker(1, 4)
            failure = self.syscall(18, (999, 0, 10, 0, 0, 0))
            self.syscall_end(failure, no_helper_error)
            self.marker(2, 4, result=778)
        if shared_threads:
            self.shared_writes(main, generation)
        self.marker(1, 4)
        for amount, returned in ((10, 7), (3, 3)):
            syscall = self.syscall(18, (1, 0, amount, 0, 0, 0))
            write = self.begin("vfs_write", (self.file_data[main]["file"], 0, amount), **self.details(main))
            self.end(write, returned)
            self.syscall_end(syscall, returned)
        self.marker(2, 4)
        self.marker(1, 6)
        syscall = self.syscall(75, (1, 0, 0, 0, 0, 0))
        sync = self.begin("vfs_fsync_range", (self.file_data[main]["file"], 0, (1 << 63) - 1, 1), **self.details(main))
        self.end(sync)
        self.syscall_end(syscall, 0)
        self.marker(2, 6)
        self.marker(1, 14)
        self.allocate(shm, 2)
        syscall = self.syscall(9, (0, 32768, 3, 1, 2, 0))
        mmap = self.begin("do_mmap", (self.file_data[shm]["file"], 0, 32768, 3, 1, 0, 0), **self.details(shm))
        vma = self.begin(
            "uprobe_mmap", (self.ptr(0x30000),), extra=(self.mm, 0x0F0000, 0x110000, 3 | 8), **self.details(shm)
        )
        self.end(vma)
        self.end(mmap, 0x100000)
        self.syscall_end(syscall, 0x100000)
        self.close_fd(shm, 2)  # mapping keeps actual struct file alive
        self.marker(2, 14)
        self.marker(1, 17)
        self.retire_file(shm)
        self.marker(2, 17)
        self.marker(1, 2)
        self.close_fd(main, 1)
        if not duplicate:
            self.retire_file(main)
        self.marker(2, 2)
        if duplicate:
            self.close_fd(main, 3)
            self.retire_file(main)
        self.add("hook", hook="__mmdrop", extra=(0, 0, 0, 0, 2002 + generation * 2))
        self.mm = 0
        self.add("task_exit", call=1001 + generation)
        exiting = self.begin("exit_files", (self.child,))
        closing = self.begin("close_files", (self.table,))
        self.snapshot(closing, 3, [(30, False), (0, False), (0, False), (0, False)], 0)
        self.end(closing, self.ptr(0x7000))
        self.end(exiting, extra=(0,))
        self.add("hook", hook="__put_task_struct", call=1001 + generation, extra=(1,))
        return self


def encode(rows):
    return [
        WIRE.pack(
            1,
            256,
            KIND_ID[r["kind"]],
            r["phase"],
            HOOKS.index(r["hook"]),
            r["flags"],
            0,
            0,
            r["ordinal"],
            r["call"],
            r["task"],
            r["mm"],
            r["table"],
            r["result"],
            *r["args"],
            r["file_cookie"],
            r["inode_cookie"],
            r["file"],
            r["inode"],
            r["device"],
            r["inumber"],
            r["mode"],
            r["context"],
            *r["extra"],
        )
        for r in rows
    ]


def totals(rows):
    counters: dict[str, int] = dict.fromkeys(TOTAL_FIELDS, 0)
    counters.update(ordinal=len(rows), emitted=len(rows), next_object=3000)
    for r in rows:
        counters["task_births"] += r["kind"] == "task_birth"
        counters["file_births"] += r["hook"] in CONSTRUCTORS and r["phase"] == 2 and pointer_result(r["result"])
        counters["file_retirements"] += r["hook"] == "security_file_free" and r["phase"] == 3
        counters["inode_retirements"] += r["hook"] == "__destroy_inode" and r["phase"] == 3
        counters["marker_entries"] += r["kind"] == "marker" and r["args"][0] == 1
        counters["marker_returns"] += r["kind"] == "marker" and r["args"][0] == 2
        counters["syscall_entries"] += r["kind"] == "syscall" and r["phase"] == 1
        counters["syscall_returns"] += r["kind"] == "syscall" and r["phase"] == 2
    return counters


def reduce(rows):
    return cast(dict[str, Any], Reducer(decode_stream(encode(rows), totals(rows))).run())


def refused(call, reason=None):
    try:
        call()
    except StreamError as error:
        assert reason is None or str(error) == reason, (reason, str(error))
        assert str(error).replace("_", "").isalnum()
    else:
        raise AssertionError("finite_refusal_missing")


def controls():
    base = Fixture().build().rows
    report = reduce(base)
    assert report["selected_returned_io_model"]["main_database"]["positive_return_bytes"] == 10
    assert report["selected_returned_io_model"]["main_database"]["successful_syncs"] == 1
    assert report["supplied_shared_index_mappings"] == 1
    assert report["all_selected_files_retired_in_supplied_stream"]
    assert report["all_owned_tasks_retired_in_supplied_stream"]
    assert report["successful_open_handles_not_closed"] == 0
    assert not report["rsp131_qualified"] and not report["selected_synchronous_attribution_proved"]
    reused = reduce(Fixture().build().build(1).rows)
    assert reused["selected_returned_io_model"]["main_database"]["positive_return_bytes"] == 20
    shared = reduce(Fixture().build(shared_threads=True).rows)
    assert shared["selected_returned_io_model"]["main_database"]["positive_return_bytes"] == 15
    assert shared["all_owned_tasks_retired_in_supplied_stream"]
    assert reduce(Fixture().build(failed_constructor=True).rows) == report
    assert reduce(Fixture().build(duplicate=True).rows) == report
    for errno in (-9, -13):
        assert reduce(Fixture().build(no_helper_error=errno).rows)["failed_attempts_without_held_file"] == 1
    checks = 0
    for variant in range(1, 41):
        different = Fixture(variant).build().rows
        raw = encode(different)
        random.Random(variant).shuffle(raw)
        assert Reducer(decode_stream(raw, totals(different))).run() == report
        checks += 1
    negatives = 0
    generations = Fixture().build().build(1).rows
    model = Reducer(decode_stream(encode(generations), totals(generations)))
    model.run()
    first_io = next(i for i in model.stream.intervals if i.entry.kind == "syscall" and i.entry.args[0] == 18)
    first_helper = next(i for i in model.stream.intervals if i.entry.hook == "vfs_write" and first_io.contains(i))
    past_retirement = model.table_history[0][1].closed_at + 1
    crossing = Interval(first_io.entry, replace(first_io.returned, ordinal=past_retirement))
    refused(lambda: model.descriptor_binding(crossing, first_helper), "io_crosses_table_retirement")
    negatives += 1
    completed = Reducer(decode_stream(encode(base), totals(base)))
    completed.run()
    old_file = next(r for r in completed.stream.records if r.hook == "vfs_write" and r.phase == 1)
    refused(lambda: completed.observed_file(old_file), "file_retired_reappeared")
    negatives += 1
    retired_inode = Fixture().build()
    identity = retired_inode.file_data[31]
    retired_inode.add(
        "hook",
        hook="__destroy_inode",
        task=retired_inode.controller,
        inode=identity["inode"],
        inode_cookie=identity["inode_cookie"],
    )
    retired_model = Reducer(decode_stream(encode(retired_inode.rows), totals(retired_inode.rows)))
    retired_model.run()
    refused(lambda: retired_model.inode(old_file), "inode_retired_reappeared")
    negatives += 1
    snapshots = [r for r in base if r["kind"] == "snapshot" and r["phase"] == 1]
    rows = copy.deepcopy(base)
    for r in rows:
        if r["kind"] in ("snapshot", "slot") and r["call"] == snapshots[1]["call"]:
            r["call"] = snapshots[0]["call"]
    refused(lambda: reduce(rows), "snapshot_entry")
    negatives += 1
    for bit in range(len(REASONS)):
        counters = totals(base)
        counters["reasons"] = 1 << bit
        refused(lambda counters=counters: decode_stream(encode(base), counters), "producer_incomplete")
        negatives += 1
    for scalar, value in ((3, 1), (4, 2)):
        rows = copy.deepcopy(base)
        for r in rows:
            if r["hook"] == "do_mmap":
                r["args"][scalar] = value
        refused(lambda rows=rows: reduce(rows), "sqlite_data_mapping_outside_shm")
        negatives += 1
    for errno in (-512, -513, -514, -516, -4096, -100000):
        refused(
            lambda errno=errno: reduce(Fixture().build(no_helper_error=errno).rows),
            "restart_or_unknown_error_normalization",
        )
        negatives += 1
    for field in TOTAL_FIELDS:
        changed = totals(base)
        changed[field] += 1
        if field == "next_object":
            changed[field] = 65537
        refused(lambda changed=changed: decode_stream(encode(base), changed))
        negatives += 1
    for index in (0, 1, 23, 255, 257):
        refused(lambda index=index: Record.decode(b"\0" * index))
        negatives += 1
    for pick, change in (
        (lambda r: r["kind"] == "task_birth", lambda r: r["args"].__setitem__(0, 0xDEAD)),
        (lambda r: r["kind"] == "syscall" and r["phase"] == 3, lambda r: r.__setitem__("result", 1)),
        (lambda r: r["kind"] == "task_exec", lambda r: r["extra"].__setitem__(4, 2001)),
        (lambda r: r["hook"] == "security_file_alloc" and r["phase"] == 2, lambda r: r.__setitem__("result", -1)),
        (lambda r: r["hook"] == "alloc_empty_file" and r["phase"] == 2, lambda r: r.__setitem__("flags", 2)),
        (lambda r: r["hook"] == "fd_install" and r["phase"] == 1, lambda r: r.__setitem__("inode_cookie", 999)),
        (lambda r: r["hook"] == "vfs_write" and r["phase"] == 2, lambda r: r.__setitem__("result", 99)),
        (lambda r: r["hook"] == "vfs_fsync_range" and r["phase"] == 1, lambda r: r["args"].__setitem__(3, 0)),
        (lambda r: r["hook"] == "uprobe_mmap" and r["phase"] == 1, lambda r: r["extra"].__setitem__(2, 0x100010)),
        (lambda r: r["hook"] == "uprobe_mmap" and r["phase"] == 1, lambda r: r["extra"].__setitem__(3, 3)),
        (lambda r: r["hook"] == "security_file_free" and r["phase"] == 3, lambda r: r["extra"].__setitem__(0, 0)),
        (lambda r: r["hook"] == "__put_task_struct", lambda r: r["extra"].__setitem__(0, 0)),
        (lambda r: r["kind"] == "slot" and r["args"][0] == 1, lambda r: r["args"].__setitem__(1, 1)),
        (
            lambda r: r["kind"] == "snapshot" and r["phase"] == 1 and r["args"][0] == 3,
            lambda r: r["args"].__setitem__(3, 1),
        ),
    ):
        rows = copy.deepcopy(base)
        change(next(r for r in rows if pick(r)))
        refused(lambda rows=rows: reduce(rows))
        negatives += 1
    return {
        "schema": "hol_sqlite_kernel_wire_finite_controls_v1",
        "synthetic_records": len(base),
        "negative_controls": negatives,
        "private_identity_and_delivery_order_controls": checks,
        "positive_return_bytes": 10,
        "separate_partial_write_attempts": 2,
        "shared_mapping_survives_fd_close": True,
        "same_pointer_table_generations_with_io": 2,
        "shared_table_overlapping_writes": 2,
        "failed_constructor_cleanup_positive": True,
        "dup_replacement_retirement_before_return": True,
        "real_kernel_events_consumed": 0,
        "bpf_programs_loaded": 0,
        "probes_attached": 0,
        "rsp131_qualified": False,
    }


if __name__ == "__main__":
    print(json.dumps(controls(), sort_keys=True))
