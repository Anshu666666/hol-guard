"""Disposable real-SQLite child for syscall-observer feasibility controls.

This program never opens a Guard store or imports the installed application.
Only its caller's freshly created private directory is used.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import sqlite3
import sys
import threading
from pathlib import Path

PAYLOAD_SENTINEL = b"rsp131-private-value-never-in-observer-report"
_stage = "root_validation"


def process_identity() -> dict[str, int]:
    fields = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
    return {
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "process_group": os.getpgrp(),
        "start_ticks": int(fields[19]),
    }


def sqlite_control(root: Path) -> dict[str, object]:
    database = root / "sqlite-control.db"
    with sqlite3.connect(database) as connection:
        source_id = connection.execute("select sqlite_source_id()").fetchone()[0]
        options = sorted(row[0] for row in connection.execute("pragma compile_options"))
        mode = connection.execute("pragma journal_mode=WAL").fetchone()[0]
        connection.execute("pragma synchronous=FULL")
        connection.execute("create table proof (id integer primary key, value blob not null)")
        connection.execute("insert into proof values (1, ?)", (PAYLOAD_SENTINEL * 128,))
    connection.close()
    failures: list[str] = []
    tids: list[int] = []

    def writer(index: int) -> None:
        tids.append(threading.get_native_id())
        try:
            with sqlite3.connect(database, timeout=2) as connection:
                connection.execute("pragma synchronous=FULL")
                for offset in range(3):
                    connection.execute("insert into proof values (?, ?)", (index * 10 + offset, PAYLOAD_SENTINEL))
                    connection.commit()
            connection.close()
        except Exception as error:
            failures.append(type(error).__name__)

    workers = [threading.Thread(target=writer, args=(index,)) for index in (1, 2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=3)
    if any(worker.is_alive() for worker in workers):
        raise RuntimeError("sqlite control worker did not stop")
    with sqlite3.connect(database) as connection:
        rows = connection.execute("select id, hex(value) from proof order by id").fetchall()
        checkpoint = tuple(connection.execute("pragma wal_checkpoint(TRUNCATE)").fetchone())
    connection.close()
    readonly = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
    readonly_error = None
    try:
        readonly.execute("insert into proof values (99, ?)", (PAYLOAD_SENTINEL,))
    except sqlite3.OperationalError as error:
        readonly_error = getattr(error, "sqlite_errorcode", None)
    finally:
        readonly.close()
    return {
        "sqlite_version": sqlite3.sqlite_version,
        "sqlite_source_id": source_id,
        "compile_options_sha256": hashlib.sha256(json.dumps(options).encode()).hexdigest(),
        "journal_mode": mode,
        "rows": len(rows),
        "row_digest": hashlib.sha256(json.dumps(rows).encode()).hexdigest(),
        "checkpoint": checkpoint,
        "readonly_error": readonly_error,
        "thread_ids": sorted(tids),
        "worker_failures": failures,
    }


def descriptor_control(root: Path) -> dict[str, object]:
    first = os.open(root / "descriptor-a", os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    first_info = os.fstat(first)
    duplicated = os.dup(first)
    written = os.write(first, PAYLOAD_SENTINEL)
    os.fsync(duplicated)
    os.close(first)
    second = os.open(root / "descriptor-b", os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    second_info = os.fstat(second)
    positioned = os.pwrite(second, PAYLOAD_SENTINEL, 7)
    os.fdatasync(second)
    os.close(second)
    os.close(duplicated)
    invalid_descriptor = os.dup(1)
    os.close(invalid_descriptor)
    failure = None
    try:
        # CPython rejects negative descriptors before entering the kernel.
        # This closed nonnegative descriptor reaches a real failing syscall.
        os.fsync(invalid_descriptor)
    except OSError as error:
        failure = error.errno
    return {
        "first_fd": first,
        "duplicate_fd": duplicated,
        "second_fd": second,
        "fd_reused": first == second,
        "first_identity": [first_info.st_dev, first_info.st_ino],
        "second_identity": [second_info.st_dev, second_info.st_ino],
        "write_bytes": written,
        "pwrite_bytes": positioned,
        "expected_bytes": len(PAYLOAD_SENTINEL),
        "invalid_sync_errno": failure,
        "invalid_sync_fd": invalid_descriptor,
        "invalid_sync_expected": errno.EBADF,
    }


def main() -> int:
    global _stage
    root = Path(sys.argv[1])
    if not root.is_absolute() or not root.is_dir() or any(root.iterdir()):
        raise ValueError("control root must be a fresh private directory")
    _stage = "process_identity"
    report: dict[str, object] = {"identity": process_identity()}
    _stage = "sqlite_controls"
    report["sqlite"] = sqlite_control(root)
    _stage = "descriptor_controls"
    report["descriptors"] = descriptor_control(root)
    _stage = "report"
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"child_failure": type(error).__name__, "stage": _stage}))
        raise SystemExit(1) from None
