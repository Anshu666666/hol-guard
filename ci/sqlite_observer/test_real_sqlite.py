"""Finite real SQLite controls, separated from every installed workload."""

from __future__ import annotations

import argparse
import concurrent.futures
import ctypes
import gc
import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path

from bind_loaded_sqlite import BoundObserver, ObserverUnavailableError, require


class File(ctypes.Structure):
    _fields_ = [("methods", ctypes.c_void_p)]


class IoPrefix(ctypes.Structure):
    _fields_ = [("version", ctypes.c_int)] + [
        (name, ctypes.c_void_p) for name in ("close", "read", "write", "truncate", "sync", "file_size")
    ]


def core_file_controls(bound: BoundObserver, directory: Path, observed: bool) -> dict[str, bool]:
    handle = bound.handle
    opening, execute, closing = handle.sqlite3_open_v2, handle.sqlite3_exec, handle.sqlite3_close
    control, freeing = handle.sqlite3_file_control, handle.sqlite3_free
    opening.argtypes, opening.restype = (
        [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_int, ctypes.c_char_p],
        ctypes.c_int,
    )
    execute.argtypes, execute.restype = (
        [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p],
        ctypes.c_int,
    )
    closing.argtypes, closing.restype = [ctypes.c_void_p], ctypes.c_int
    control.argtypes, control.restype = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p], ctypes.c_int
    freeing.argtypes, freeing.restype = [ctypes.c_void_p], None
    db = ctypes.c_void_p()
    require(opening(os.fsencode(directory / "core.db"), ctypes.byref(db), 6, None) == 0, "finite_core_open")
    try:
        require(
            execute(
                db,
                b"PRAGMA journal_mode=DELETE; PRAGMA cache_size=1; "
                b"CREATE TABLE t(v); BEGIN IMMEDIATE; "
                b"INSERT INTO t VALUES(zeroblob(90000));",
                None,
                None,
                None,
            )
            == 0,
            "finite_core_setup",
        )
        for opcode in (7, 28):  # FILE_POINTER and JOURNAL_POINTER, handled by core.
            file_pointer = ctypes.c_void_p()
            require(
                control(db, b"main", opcode, ctypes.byref(file_pointer)) == 0 and bool(file_pointer.value),
                "finite_core_file_pointer",
            )
            file = File.from_address(file_pointer.value)
            methods = IoPrefix.from_address(file.methods)
            require(methods.version in (1, 2, 3) and bool(methods.file_size), "finite_core_file_methods")
            size = ctypes.c_longlong()
            before = bound.snapshot()["markers"][7][1]
            function = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_longlong))(
                methods.file_size
            )
            require(
                function(file_pointer, ctypes.byref(size)) == 0 and size.value >= 0, "finite_core_file_pointer_usable"
            )
            after = bound.snapshot()["markers"][7][1]
            require(after - before == int(observed), "finite_core_pointer_bypasses_wrapper")
        vfs_pointer = ctypes.c_void_p()
        require(
            control(db, b"main", 27, ctypes.byref(vfs_pointer)) == 0 and vfs_pointer.value == bound.find(None),
            "finite_core_vfs_pointer",
        )
        name_pointer = ctypes.c_void_p()
        require(
            control(db, b"main", 12, ctypes.byref(name_pointer)) == 0 and bool(name_pointer.value),
            "finite_core_vfs_name",
        )
        try:
            name = ctypes.string_at(name_pointer.value, 4)
            require(name == b"unix", "finite_core_delegated_vfs_name")
        finally:
            freeing(name_pointer)
        require(control(db, b"main", 99999, None) == 12, "finite_core_unknown_file_control")
        require(execute(db, b"ROLLBACK;", None, None, None) == 0, "finite_core_rollback")
    finally:
        require(closing(db) == 0, "finite_core_close")
    return {
        "file_pointer_usable": True,
        "journal_pointer_usable": True,
        "core_vfs_pointer_is_default": True,
        "vfsname_preserves_delegate": True,
        "unknown_file_control_preserved": True,
    }


def scenario(directory: Path, name: str, mode: str, specimen: str) -> dict[str, object]:
    path = directory / name
    connection = sqlite3.connect(path, timeout=0)
    try:
        require(connection.execute("PRAGMA journal_mode=" + mode).fetchone()[0] == mode.lower(), "finite_journal_mode")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT)")
        connection.executemany("INSERT INTO records(value) VALUES (?)", [(specimen + str(i),) for i in range(32)])
        connection.commit()
        before = connection.execute("SELECT count(*),sum(id) FROM records").fetchone()
        connection.execute("INSERT INTO records(value) VALUES (?)", (specimen,))
        connection.rollback()
        require(
            connection.execute("SELECT count(*),sum(id) FROM records").fetchone() == before, "finite_rollback_readback"
        )
        reader = sqlite3.connect(path, timeout=0)
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                reader.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as error:
                busy_code = error.sqlite_errorcode
            else:
                raise ObserverUnavailableError("finite_busy_missing")
            require(busy_code == sqlite3.SQLITE_BUSY, "finite_busy_category")
            connection.rollback()
            require(
                reader.execute("SELECT count(*) FROM records").fetchone()[0] == 32, "finite_second_connection_readback"
            )
        finally:
            reader.close()
        if mode == "WAL":
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            require(checkpoint == (0, 0, 0), "finite_checkpoint")
        # Exercise fetch/unfetch capability without claiming mmap dirty bytes.
        connection.execute("PRAGMA mmap_size=1048576")
        require(connection.execute("SELECT count(value) FROM records").fetchone()[0] == 32, "finite_mmap_readback")
        readonly = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0)
        try:
            try:
                readonly.execute("INSERT INTO records(value) VALUES (?)", (specimen,))
            except sqlite3.OperationalError as error:
                readonly_code = error.sqlite_errorcode
            else:
                raise ObserverUnavailableError("finite_readonly_missing")
            require(readonly_code == sqlite3.SQLITE_READONLY, "finite_readonly_category")
        finally:
            readonly.close()
        require(connection.execute("PRAGMA integrity_check").fetchone() == ("ok",), "finite_integrity")
    finally:
        connection.close()
    renamed = directory / (name + ".renamed")
    path.rename(renamed)  # After all handles close; no live-inode identity claim.
    check = sqlite3.connect(renamed)
    try:
        require(check.execute("SELECT count(*) FROM records").fetchone()[0] == 32, "finite_rename_reopen")
    finally:
        check.close()
    renamed.unlink()
    return {
        "rows": 32,
        "id_sum": 528,
        "busy_code": busy_code,
        "readonly_code": readonly_code,
        "rollback_preserved": True,
        "integrity_ok": True,
        "closed_rename_reopen": True,
    }


def run(shim: Path, observed: bool, variant: int) -> dict[str, object]:
    bound = BoundObserver(shim, hashlib.sha256(shim.read_bytes()).hexdigest())
    if observed:
        bound.install(
            {
                key: bound.metadata[key]
                for key in ("sqlite_version", "sqlite_source_id", "sqlite_image_sha256", "python_extension_sha256")
            }
        )
    try:
        with tempfile.TemporaryDirectory(prefix="hol-vfs-component-private-") as raw:
            root = Path(raw)
            specimen = "finite_only_private_sql_value_A" if variant == 0 else "different_private_sql_value_Z"
            results = {
                mode: scenario(root, mode + str(variant), mode, specimen) for mode in ("DELETE", "PERSIST", "WAL")
            }
            core = core_file_controls(bound, root, observed)
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(scenario, root, "thread" + str(i), "WAL", specimen) for i in range(4)]
                threaded = [future.result() for future in futures]
            require(all(value == results["WAL"] for value in threaded), "finite_threaded_results")
            try:
                sqlite3.connect(root / "absent" / "database")
            except sqlite3.OperationalError as error:
                require(error.sqlite_errorcode == sqlite3.SQLITE_CANTOPEN, "finite_failed_open_category")
            else:
                raise ObserverUnavailableError("finite_failed_open_missing")
        gc.collect()
        bound.validate_loaded_binding()
        snapshot = bound.snapshot()
        require(snapshot["incomplete"] == 0 and snapshot["active_files"] == 0, "finite_observer_incomplete")
        require(all(row[1] == row[2] for row in snapshot["markers"]), "finite_marker_conservation")
        if observed:
            require(
                snapshot["markers"][4][1] > 0
                and snapshot["markers"][6][1] > 0
                and snapshot["markers"][11][3] > 0
                and snapshot["markers"][11][3] == snapshot["markers"][11][4],
                "finite_expected_markers_missing",
            )
        else:
            require(all(all(n == 0 for n in row) for row in snapshot["markers"]), "finite_unregistered_markers")
        # Public data is allowlisted; no raw filenames, SQL, addresses, PIDs,
        # error strings or specimen values are written to this report.
        return {
            "schema": "hol_sqlite_real_component_controls_v1",
            "arm": "shim" if observed else "plain",
            "variant": variant,
            "binding": bound.metadata,
            "logical_results": results,
            "core_file_controls": core,
            "threaded_connections": 4,
            "failed_open_category_preserved": True,
            "snapshot": snapshot,
            "observer_overhead_measured": False,
            "installed_equivalence_claimed": False,
        }
    finally:
        if observed:
            bound.uninstall()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--shim", type=Path, required=True)
    parser.add_argument("--observed", action="store_true")
    parser.add_argument("--variant", type=int, choices=(0, 1), default=0)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.shim.resolve(), args.observed, args.variant), sort_keys=True, separators=(",", ":")))
    except ObserverUnavailableError as error:
        print(json.dumps({"status": "unavailable", "reason": str(error)}))
        raise SystemExit(1) from None
    except Exception:
        print(json.dumps({"status": "unavailable", "reason": "component_control_error"}))
        raise SystemExit(1) from None
