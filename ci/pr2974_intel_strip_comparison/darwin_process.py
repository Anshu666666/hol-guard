"""Read owned-user process identities from Darwin's public libproc interface."""

from __future__ import annotations

import ctypes
import errno
import os
import sys

from common import require

# Public xnu bsd/sys/proc_info.h proc_bsdinfo; LP64 field sizes are asserted.
class BsdInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid",
        "svuid", "svgid", "reserved",
    )] + [
        ("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32),
        ("nfiles", ctypes.c_uint32), ("pgid", ctypes.c_uint32), ("jobc", ctypes.c_uint32),
        ("tty", ctypes.c_uint32), ("tty_pgid", ctypes.c_uint32), ("nice", ctypes.c_int32),
        ("start_seconds", ctypes.c_uint64), ("start_microseconds", ctypes.c_uint64),
    ]


def library():
    require(sys.platform == "darwin" and ctypes.sizeof(BsdInfo) == 136, "Darwin libproc ABI mismatch")
    value = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    value.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
    value.proc_listpids.restype = ctypes.c_int
    value.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                  ctypes.c_void_p, ctypes.c_int]
    value.proc_pidinfo.restype = ctypes.c_int
    return value


def identity(pid: int, lib=None) -> dict | None:
    require(os.getuid() == os.geteuid(), "Real/effective UID mismatch")
    # PROC_PIDTBSDINFO arg=1 includes the unreaped zombie held by WNOWAIT.
    lib = lib or library()
    row = BsdInfo()
    ctypes.set_errno(0)
    count = lib.proc_pidinfo(pid, 3, 1, ctypes.byref(row), ctypes.sizeof(row))
    if count == 0 and ctypes.get_errno() == errno.ESRCH:
        return None
    require(count == ctypes.sizeof(row), "Incomplete owned process identity: " + str(pid))
    require(row.pid == pid and row.uid == os.geteuid(), "Owned process UID/PID changed")
    return {"pid": pid, "ppid": row.ppid, "pgid": row.pgid, "uid": row.uid,
            "status": row.status, "start_seconds": row.start_seconds,
            "start_microseconds": row.start_microseconds,
            "command_name_hex": bytes(row.comm).hex(), "registered_name_hex": bytes(row.name).hex()}


def key(row: dict) -> tuple:
    return row["pid"], row["uid"], row["start_seconds"], row["start_microseconds"]


def census() -> dict[int, dict]:
    lib = library()
    storage = (ctypes.c_int * 32768)()
    # PROC_UID_ONLY enumerates the effective UID; no unrelated users are inspected.
    count = lib.proc_listpids(4, os.geteuid(), storage, ctypes.sizeof(storage))
    require(0 <= count < ctypes.sizeof(storage) and count % ctypes.sizeof(ctypes.c_int) == 0,
            "Owned process census overflow or ABI mismatch")
    pids = [pid for pid in storage[:count // ctypes.sizeof(ctypes.c_int)] if pid > 0]
    require(len(pids) == len(set(pids)), "Duplicate process census PID")
    rows = {}
    for pid in pids:
        row = identity(pid, lib)
        if row is not None:
            rows[pid] = row
    require(os.getpid() in rows, "Observer missing from owned process census")
    return rows
