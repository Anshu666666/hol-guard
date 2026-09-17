"""Darwin raw CPU counters; no process data is public evidence.

ABI/units/rollup are pinned in docs/guard/rust-performance/darwin-resource-accounting.md.
CPU counters use Mach ticks, including on ARM; they are not nanoseconds.
Ignored-child usage can be rolled up twice; these counters do not prove tree CPU.
"""

from __future__ import annotations

import ctypes
import errno
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol, cast

_RUSAGE_INFO_V2 = 2
_RUSAGE_BYTES = 160
REAPED_CPU_UNAVAILABLE = "darwin_reaped_cpu_ambiguous"


class _RusageInfoV2(ctypes.Structure):
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [
        (name, ctypes.c_uint64)
        for name in (
            "user_time",
            "system_time",
            "pkg_idle_wkups",
            "interrupt_wkups",
            "pageins",
            "wired_size",
            "resident_size",
            "phys_footprint",
            "proc_start_abstime",
            "proc_exit_abstime",
            "child_user_time",
            "child_system_time",
            "child_pkg_idle_wkups",
            "child_interrupt_wkups",
            "child_pageins",
            "child_elapsed_abstime",
            "diskio_bytesread",
            "diskio_byteswritten",
        )
    ]


class _Timebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


class _Function(Protocol):
    argtypes: list[object]
    restype: object

    def __call__(self, *arguments: object) -> int: ...


class _Libproc(Protocol):
    proc_pid_rusage: _Function


class _System(Protocol):
    mach_timebase_info: _Function


class DarwinCpuUnavailableError(RuntimeError):
    """Only fixed codes, never errno text, paths or process identifiers."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@lru_cache(maxsize=1)
def _api() -> tuple[_Libproc, _System]:
    if sys.platform != "darwin":
        raise DarwinCpuUnavailableError("platform_unsupported")
    if ctypes.sizeof(_RusageInfoV2) != _RUSAGE_BYTES or ctypes.sizeof(_Timebase) != 8:
        raise DarwinCpuUnavailableError("darwin_cpu_abi_invalid")
    try:
        proc = cast(_Libproc, cast(object, ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)))
        system = cast(_System, cast(object, ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)))
        # rusage_info_t is void*. The C API's pointer is used as the address of
        # caller-owned struct storage, not as an output pointer allocation.
        proc.proc_pid_rusage.argtypes = [ctypes.c_int32, ctypes.c_int32, ctypes.c_void_p]
        proc.proc_pid_rusage.restype = ctypes.c_int32
        system.mach_timebase_info.argtypes = [ctypes.POINTER(_Timebase)]
        system.mach_timebase_info.restype = ctypes.c_int32
    except (OSError, AttributeError) as error:
        raise DarwinCpuUnavailableError("platform_unsupported") from error
    return proc, system


@dataclass(frozen=True)
class DarwinProcessCpu:
    start: int
    user: int
    system: int
    child_user: int
    child_system: int

    @property
    def ticks(self) -> int:
        return self.user + self.system + self.child_user + self.child_system


@dataclass(frozen=True)
class DarwinTreeCpu:
    """Private raw counter snapshot, not a proof of complete descendant CPU."""

    root: tuple[int, float, int]
    ticks: int
    numer: int
    denom: int
    members: tuple[tuple[tuple[int, float], DarwinProcessCpu], ...] = ()

    def seconds_since(self, earlier: DarwinTreeCpu) -> float:
        if self.root != earlier.root:
            raise DarwinCpuUnavailableError("darwin_cpu_root_changed")
        if (self.numer, self.denom) != (earlier.numer, earlier.denom):
            raise DarwinCpuUnavailableError("darwin_cpu_timebase_changed")
        if self.ticks < earlier.ticks:
            raise DarwinCpuUnavailableError("darwin_cpu_counter_regressed")
        previous = dict(earlier.members)
        for identity, current in self.members:
            prior = previous.get(identity)
            if prior is None:
                continue
            if prior.start != current.start:
                raise DarwinCpuUnavailableError("darwin_cpu_process_changed")
            if any(
                after < before
                for before, after in zip(
                    (prior.user, prior.system, prior.child_user, prior.child_system),
                    (current.user, current.system, current.child_user, current.child_system),
                    strict=True,
                )
            ):
                raise DarwinCpuUnavailableError("darwin_cpu_counter_regressed")
        # Exact integer difference/product before conversion (including >2**53).
        return ((self.ticks - earlier.ticks) * self.numer) / (self.denom * 1_000_000_000)


def timebase() -> tuple[int, int]:
    _, system = _api()
    result = _Timebase()
    if system.mach_timebase_info(ctypes.byref(result)) != 0 or not result.numer or not result.denom:
        raise DarwinCpuUnavailableError("darwin_cpu_timebase_unavailable")
    return result.numer, result.denom


def process_cpu(pid: int) -> DarwinProcessCpu:
    if type(pid) is not int or not 0 < pid < 2**31:
        raise DarwinCpuUnavailableError("darwin_cpu_pid_invalid")
    proc, _ = _api()
    result = _RusageInfoV2()
    ctypes.set_errno(0)
    if proc.proc_pid_rusage(pid, _RUSAGE_INFO_V2, ctypes.byref(result)) != 0:
        code = {
            errno.EACCES: "permission_denied",
            errno.EPERM: "permission_denied",
            errno.ESRCH: "darwin_cpu_process_missing",
            errno.EINVAL: "platform_unsupported",
            errno.ENOSYS: "platform_unsupported",
            errno.ENOTSUP: "platform_unsupported",
        }.get(ctypes.get_errno(), "darwin_cpu_query_failed")
        raise DarwinCpuUnavailableError(code)
    if not result.proc_start_abstime:
        raise DarwinCpuUnavailableError("darwin_cpu_start_invalid")
    # Ignored-SIGCHLD children can roll up before disappearance. Counting that
    # zombie and the parent's child fields would count the same CPU twice.
    if result.proc_exit_abstime:
        raise DarwinCpuUnavailableError("darwin_cpu_process_exiting")
    return DarwinProcessCpu(
        result.proc_start_abstime,
        result.user_time,
        result.system_time,
        result.child_user_time,
        result.child_system_time,
    )


def stable_tree_cpu(
    root_pid: int,
    before: Mapping[tuple[int, float], DarwinProcessCpu],
    after: Mapping[tuple[int, float], DarwinProcessCpu],
    first_timebase: tuple[int, int],
    last_timebase: tuple[int, int],
) -> DarwinTreeCpu:
    if not before or set(before) != set(after):
        raise DarwinCpuUnavailableError("darwin_cpu_inventory_changed")
    if first_timebase != last_timebase:
        raise DarwinCpuUnavailableError("darwin_cpu_timebase_changed")
    for identity, first in before.items():
        last = after[identity]
        if first.start != last.start:
            raise DarwinCpuUnavailableError("darwin_cpu_process_changed")
        if last.user < first.user or last.system < first.system:
            raise DarwinCpuUnavailableError("darwin_cpu_counter_regressed")
        if (first.child_user, first.child_system) != (last.child_user, last.child_system):
            raise DarwinCpuUnavailableError("darwin_cpu_reap_during_snapshot")
    roots = [identity for identity in before if identity[0] == root_pid]
    if len(roots) != 1:
        raise DarwinCpuUnavailableError("darwin_cpu_root_missing")
    root = roots[0]
    return DarwinTreeCpu(
        (*root, before[root].start), sum(item.ticks for item in before.values()), *first_timebase, tuple(before.items())
    )
