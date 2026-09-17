"""Read-only CPU accounting for the fixture's existing retained Windows job.

The caller must stop sampling before closing the fixture. This reader neither
creates jobs nor changes containment, and never queries the caller's default job.
Microsoft's cumulative counters include exited members and nested child jobs:
https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information
"""

from __future__ import annotations

import ctypes
import os
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Protocol, cast

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.codex_hook_windows_job import WindowsHookJob

_JOB_BASIC_ACCOUNTING = 1
_ACCOUNTING_BYTES = 48


class _BasicAccounting(ctypes.Structure):
    # Windows LARGE_INTEGER is signed 64-bit and DWORD is unsigned 32-bit.
    # Fixed-width types also make the ABI assertions meaningful on Unix hosts.
    _fields_ = [
        ("total_user_time", ctypes.c_int64),
        ("total_kernel_time", ctypes.c_int64),
        ("period_user_time", ctypes.c_int64),
        ("period_kernel_time", ctypes.c_int64),
        ("page_faults", ctypes.c_uint32),
        ("total_processes", ctypes.c_uint32),
        ("active_processes", ctypes.c_uint32),
        ("limit_terminated_processes", ctypes.c_uint32),
    ]


class _Function(Protocol):
    argtypes: list[object]
    restype: object

    def __call__(self, *arguments: object) -> int: ...


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _Kernel32(Protocol):
    GetProcessId: _Function
    GetProcessTimes: _Function
    IsProcessInJob: _Function
    QueryInformationJobObject: _Function


def _kernel32() -> _Kernel32:
    loader = getattr(ctypes, "WinDLL", None)
    if os.name != "nt" or loader is None:
        raise WindowsJobCpuUnavailableError("windows_job_api_unavailable")
    return cast(_Kernel32, loader("kernel32", use_last_error=True))


class WindowsJobCpuUnavailableError(RuntimeError):
    """A fixed, privacy-safe unavailable reason; never a zero CPU sample."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class WindowsJobCpuSnapshot:
    total_ticks: int
    total_processes: int
    active_processes: int
    unit: ClassVar[str] = "100ns"
    collector: ClassVar[str] = "windows_job_object"
    complete_exited_descendants: ClassVar[bool] = True


def _handle(value: object) -> int:
    maximum = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value < maximum:
        raise WindowsJobCpuUnavailableError("windows_job_handle_invalid")
    return value


class WindowsJobCpuReader:
    """Borrow a verified fixture job for sequential samples during its lifetime.

    The production launcher already assigns the suspended root before resuming
    it, disallows breakaway, and retains this job separately from any runner job.
    Retaining both owners prevents garbage-collection closure. Explicit fixture
    closure must not race the sampler; binding is checked on both sides of reads.
    Any failure permanently invalidates this reader, so later samples cannot
    conceal a lost accounting interval or a reset/replaced handle.
    """

    def __init__(self, job: WindowsHookJob, process: subprocess.Popen[bytes]) -> None:
        if ctypes.sizeof(_BasicAccounting) != _ACCOUNTING_BYTES:
            raise WindowsJobCpuUnavailableError("windows_job_accounting_abi_invalid")
        self._job = job
        self._process = process
        self._job_handle = _handle(job.handle)
        self._process_handle = _handle(getattr(process, "_handle", None))
        self._pid = process.pid
        if isinstance(self._pid, bool) or not isinstance(self._pid, int) or not 0 < self._pid < 2**32:
            raise WindowsJobCpuUnavailableError("windows_job_root_invalid")
        self._api = _kernel32()
        self._api.GetProcessId.argtypes = [ctypes.c_void_p]
        self._api.GetProcessId.restype = ctypes.c_uint32
        self._api.GetProcessTimes.argtypes = [ctypes.c_void_p, *([ctypes.POINTER(_FileTime)] * 4)]
        self._api.GetProcessTimes.restype = ctypes.c_int32
        self._api.IsProcessInJob.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32)]
        self._api.IsProcessInJob.restype = ctypes.c_int32
        self._api.QueryInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._api.QueryInformationJobObject.restype = ctypes.c_int32
        self._previous: tuple[int, int, int] | None = None
        self._failed = False
        self._creation_time = self._process_creation_time()
        self._verify_binding()

    def _process_creation_time(self) -> int:
        creation, exit_time, kernel, user = (_FileTime() for _ in range(4))
        if not self._api.GetProcessTimes(
            ctypes.c_void_p(self._process_handle),
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise WindowsJobCpuUnavailableError("windows_job_root_time_query_failed")
        result = (creation.high << 32) | creation.low
        if result == 0:
            raise WindowsJobCpuUnavailableError("windows_job_root_time_invalid")
        return result

    def _verify_binding(self) -> None:
        if (
            self._job.closed
            or _handle(self._job.handle) != self._job_handle
            or _handle(getattr(self._process, "_handle", None)) != self._process_handle
            or self._process.pid != self._pid
        ):
            raise WindowsJobCpuUnavailableError("windows_job_binding_changed")
        if self._process.poll() is not None:
            raise WindowsJobCpuUnavailableError("windows_job_root_exited")
        if self._api.GetProcessId(ctypes.c_void_p(self._process_handle)) != self._pid:
            raise WindowsJobCpuUnavailableError("windows_job_root_mismatch")
        if self._process_creation_time() != self._creation_time:
            raise WindowsJobCpuUnavailableError("windows_job_root_identity_changed")
        assigned = ctypes.c_int32()
        if not self._api.IsProcessInJob(
            ctypes.c_void_p(self._process_handle), ctypes.c_void_p(self._job_handle), ctypes.byref(assigned)
        ):
            raise WindowsJobCpuUnavailableError("windows_job_membership_query_failed")
        if assigned.value != 1:
            raise WindowsJobCpuUnavailableError("windows_job_root_not_assigned")

    def __call__(self) -> WindowsJobCpuSnapshot:
        if self._failed:
            raise WindowsJobCpuUnavailableError("windows_job_reader_invalidated")
        try:
            self._verify_binding()
            value = _BasicAccounting()
            returned = ctypes.c_uint32()
            if not self._api.QueryInformationJobObject(
                ctypes.c_void_p(self._job_handle),
                _JOB_BASIC_ACCOUNTING,
                ctypes.byref(value),
                _ACCOUNTING_BYTES,
                ctypes.byref(returned),
            ):
                raise WindowsJobCpuUnavailableError("windows_job_accounting_query_failed")
            self._verify_binding()
            if returned.value != _ACCOUNTING_BYTES:
                raise WindowsJobCpuUnavailableError("windows_job_accounting_length_invalid")
            times = (value.total_user_time, value.total_kernel_time, value.period_user_time, value.period_kernel_time)
            if any(number < 0 for number in times):
                raise WindowsJobCpuUnavailableError("windows_job_accounting_negative")
            if not 1 <= value.active_processes <= value.total_processes or (
                value.limit_terminated_processes > value.total_processes
            ):
                raise WindowsJobCpuUnavailableError("windows_job_accounting_counts_invalid")
            current = (value.total_user_time, value.total_kernel_time, value.total_processes)
            if self._previous is not None and any(
                after < before for before, after in zip(self._previous, current, strict=True)
            ):
                raise WindowsJobCpuUnavailableError("windows_job_accounting_regressed")
            self._previous = current
            return WindowsJobCpuSnapshot(sum(times[:2]), value.total_processes, value.active_processes)
        except (OSError, ValueError, RuntimeError):
            self._failed = True
            raise
