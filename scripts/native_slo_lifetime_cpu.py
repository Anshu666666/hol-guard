"""Read lifetime CPU from an externally prepared, protected Linux cgroup.

This module never creates a cgroup, moves a process, changes permissions or
reaps a child. Admission must precede any fixture/launcher children. A separate
reviewed controller must put the benchmark worker alone in a private cgroup.
Other operating systems and ordinary process polling remain incomplete.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

_LIMIT = 1024 * 1024
_MAX_COUNTER = 2**63 - 1
_CGROUP_ROOT = Path("/sys/fs/cgroup")


class LifetimeCpuUnavailableError(RuntimeError):
    """A fixed diagnostic refusal, never a product failure."""


@dataclass(frozen=True, slots=True)
class CpuSnapshot:
    usage_usec: int
    user_usec: int
    system_usec: int


def parse_cpu_stat(body: bytes) -> CpuSnapshot:
    if len(body) > 8192:
        raise LifetimeCpuUnavailableError("cpu_stat_size")
    values: dict[str, int] = {}
    try:
        lines = body.decode("ascii").splitlines()
        if not 3 <= len(lines) <= 64:
            raise ValueError
        for line in lines:
            key, number = line.split()
            if key in values or not key.replace("_", "").isalnum() or not number.isdecimal():
                raise ValueError
            value = int(number)
            if value > _MAX_COUNTER:
                raise ValueError
            values[key] = value
        return CpuSnapshot(values["usage_usec"], values["user_usec"], values["system_usec"])
    except (UnicodeError, ValueError, KeyError) as error:
        raise LifetimeCpuUnavailableError("cpu_stat_invalid") from error


def cpu_delta(before: CpuSnapshot, after: CpuSnapshot) -> dict[str, float]:
    names = ("usage_usec", "user_usec", "system_usec")
    differences = {name: getattr(after, name) - getattr(before, name) for name in names}
    if any(value < 0 for value in differences.values()):
        raise LifetimeCpuUnavailableError("cpu_counter_regressed")
    # Kernel counters are read together but need not have an exact algebraic
    # relationship on all kernels. Do not invent a user+system equality gate.
    return {name.replace("_usec", "_seconds"): value / 1_000_000 for name, value in differences.items()}


def _read(path: Path, limit: int = _LIMIT) -> bytes:
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise LifetimeCpuUnavailableError("metadata_size")
    return value


def _status() -> None:
    fields: dict[str, str] = {}
    for line in _read(Path("/proc/self/status"), 65536).decode("ascii").splitlines():
        key, _, value = line.partition(":")
        if key in fields:
            raise LifetimeCpuUnavailableError("status_duplicate")
        fields[key] = value.strip()
    if fields.get("NoNewPrivs") != "1" or any(
        int(fields.get(name, "1"), 16) != 0 for name in ("CapEff", "CapPrm", "CapAmb")
    ):
        raise LifetimeCpuUnavailableError("privilege_boundary_unproved")
    if fields.get("Threads") != "1":
        raise LifetimeCpuUnavailableError("admission_requires_single_thread")


class ProtectedCgroupCpu:
    """Lifetime counters for one source-owned fork/exec inheritance boundary.

    Completeness applies to CPU charged to this kernel group, including exited
    members. It does not prove peak private memory or external service work.
    The trusted controller/host can still interfere; its identity and isolation
    are an operational prerequisite, not inferred from a counter value.
    """

    def __init__(self, path: Path) -> None:
        self._fd = -1
        self._pid = os.getpid()
        self._relative = ""
        self.identity_sha256 = ""
        try:
            self._admit(path)
        except BaseException:
            self.close()
            raise

    def _admit(self, path: Path) -> None:
        if not sys.platform.startswith("linux"):
            raise LifetimeCpuUnavailableError("protected_cgroup_platform_or_user")
        users = os.getresuid()
        if len(set(users)) != 1 or users[0] == 0:
            raise LifetimeCpuUnavailableError("protected_cgroup_platform_or_user")
        _status()
        root = _CGROUP_ROOT
        if not path.is_absolute() or ".." in path.parts or path != path.resolve(strict=True):
            raise LifetimeCpuUnavailableError("cgroup_path_invalid")
        relative = path.relative_to(root)
        if not relative.parts:
            raise LifetimeCpuUnavailableError("shared_root_cgroup")
        self._relative = "/" + relative.as_posix()
        self._fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        metadata = os.fstat(self._fd)
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise LifetimeCpuUnavailableError("cgroup_owner_unproved")
        # A move to a distant branch uses its actual common ancestor, not
        # necessarily our immediate parent. Admit only bounded hierarchies
        # with no writable ancestor migration point all the way to root.
        if len(relative.parts) > 32:
            raise LifetimeCpuUnavailableError("cgroup_hierarchy_depth")
        ancestors = [parent for parent in path.parents if parent == root or root in parent.parents]
        for target in (path, path / "cgroup.procs", *(parent / "cgroup.procs" for parent in ancestors)):
            if os.access(target, os.W_OK, effective_ids=True):
                raise LifetimeCpuUnavailableError("cgroup_migration_possible")
        fdinfo = _read(Path(f"/proc/self/fdinfo/{self._fd}"), 4096).decode("ascii")
        mount_ids = [line.split(":", 1)[1].strip() for line in fdinfo.splitlines() if line.startswith("mnt_id:")]
        if len(mount_ids) != 1:
            raise LifetimeCpuUnavailableError("cgroup_mount_identity")
        records = [
            line
            for line in _read(Path("/proc/self/mountinfo")).decode("ascii").splitlines()
            if line.split()[0] == mount_ids[0]
        ]
        if len(records) != 1:
            raise LifetimeCpuUnavailableError("cgroup_mount_identity")
        left, separator, right = records[0].partition(" - ")
        if not separator or left.split()[3:5] != ["/", str(root)] or right.split()[0] != "cgroup2":
            raise LifetimeCpuUnavailableError("cgroup_mount_unsupported")
        self._check_membership()
        pids = self._read_member("cgroup.procs", 65536).decode("ascii").splitlines()
        if pids != [str(self._pid)]:
            raise LifetimeCpuUnavailableError("cgroup_not_exclusive_at_admission")
        # cgroup.procs excludes descendant groups. Refuse an already populated
        # hierarchy rather than mistake one direct member for exclusivity.
        with os.scandir(self._fd) as entries:
            for index, entry in enumerate(entries):
                if index >= 256 or entry.is_dir(follow_symlinks=False):
                    raise LifetimeCpuUnavailableError("cgroup_initial_hierarchy_unproved")
        if self._read_member("cgroup.type", 64) != b"domain\n":
            raise LifetimeCpuUnavailableError("cgroup_domain_unproved")
        self.identity_sha256 = hashlib.sha256(
            f"{metadata.st_dev}:{metadata.st_ino}:{mount_ids[0]}".encode("ascii")
        ).hexdigest()
        self.snapshot()

    def _read_member(self, name: str, limit: int) -> bytes:
        if self._fd < 0:
            raise LifetimeCpuUnavailableError("cgroup_handle_closed")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._fd)
        with os.fdopen(descriptor, "rb") as stream:
            body = stream.read(limit + 1)
        if len(body) > limit:
            raise LifetimeCpuUnavailableError("cgroup_member_size")
        return body

    def _check_membership(self) -> None:
        if os.getpid() != self._pid:
            raise LifetimeCpuUnavailableError("cgroup_reader_process_changed")
        memberships = _read(Path("/proc/self/cgroup"), 65536).decode("ascii").splitlines()
        if memberships != ["0::" + self._relative]:
            raise LifetimeCpuUnavailableError("cgroup_membership_changed")

    def snapshot(self) -> CpuSnapshot:
        self._check_membership()
        result = parse_cpu_stat(self._read_member("cpu.stat", 8192))
        self._check_membership()
        return result

    def close(self) -> None:
        if self._fd >= 0:
            descriptor, self._fd = self._fd, -1
            os.close(descriptor)
