from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts import native_slo_lifetime_cpu as lifetime


@pytest.mark.parametrize(
    "body",
    [
        b"usage_usec 2\nuser_usec 1\nsystem_usec 1\nusage_usec 3\n",
        b"usage_usec -2\nuser_usec 1\nsystem_usec 1\n",
        b"usage_usec 2\nuser_usec 1\n",
        b"usage_usec 2\nuser_usec 1\nsystem_usec inf\n",
        b"usage_usec 9223372036854775808\nuser_usec 1\nsystem_usec 1\n",
        b"usage_usec 2\nuser_usec 1\nsystem_usec 1\n" + b" " * 8192,
        b"usage_usec 2\nuser_usec 1\nsystem_usec 1\nprivate\xff 3\n",
    ],
    ids=["duplicate", "negative", "missing", "nonfinite", "overflow", "size", "encoding"],
)
def test_invalid_kernel_counter_is_not_a_zero_or_complete_sample(body: bytes) -> None:
    with pytest.raises(lifetime.LifetimeCpuUnavailableError):
        lifetime.parse_cpu_stat(body)


def test_kernel_counter_retains_three_domains_without_inventing_exact_sum() -> None:
    start = lifetime.parse_cpu_stat(b"usage_usec 100\nuser_usec 60\nsystem_usec 39\nnr_periods 3\n")
    end = lifetime.parse_cpu_stat(b"usage_usec 200\nuser_usec 120\nsystem_usec 78\nnr_periods 5\n")
    assert lifetime.cpu_delta(start, end) == {
        "usage_seconds": 0.0001,
        "user_seconds": 0.00006,
        "system_seconds": 0.000039,
    }
    with pytest.raises(lifetime.LifetimeCpuUnavailableError, match="regressed"):
        lifetime.cpu_delta(end, start)


@pytest.mark.parametrize("position", [0, 1, 2, 3])
def test_linux_core_scheduling_counter_preserves_required_totals(position: int) -> None:
    # The exact auxiliary spelling is emitted by Linux v6.8 and v6.17
    # kernel/cgroup/rstat.c. These are source-shaped values, not hosted input.
    lines = [b"usage_usec 200", b"user_usec 120", b"system_usec 78"]
    lines.insert(position, b"core_sched.force_idle_usec 41")
    snapshot = lifetime.parse_cpu_stat(b"\n".join(lines) + b"\n")
    assert snapshot == lifetime.CpuSnapshot(usage_usec=200, user_usec=120, system_usec=78)


@pytest.mark.parametrize(
    "auxiliary",
    [
        b"core_sched.force_idle_usec 1\ncore_sched.force_idle_usec 2\n",
        b"core_sched.force_idle_usec -1\n",
        b"core_sched.force_idle_usec 1.0\n",
        b"core_sched.force_idle_usec inf\n",
        b"core_sched.force_idle_usec 9223372036854775808\n",
        b"core_sched.force_idle_usec 1 extra\n",
        b"core_sched.other 1\n",
        b"other.force_idle_usec 1\n",
        b"core_sched..force_idle_usec 1\n",
    ],
    ids=["duplicate", "negative", "fraction", "nonfinite", "overflow", "extra", "unknown", "namespace", "dots"],
)
def test_dotted_auxiliary_does_not_relax_duplicate_value_or_key_checks(auxiliary: bytes) -> None:
    body = b"usage_usec 200\nuser_usec 120\nsystem_usec 78\n" + auxiliary
    with pytest.raises(lifetime.LifetimeCpuUnavailableError, match="cpu_stat_invalid"):
        lifetime.parse_cpu_stat(body)


@pytest.mark.parametrize("missing", ["usage_usec", "user_usec", "system_usec"])
def test_auxiliary_never_substitutes_for_a_required_lifetime_counter(missing: str) -> None:
    lines = [f"{key} 1" for key in ("usage_usec", "user_usec", "system_usec") if key != missing]
    lines.append("core_sched.force_idle_usec 1")
    with pytest.raises(lifetime.LifetimeCpuUnavailableError, match="cpu_stat_invalid"):
        lifetime.parse_cpu_stat(("\n".join(lines) + "\n").encode("ascii"))


def test_core_scheduling_counter_still_obeys_original_row_and_byte_bounds() -> None:
    rows = b"usage_usec 200\nuser_usec 120\nsystem_usec 78\ncore_sched.force_idle_usec 41\n"
    rows += b"".join(f"aux_{index} 0\n".encode("ascii") for index in range(60))
    assert lifetime.parse_cpu_stat(rows).usage_usec == 200
    with pytest.raises(lifetime.LifetimeCpuUnavailableError, match="cpu_stat_invalid"):
        lifetime.parse_cpu_stat(rows + b"extra 0\n")
    with pytest.raises(lifetime.LifetimeCpuUnavailableError, match="cpu_stat_size"):
        lifetime.parse_cpu_stat(rows + b" " * 8192)


@pytest.fixture
def modeled_group(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    if not sys.platform.startswith("linux"):
        pytest.skip("models Linux filesystem admission")
    root = tmp_path / "cgroup"
    path = root / "owned"
    path.mkdir(parents=True)
    (root / "cgroup.procs").write_text("")
    (path / "cgroup.procs").write_text(f"{os.getpid()}\n")
    (path / "cgroup.type").write_text("domain\n")
    (path / "cpu.stat").write_text("usage_usec 100\nuser_usec 60\nsystem_usec 40\n")
    original_read = lifetime._read
    evidence: dict[str, Any] = {
        "status": b"NoNewPrivs:\t1\nCapEff:\t0\nCapPrm:\t0\nCapAmb:\t0\nThreads:\t1\n",
        "membership": b"0::/owned\n",
        "mount": f"123 1 0:1 / {root} ro - cgroup2 cgroup2 rw\n".encode(),
        "writable": False,
    }

    def read(value: Path, limit: int = 1024 * 1024) -> bytes:
        if value == Path("/proc/self/status"):
            return evidence["status"]
        if value == Path("/proc/self/cgroup"):
            return evidence["membership"]
        if value == Path("/proc/self/mountinfo"):
            return evidence["mount"]
        if str(value).startswith("/proc/self/fdinfo/"):
            return b"mnt_id:\t123\n"
        return original_read(value, limit)

    monkeypatch.setattr(lifetime, "_CGROUP_ROOT", root)
    monkeypatch.setattr(lifetime, "_read", read)
    monkeypatch.setattr(lifetime.sys, "platform", "linux")
    monkeypatch.setattr(lifetime.os, "getresuid", lambda: (1001, 1001, 1001))
    original_fstat = lifetime.os.fstat

    def root_owned(descriptor: int) -> os.stat_result:
        fields = list(original_fstat(descriptor))
        fields[4] = 0
        return os.stat_result(fields)

    monkeypatch.setattr(lifetime.os, "fstat", root_owned)
    monkeypatch.setattr(
        lifetime.os,
        "access",
        lambda value, *_args, **_kwargs: evidence["writable"] or value == evidence.get("writable_path"),
    )
    return path, evidence


def test_modeled_admission_uses_pinned_counter_handle_and_refuses_lost_membership(modeled_group) -> None:
    path, evidence = modeled_group
    reader = lifetime.ProtectedCgroupCpu(path)
    try:
        assert reader.snapshot().usage_usec == 100
        evidence["membership"] = b"0::/escaped\n"
        with pytest.raises(lifetime.LifetimeCpuUnavailableError, match="membership_changed"):
            reader.snapshot()
    finally:
        reader.close()
    with pytest.raises(lifetime.LifetimeCpuUnavailableError):
        reader.snapshot()


@pytest.mark.parametrize(
    "failure", ["privilege", "capability", "threads", "writable", "foreign", "filesystem", "threaded", "descendant"]
)
def test_modeled_admission_refuses_unproved_lifetime_boundary(modeled_group, failure: str) -> None:
    path, evidence = modeled_group
    if failure == "privilege":
        evidence["status"] = evidence["status"].replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0")
    elif failure == "capability":
        evidence["status"] = evidence["status"].replace(b"CapPrm:\t0", b"CapPrm:\t1")
    elif failure == "threads":
        evidence["status"] = evidence["status"].replace(b"Threads:\t1", b"Threads:\t2")
    elif failure == "writable":
        evidence["writable"] = True
    elif failure == "foreign":
        (path / "cgroup.procs").write_text(f"{os.getpid()}\n12345\n")
    elif failure == "filesystem":
        evidence["mount"] = evidence["mount"].replace(b" - cgroup2 ", b" - ext4 ")
    elif failure == "threaded":
        (path / "cgroup.type").write_text("threaded\n")
    else:
        (path / "preexisting-child").mkdir()
    with pytest.raises(lifetime.LifetimeCpuUnavailableError):
        lifetime.ProtectedCgroupCpu(path)


@pytest.mark.parametrize("users", [(0, 0, 0), (1001, 1001, 0), (0, 1001, 1001)])
def test_saved_or_real_privileged_identity_cannot_gain_completeness(
    modeled_group, monkeypatch: pytest.MonkeyPatch, users: tuple[int, int, int]
) -> None:
    path, _ = modeled_group
    monkeypatch.setattr(lifetime.os, "getresuid", lambda: users)
    with pytest.raises(lifetime.LifetimeCpuUnavailableError, match="platform_or_user"):
        lifetime.ProtectedCgroupCpu(path)


def test_symlink_and_shared_root_are_not_private_boundaries(modeled_group) -> None:
    path, _ = modeled_group
    alias = path.parent / "alias"
    alias.symlink_to(path, target_is_directory=True)
    for value in (alias, path.parent):
        with pytest.raises(lifetime.LifetimeCpuUnavailableError):
            lifetime.ProtectedCgroupCpu(value)


def test_changed_reader_process_cannot_reuse_parent_admission(modeled_group, monkeypatch: pytest.MonkeyPatch) -> None:
    path, _ = modeled_group
    reader = lifetime.ProtectedCgroupCpu(path)
    pid = os.getpid()
    try:
        monkeypatch.setattr(lifetime.os, "getpid", lambda: pid + 1)
        with pytest.raises(lifetime.LifetimeCpuUnavailableError, match="process_changed"):
            reader.snapshot()
    finally:
        reader.close()


def test_distant_writable_ancestor_is_not_hidden_by_read_only_immediate_parent(modeled_group) -> None:
    path, evidence = modeled_group
    deep = path / "inner" / "owned"
    deep.mkdir(parents=True)
    evidence["writable_path"] = path.parent / "cgroup.procs"
    with pytest.raises(lifetime.LifetimeCpuUnavailableError, match="migration_possible"):
        lifetime.ProtectedCgroupCpu(deep)


def test_shared_local_cgroup_or_unsupported_platform_cannot_gain_completeness() -> None:
    with pytest.raises((lifetime.LifetimeCpuUnavailableError, OSError, ValueError)):
        lifetime.ProtectedCgroupCpu(Path("/sys/fs/cgroup"))


@pytest.mark.skipif(
    "HOL_GUARD_TEST_PROTECTED_CGROUP" not in os.environ,
    reason="requires separately reviewed private kernel cgroup preparation; no simulated full-coverage credit",
)
def test_real_protected_group_accounts_exited_child_and_grandchild() -> None:
    reader = lifetime.ProtectedCgroupCpu(Path(os.environ["HOL_GUARD_TEST_PROTECTED_CGROUP"]))
    try:
        before = reader.snapshot()
        leaf = "import time; end=time.process_time()+0.04\nwhile time.process_time()<end: pass"
        program = f"import subprocess,sys; subprocess.run([sys.executable,'-c',{leaf!r}],check=True,timeout=5)"
        completed = subprocess.run([sys.executable, "-c", program], capture_output=True, timeout=8, check=True)
        assert completed.returncode == 0
        assert lifetime.cpu_delta(before, reader.snapshot())["usage_seconds"] >= 0.03
    finally:
        reader.close()
