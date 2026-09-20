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
    monkeypatch.setattr(lifetime.os, "geteuid", lambda: 1001)
    original_fstat = lifetime.os.fstat

    def root_owned(descriptor: int) -> os.stat_result:
        fields = list(original_fstat(descriptor))
        fields[4] = 0
        return os.stat_result(fields)

    monkeypatch.setattr(lifetime.os, "fstat", root_owned)
    monkeypatch.setattr(lifetime.os, "access", lambda *_args, **_kwargs: evidence["writable"])
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


@pytest.mark.parametrize("failure", ["privilege", "threads", "writable", "foreign", "filesystem", "threaded"])
def test_modeled_admission_refuses_unproved_lifetime_boundary(modeled_group, failure: str) -> None:
    path, evidence = modeled_group
    if failure == "privilege":
        evidence["status"] = evidence["status"].replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0")
    elif failure == "threads":
        evidence["status"] = evidence["status"].replace(b"Threads:\t1", b"Threads:\t2")
    elif failure == "writable":
        evidence["writable"] = True
    elif failure == "foreign":
        (path / "cgroup.procs").write_text(f"{os.getpid()}\n12345\n")
    elif failure == "filesystem":
        evidence["mount"] = evidence["mount"].replace(b" - cgroup2 ", b" - ext4 ")
    else:
        (path / "cgroup.type").write_text("threaded\n")
    with pytest.raises(lifetime.LifetimeCpuUnavailableError):
        lifetime.ProtectedCgroupCpu(path)


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
