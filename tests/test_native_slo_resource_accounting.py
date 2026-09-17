from __future__ import annotations

import os

import pytest

from scripts import native_slo_resources as resources
from scripts.native_slo_windows_job_resources import WindowsJobCpuSnapshot


def _fixture_pid() -> int:
    # A small fixed PID can be the actual test driver in a PID namespace.
    # These tests replace the process reader, so select a distinct identity.
    return os.getpid() + 1


def _snapshot(*, unavailable_cpu: bool = False) -> resources.TreeResources:
    return resources.TreeResources(
        100,
        50,
        999999.0,
        1,
        1,
        3,
        handles=4,
        unavailable={"cpu_seconds": "permission_denied"} if unavailable_cpu else {},
        process_cpu={(_fixture_pid(), 1.0): 999999.0},
    )


def test_job_cpu_includes_unobserved_exits_without_adding_psutil_cpu(monkeypatch):
    monkeypatch.setattr(resources, "sample_process_tree", lambda _pid: _snapshot(unavailable_cpu=True))
    # Large absolute counters prove subtraction happens before float conversion.
    origin = 2**60
    values = iter(WindowsJobCpuSnapshot(origin + i * 10_000_000, 3, 1) for i in range(30))
    sampler = resources.ResourceSampler(pid=_fixture_pid(), cpu_reader=lambda: next(values))
    for _ in range(30):
        sampler._sample()
    result = sampler.report(attempted=29)
    assert result["cpu_seconds"] == 29.0
    assert result["cpu_ms_per_attempt"] == 1000.0
    assert result["short_exited_descendants_cpu_complete"] is True
    assert result["metric_minimum_met"]["cpu_seconds"] is True
    assert result["collector"] == "psutil_with_windows_job_cpu"
    assert result["cpu_accounting_scope"] == "explicit_fixture_job"
    assert result["includes_load_generator"] is False
    assert "cpu_seconds" not in result["unavailable_metrics"]
    assert sampler._observed_cpu == {}


@pytest.mark.parametrize("fault", ["query", "reset", "negative", "invalid"])
def test_any_job_fault_permanently_withholds_complete_cpu(monkeypatch, fault):
    monkeypatch.setattr(resources, "sample_process_tree", lambda _pid: _snapshot())
    calls = 0

    def read():
        nonlocal calls
        calls += 1
        if calls == 2:
            if fault == "query":
                raise OSError("synthetic private detail must not reach evidence")
            if fault == "invalid":
                return None
            return WindowsJobCpuSnapshot(-1 if fault == "negative" else 0, 1, 1)
        return WindowsJobCpuSnapshot(calls * 100, 1, 1)

    sampler = resources.ResourceSampler(pid=_fixture_pid(), cpu_reader=read)
    for _ in range(32):
        sampler._sample()
    result = sampler.report(attempted=30)
    assert result["cpu_seconds"] is None
    assert result["short_exited_descendants_cpu_complete"] is False
    assert result["metric_minimum_met"]["cpu_seconds"] is False
    assert result["cpu_unavailable_samples"] == 1
    assert result["unavailable_metrics"]["cpu_seconds"] == {"job_accounting_unavailable": 1}
    assert "private detail" not in repr(result)


def test_job_cpu_does_not_fabricate_missing_memory_inventory(monkeypatch):
    monkeypatch.setattr(resources, "sample_process_tree", lambda _pid: None)
    values = iter(WindowsJobCpuSnapshot(i * 100, 1, 1) for i in range(30))
    sampler = resources.ResourceSampler(pid=_fixture_pid(), cpu_reader=lambda: next(values))
    for _ in range(30):
        sampler._sample()
    result = sampler.report(attempted=29)
    assert result["metric_minimum_met"]["cpu_seconds"] is True
    assert result["metric_minimum_met"]["rss_bytes"] is False
    assert result["sample_minimum_met"] is False
    assert result["unavailable_samples"] == 30
    assert result["cpu_unavailable_samples"] == 0


def test_explicit_fixture_cpu_cannot_be_attached_to_load_generator():
    with pytest.raises(ValueError, match="load generator"):
        resources.ResourceSampler(pid=os.getpid(), cpu_reader=lambda: WindowsJobCpuSnapshot(0, 1, 1))
