from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.ci import qualification_host_facts as host


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch) -> dict[str, Any]:
    proc = tmp_path / "proc"
    proc.mkdir()
    sysfs = tmp_path / "sys"
    block = (
        "processor: {cpu}\nvendor_id: GenuineIntel\ncpu family: 6\nmodel: 106\n"
        "model name: Intel(R) Xeon(R) Platinum CPU @ 2.80GHz\nstepping: 6"
    )
    (proc / "cpuinfo").write_text("\n\n".join(block.format(cpu=i) for i in range(2)) + "\n")
    (proc / "meminfo").write_text("MemTotal: 16777216 kB\nMemAvailable: 8388608 kB\n")
    for cpu in range(2):
        p = sysfs / f"devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"
        p.parent.mkdir(parents=True)
        p.write_text("performance\n")
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    python = tmp_path / "python"
    python.write_bytes(b"controlled interpreter bytes")
    monkeypatch.setattr(host.os, "sched_getaffinity", lambda _pid: {0, 1})
    monkeypatch.setattr(host.os, "cpu_count", lambda: 2)
    monkeypatch.setattr(host, "sys", SimpleNamespace(executable=str(python)))
    monkeypatch.setattr(
        host,
        "platform",
        SimpleNamespace(
            system=lambda: "Linux",
            release=lambda: "6.11.0-1018-azure",
            machine=lambda: "x86_64",
            python_version=lambda: "3.12.14",
            python_implementation=lambda: "CPython",
        ),
    )
    monkeypatch.setenv("ImageOS", "ubuntu24")
    monkeypatch.setenv("ImageVersion", "20260920.1")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setenv("UNRELATED_PRIVATE_TOKEN", "never-export-this")
    return {"proc": proc, "sysfs": sysfs, "os_release": os_release}


def test_all_declared_facts_are_available_without_granting_campaign_admission(fixture) -> None:
    result = host.capture(**fixture)
    assert result["all_declared_facts_available"] is True
    assert result["campaign_admission"] is False
    assert result["facts"]["cpu"]["eligible_logical_cpus"] == 2
    assert result["facts"]["memory"]["ram_class_gib_rounded_up"] == 16
    assert "never-export-this" not in json.dumps(result)
    assert str(fixture["proc"].parent) not in json.dumps(result)


@pytest.mark.parametrize("count,state", [(0, "unexposed"), (1, "partial")])
def test_unexposed_or_partial_governors_remain_unavailable(fixture, count: int, state: str) -> None:
    for cpu in range(count, 2):
        (fixture["sysfs"] / f"devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor").unlink()
    result = host.capture(**fixture)
    assert result["facts"]["governors"] == {"available": False, "state": state, "visible_count": count}
    assert result["all_declared_facts_available"] is False and result["campaign_admission"] is False


@pytest.mark.parametrize("kind", ["duplicate_cpu", "missing_cpu", "heterogeneous_cpu", "memory", "image", "release"])
def test_ambiguous_or_missing_fact_is_fixed_unavailable_without_substitution(fixture, monkeypatch, kind: str) -> None:
    cpu = fixture["proc"] / "cpuinfo"
    if kind == "duplicate_cpu":
        cpu.write_text(cpu.read_text().replace("processor: 1", "processor: 0"))
    elif kind == "missing_cpu":
        cpu.write_text(cpu.read_text().split("\n\n")[0])
    elif kind == "heterogeneous_cpu":
        cpu.write_text(
            cpu.read_text().replace("processor: 1\nvendor_id: GenuineIntel", "processor: 1\nvendor_id: AuthenticAMD")
        )
    elif kind == "memory":
        (fixture["proc"] / "meminfo").write_text("MemTotal: 10 kB\nMemAvailable: 11 kB\n")
    elif kind == "image":
        monkeypatch.delenv("ImageVersion")
    else:
        fixture["os_release"].write_text("ID=ubuntu\nID=ubuntu\nVERSION_ID=24.04\n")
    result = host.capture(**fixture)
    field = (
        "cpu"
        if kind.endswith("cpu")
        else "memory"
        if kind == "memory"
        else "runner_image"
        if kind == "image"
        else "os_release"
    )
    assert result["unavailable"][field] == "unavailable"
    assert result["all_declared_facts_available"] is False and result["campaign_admission"] is False


def test_bounded_system_fact_read_refuses_symlink_and_oversize(fixture, tmp_path: Path) -> None:
    source = tmp_path / "body"
    source.write_text("x" * 257)
    with pytest.raises(ValueError, match="bound"):
        host._read(source, 256)
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(OSError):
        host._read(link, 1024)


def test_declared_os_release_symlink_resolves_to_bounded_read_only_metadata(fixture, tmp_path: Path) -> None:
    source = fixture["os_release"]
    target = tmp_path / "os-release-target"
    source.rename(target)
    source.symlink_to(target)
    result = host.capture(**fixture)
    assert result["facts"]["os_release"] == {"ID": "ubuntu", "VERSION_ID": "24.04"}
    assert result["all_declared_facts_available"] is True and result["campaign_admission"] is False


def test_unavailable_online_cpu_count_cannot_be_reported_as_available(fixture, monkeypatch) -> None:
    monkeypatch.setattr(host.os, "cpu_count", lambda: None)
    result = host.capture(**fixture)
    assert result["unavailable"]["cpu"] == "unavailable"
    assert result["all_declared_facts_available"] is False
