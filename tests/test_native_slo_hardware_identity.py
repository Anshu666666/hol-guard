"""Qualification must observe Windows RAM without accepting missing identity."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from scripts import native_slo_qualification_run as qualification
from scripts.native_slo_surface_tail_contract import ROUTES
from scripts.native_slo_surface_tail_record import _identity_leaves
from tests.native_slo_pair_support import bundle_fixture
from tests.native_slo_surface_tail_support import block


def test_windows_hardware_records_actual_memory_without_posix_capacity(monkeypatch):
    monkeypatch.setattr(qualification.platform, "system", lambda: "Windows")
    monkeypatch.setattr(qualification.psutil, "virtual_memory", lambda: SimpleNamespace(total=16 * 1024**3))

    def no_posix_capacity():
        raise AssertionError("Windows cannot use absent sysconf/cgroup RAM")

    monkeypatch.setattr(qualification, "physical_memory_bytes", no_posix_capacity)
    assert qualification.hardware_summary()["ram_bytes"] == 16 * 1024**3


@pytest.mark.parametrize("total", [None, True, False, 0, -1, 16.0, "16", 2**63])
def test_invalid_windows_memory_stays_missing(monkeypatch, total):
    monkeypatch.setattr(qualification.platform, "system", lambda: "Windows")
    monkeypatch.setattr(qualification.psutil, "virtual_memory", lambda: SimpleNamespace(total=total))
    assert qualification._hardware_ram_bytes() is None


@pytest.mark.parametrize("error", [OSError("unavailable"), qualification.psutil.Error(), NotImplementedError()])
def test_failed_windows_memory_read_stays_missing(monkeypatch, error):
    monkeypatch.setattr(qualification.platform, "system", lambda: "Windows")

    def denied():
        raise error

    monkeypatch.setattr(qualification.psutil, "virtual_memory", denied)
    assert qualification._hardware_ram_bytes() is None


@pytest.mark.parametrize("system,total", [("Linux", 2 * 1024**3), ("Darwin", 8 * 1024**3), ("Linux", None)])
def test_posix_capacity_and_missingness_are_preserved(monkeypatch, system, total):
    monkeypatch.setattr(qualification.platform, "system", lambda: system)
    monkeypatch.setattr(qualification, "physical_memory_bytes", lambda: total)

    def no_fallback():
        raise AssertionError("host RAM cannot replace the POSIX effective capacity")

    monkeypatch.setattr(qualification.psutil, "virtual_memory", no_fallback)
    assert qualification._hardware_ram_bytes() == total


def test_missing_memory_still_fails_tail_identity_admission(tmp_path):
    bundle = bundle_fixture(tmp_path / "bundle")
    report, _ = block(bundle, "candidate", ROUTES[0], "smoke")
    runtime = cast(dict[str, object], report["runtime"])
    hardware = cast(dict[str, object], report["hardware"])
    hardware["ram_bytes"] = None
    with pytest.raises(ValueError, match="surface_tail_hardware_count_invalid"):
        _identity_leaves(runtime, hardware)
