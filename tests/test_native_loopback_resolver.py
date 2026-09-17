from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts.ci import native_loopback_resolver as resolver


def test_fixed_entry_preserves_existing_hosts_and_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n::1 localhost\n192.0.2.2 private-fixture-name\n"
    path.write_bytes(original)
    assert resolver.hosts_summary(path) == {"ipv4_localhost_entry": True, "fixed_alias_entry": False}
    assert resolver.add_fixed_entry(path)
    assert path.read_bytes().startswith(original)
    assert resolver.hosts_summary(path) == {"ipv4_localhost_entry": True, "fixed_alias_entry": True}
    before = path.read_bytes()
    assert not resolver.add_fixed_entry(path)
    assert path.read_bytes() == before
    assert "private-fixture-name" not in json.dumps(resolver.hosts_summary(path))


def test_hosts_inventory_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "hosts"
    path.write_bytes(b"x" * (resolver._HOSTS_LIMIT + 1))
    with pytest.raises(ValueError, match="resolver_hosts_oversized"):
        resolver.add_fixed_entry(path)


def test_probe_timeout_never_exposes_child_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert arguments[1:3] == ["-I", "-c"] and kwargs["timeout"] == 5
        raise subprocess.TimeoutExpired(arguments, 5, output="private-fixture-name")

    monkeypatch.setattr(resolver.subprocess, "run", timeout)
    report = resolver.resolver_probe()
    assert report["status"] == "deadline_exceeded"
    assert "private-fixture-name" not in json.dumps(report)


def test_repair_reports_failed_actual_retry_without_claiming_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resolver.sys, "platform", "darwin")
    monkeypatch.setattr(resolver, "hosts_summary", lambda _: {"ipv4_localhost_entry": True, "fixed_alias_entry": False})
    monkeypatch.setattr(resolver, "resolver_probe", lambda: {"status": "deadline_exceeded", "elapsed_ms": 5000})
    actions: list[list[str]] = []

    def maintenance(arguments: list[str]) -> str:
        actions.append(arguments)
        return "completed"

    monkeypatch.setattr(resolver, "_run_maintenance", maintenance)
    report = resolver.diagnose(repair=True)
    assert report["repair_attempted"] is True
    assert len(actions) == 3 and all(arguments[:2] == ["sudo", "-n"] for arguments in actions)
    assert report["after"] == {"status": "deadline_exceeded", "elapsed_ms": 5000}
    assert report["baseline_artifact_modified"] is False and report["runtime_patched"] is False
    assert "passed" not in report


def test_healthy_resolver_does_not_mutate_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resolver.sys, "platform", "darwin")
    monkeypatch.setattr(resolver, "hosts_summary", lambda _: {"ipv4_localhost_entry": True, "fixed_alias_entry": False})
    monkeypatch.setattr(resolver, "resolver_probe", lambda: {"status": "completed", "elapsed_ms": 1})

    def forbidden(_arguments: list[str]) -> str:
        raise AssertionError("healthy resolver should not need maintenance")

    monkeypatch.setattr(resolver, "_run_maintenance", forbidden)
    assert resolver.diagnose(repair=True)["repair_attempted"] is False
