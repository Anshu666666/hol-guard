"""Finite hosted preflight/outcome controls; no tracing or installed workload."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.ci import run_sqlite_syscall_diagnostic as hosted


def _runtime():
    return {
        "python_sha256": "python",
        "sqlite_version": "actual",
        "sqlite_source_id": "source",
        "compile_options_sha256": "options",
    }


def _probe(status="feasible"):
    sqlite = {key: value for key, value in _runtime().items() if key != "python_sha256"}
    return {
        "status": status,
        "python_sha256": "python",
        "strace_sha256": "tracer",
        "source_sha256": {
            Path(name).name: digest for name, digest in hosted.FROZEN_HELPERS.items() if name.startswith("scripts/")
        },
        "baseline": {"child": {"sqlite": sqlite}},
        "observed": {"child": {"sqlite": dict(sqlite)}},
        "rsp131_qualified": False,
    }


def _preflight(monkeypatch, *, probe=None):
    monkeypatch.setattr(hosted, "source_identity", lambda *_args: {"source": "bound"})
    monkeypatch.setattr(hosted, "python_sqlite_identity", _runtime)
    monkeypatch.setattr(hosted, "strace_identity", lambda: {"sha256": "tracer", "version": "strace -- version 6.8"})
    selected = _probe() if probe is None else probe
    monkeypatch.setattr(hosted.importlib, "import_module", lambda _name: SimpleNamespace(run_probe=lambda: selected))


def test_failed_controls_stop_before_importing_or_running_probe(monkeypatch):
    monkeypatch.setattr(hosted, "source_identity", lambda *_args: {"source": "bound"})
    monkeypatch.setattr(hosted, "python_sqlite_identity", lambda: pytest.fail("runtime must not run"))
    result = hosted.hosted_report("a" * 40, "failure")
    assert result["status"] == "unavailable" and result["reason"] == "finite_controls_not_passed"
    assert "probe" not in result


def test_missing_strace_is_explicit_and_never_runs_probe(monkeypatch):
    _preflight(monkeypatch)
    monkeypatch.setattr(hosted, "strace_identity", lambda: None)
    monkeypatch.setattr(hosted.importlib, "import_module", lambda _name: pytest.fail("probe must not run"))
    result = hosted.hosted_report("a" * 40, "success")
    assert result["reason"] == "strace_unavailable" and result["status"] == "unavailable"


def test_actual_denied_result_is_retained_without_syscall_counters(monkeypatch):
    original = _probe("denied")
    _preflight(monkeypatch, probe=original)
    result = hosted.hosted_report("a" * 40, "success")
    assert result["status"] == "denied" and result["probe"] is original
    assert not result["rsp131_qualified"] and "descriptor_witness" not in result["probe"]


@pytest.mark.parametrize("changed", ["source", "runtime", "strace"])
def test_changed_post_probe_identity_rejects_feasibility(monkeypatch, changed):
    _preflight(monkeypatch)
    method = {"source": "source_identity", "runtime": "python_sqlite_identity", "strace": "strace_identity"}[changed]
    original = getattr(hosted, method)
    observed = 0

    def transition(*args):
        nonlocal observed
        observed += 1
        return original(*args) if observed == 1 else {"changed": True}

    monkeypatch.setattr(hosted, method, transition)
    result = hosted.hosted_report("a" * 40, "success")
    assert result["status"] == "ambiguous" and result["reason"] == "source_or_runtime_identity_unproved"


def test_actual_child_sqlite_identity_must_match_parent_runtime(monkeypatch):
    original = _probe()
    original["observed"]["child"]["sqlite"]["sqlite_source_id"] = "different-runtime"
    _preflight(monkeypatch, probe=original)
    result = hosted.hosted_report("a" * 40, "success")
    assert result["status"] == "ambiguous" and not result["observed_identity_matches"]


def test_exception_does_not_export_private_text(monkeypatch):
    def fail(*_args):
        raise ValueError("private-path-and-buffer")

    monkeypatch.setattr(hosted, "source_identity", fail)
    result = hosted.hosted_report("a" * 40, "success")
    assert result["status"] == "ambiguous" and result["error_type"] == "ValueError"
    assert "private-path-and-buffer" not in json.dumps(result)


@pytest.mark.parametrize("status,exit_code", [("feasible", 0), ("denied", 1), ("unavailable", 1), ("ambiguous", 1)])
def test_cli_passes_only_feasible_and_always_retains_original_outcome(tmp_path, monkeypatch, status, exit_code):
    report = {"status": status, "stage": "complete", "rsp131_qualified": False}
    monkeypatch.setattr(hosted, "hosted_report", lambda *_args: report)
    target = tmp_path / "outcome.json"
    monkeypatch.setattr(
        hosted.sys,
        "argv",
        ["diagnostic", "--commit", "a" * 40, "--controls-status", "success", "--report", str(target)],
    )
    assert hosted.main() == exit_code
    assert json.loads(target.read_text()) == report and target.stat().st_mode & 0o777 == 0o600
