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


def _capture_child_command(monkeypatch, root, tracer):
    from scripts import sqlite_syscall_probe_supervision as supervision

    captured = []

    class CapturedBeforeLaunchError(Exception):
        pass

    def capture(command, **options):
        captured.append((command, options))
        raise CapturedBeforeLaunchError

    monkeypatch.setattr(supervision.subprocess, "Popen", capture)
    with pytest.raises(CapturedBeforeLaunchError):
        supervision._run_child(root, tracer)
    assert len(captured) == 1
    return captured[0]


def _assert_scoped_trace_command(command, options, baseline):
    """Independent finite contract for identity, privacy and observation scope."""
    from scripts import sqlite_syscall_probe_supervision as supervision

    assert command[0] == "/synthetic/bin/strace" and command[-3:] == baseline
    assert options == {
        "stdin": supervision.subprocess.DEVNULL,
        "stdout": supervision.subprocess.PIPE,
        "stderr": supervision.subprocess.PIPE,
        "start_new_session": True,
    }
    flags = set()
    qualifiers = {}
    remaining = iter(command[1:-3])
    for argument in remaining:
        if argument in {"-D", "-f", "-yy"}:
            assert argument not in flags
            flags.add(argument)
        else:
            assert argument == "-e"
            key, separator, value = next(remaining, "").partition("=")
            assert separator and key not in qualifiers
            qualifiers[key] = value
    assert flags == {"-D", "-f", "-yy"}
    assert qualifiers == {
        "quiet": "attach",
        "trace": "open,openat,close,dup,dup2,dup3,fcntl,write,pwrite64,writev,pwritev,pwritev2,fsync,fdatasync",
        "raw": "write,pwrite64,writev,pwritev,pwritev2",
    }


def test_observed_launch_suppresses_only_attach_status_and_preserves_baseline(monkeypatch, tmp_path):
    from scripts import sqlite_syscall_probe_supervision as supervision

    baseline, baseline_options = _capture_child_command(monkeypatch, tmp_path, None)
    assert baseline == [
        supervision.sys.executable,
        str(Path(supervision.__file__).with_name("sqlite_syscall_probe_child.py")),
        str(tmp_path),
    ]
    command, options = _capture_child_command(monkeypatch, tmp_path, "/synthetic/bin/strace")
    assert options == baseline_options
    _assert_scoped_trace_command(command, options, baseline)


@pytest.mark.parametrize(
    "mutation",
    [
        "remove-D",
        "remove-f",
        "remove-yy",
        "separate-process-group",
        "missing-quiet",
        "quiet-all",
        "quiet-exit",
        "quiet-mixed",
        "missing-trace",
        "trace-all",
        "trace-missing-sync",
        "missing-raw",
        "raw-missing-writev",
        "output-file",
        "broad-quiet-flag",
        "unowned-session",
        "discard-stderr",
    ],
)
def test_scope_contract_rejects_identity_filter_privacy_and_quiet_mutations(monkeypatch, tmp_path, mutation):
    baseline, _ = _capture_child_command(monkeypatch, tmp_path, None)
    original, original_options = _capture_child_command(monkeypatch, tmp_path, "/synthetic/bin/strace")
    command, options = list(original), dict(original_options)
    if mutation.startswith("remove-"):
        command.remove("-" + mutation.removeprefix("remove-"))
    elif mutation == "separate-process-group":
        command[command.index("-D")] = "-DD"
    elif mutation.startswith("missing-"):
        qualifier = mutation.removeprefix("missing-")
        index = next(i for i, value in enumerate(command) if value.startswith(qualifier + "="))
        del command[index - 1 : index + 1]
    elif mutation.startswith("quiet-"):
        replacement = {"quiet-all": "quiet=all", "quiet-exit": "quiet=exit", "quiet-mixed": "quiet=attach,exit"}[
            mutation
        ]
        command[command.index("quiet=attach")] = replacement
    elif mutation.startswith("trace-"):
        index = next(i for i, value in enumerate(command) if value.startswith("trace="))
        command[index] = "trace=all" if mutation == "trace-all" else command[index].replace(",fsync", "")
    elif mutation == "raw-missing-writev":
        index = next(i for i, value in enumerate(command) if value.startswith("raw="))
        command[index] = command[index].replace(",writev", "")
    elif mutation == "output-file":
        command[1:1] = ["-o", "/synthetic-output"]
    elif mutation == "broad-quiet-flag":
        command.insert(1, "-qq")
    elif mutation == "unowned-session":
        options["start_new_session"] = False
    else:
        assert mutation == "discard-stderr"
        options["stderr"] = options["stdin"]
    with pytest.raises(AssertionError):
        _assert_scoped_trace_command(command, options, baseline)
