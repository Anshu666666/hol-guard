"""Real command bounds and the diagnostic's non-qualifying boundary."""

from __future__ import annotations

import os
import sys

import pytest

pytest.importorskip("resource")

from scripts.ci import native_macos_dtrace_availability as diagnostic


def test_actual_nonzero_command_retains_reason_without_claiming_availability() -> None:
    report = diagnostic._bounded_capture(
        (sys.executable, "-I", "-c", "import sys; sys.stderr.write('provider denied\\n'); sys.exit(1)")
    )
    assert report["return_code"] == 1
    assert report["status"] == "completed"
    assert report["completed_without_intervention"] is True
    assert report["termination_attempted"] is False
    assert report["stderr"] == "provider denied\n"


def test_actual_sleeping_command_cannot_outlive_bound_as_completed() -> None:
    report = diagnostic._bounded_capture(
        (sys.executable, "-I", "-c", "import os,time; print(os.getpid(),flush=True); time.sleep(10)"), timeout=0.1
    )
    assert report["status"] == "deadline_exceeded"
    assert report["termination_attempted"] is True
    assert report["completed_without_intervention"] is False
    assert report["elapsed_ms"] < 1500
    pid = int(report["stdout"])
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_actual_large_write_is_limited_by_kernel() -> None:
    report = diagnostic._bounded_capture((sys.executable, "-I", "-c", "import os; os.write(1,b'x' * (1024 * 1024))"))
    assert report["status"] == "output_limit"
    assert report["stdout_bytes"] == diagnostic._OUTPUT_LIMIT
    assert report["completed_without_intervention"] is False
    assert len(report["stdout"]) == diagnostic._OUTPUT_LIMIT


@pytest.mark.parametrize("available", [True, False])
def test_completed_listing_never_claims_enabled_coverage_or_ownership(
    monkeypatch: pytest.MonkeyPatch, available: bool
) -> None:
    monkeypatch.setattr(diagnostic.sys, "platform", "darwin")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_OS", "macOS")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    calls: list[tuple[str, ...]] = []

    def capture(arguments: tuple[str, ...]) -> dict[str, object]:
        calls.append(arguments)
        return {
            "return_code": 0 if available else 1,
            "stdout": "1 proc kernel fork create\n2 proc kernel exit exit\n3 proc kernel exit exited\n"
            if available
            else "",
            "stderr": "" if available else "system integrity protection is on",
            "completed_without_intervention": True,
        }

    monkeypatch.setattr(diagnostic, "_bounded_capture", capture)
    report = diagnostic.collect()
    assert calls == [diagnostic._CSR, diagnostic._LIST]
    assert report["safe_to_run_cohort"] is True
    assert report["all_required_probes_listed"] is available
    assert report["qualification_pass"] is False
    assert report["ownership_verified"] is False
    assert report["descendant_coverage_verified"] is False
    assert report["enabled_probe_verified"] is False
    assert report["tracing_enabled"] is False
    assert report["security_configuration_modified"] is False


def test_incomplete_command_blocks_cohort(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(diagnostic.sys, "platform", "darwin")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_OS", "macOS")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setattr(
        diagnostic,
        "_bounded_capture",
        lambda _argv: {"return_code": None, "stdout": "", "completed_without_intervention": False},
    )
    report = diagnostic.collect()
    assert report["status"] == "diagnostic_incomplete"
    assert report["safe_to_run_cohort"] is False
    assert report["all_required_probes_listed"] is False


def test_unapproved_environment_does_not_launch_sudo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(diagnostic, "_bounded_capture", lambda _argv: pytest.fail("unexpected command"))
    report = diagnostic.collect()
    assert report["status"] == "not_disposable_macos_ci"
    assert report["safe_to_run_cohort"] is False
