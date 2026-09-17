"""The DNS experiment encloses both immutable arms and always attempts cleanup."""

from __future__ import annotations

import json
import subprocess
import sys
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

from scripts.ci import native_loopback_resolver as resolver


def test_probe_timeout_never_exposes_child_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert arguments[1:3] == ["-I", "-c"] and kwargs["timeout"] == 5
        assert "getfqdn('127.0.0.1')" in arguments[-1]
        raise subprocess.TimeoutExpired(arguments, 5, output="private-fixture-name")

    monkeypatch.setattr(resolver.subprocess, "run", timeout)
    report = resolver.resolver_probe()
    assert report["status"] == "deadline_exceeded"
    assert "private-fixture-name" not in json.dumps(report)


def test_helper_is_isolated_bounded_and_accepts_no_mutation_path(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert arguments[:4] == ["sudo", "-n", sys.executable, "-I"]
        assert Path(arguments[4]).name == "native_loopback_dns.py"
        assert arguments[5:] == ["--operation", "install", "--port", "54321", "--owner", "a" * 32]
        assert kwargs == {"capture_output": True, "timeout": 10, "check": False}
        return subprocess.CompletedProcess(arguments, 2, stdout=b"", stderr=b"private-fixture-name")

    monkeypatch.setattr(resolver.subprocess, "run", run)
    assert resolver._run_helper("install", 54321, "a" * 32) == "existing_configuration"


def _experiment(monkeypatch: pytest.MonkeyPatch, *, install: str = "completed", cleanup: str = "completed"):
    events = []

    class Responder:
        port = 54321

        def __enter__(self):
            events.append("responder_start")
            return self

        def __exit__(self, *_args):
            events.append("responder_stop")

        def snapshot(self):
            return {"received": 1, "answered": 1, "rejected": 0, "errors": 0}

    def helper(operation, port, owner):
        assert port == 54321 and owner == "a" * 32
        events.append(operation)
        return install if operation == "install" else cleanup

    probes = iter(
        [
            {"status": "deadline_exceeded", "loopback_label": False, "elapsed_ms": 5000},
            {"status": "completed", "loopback_label": True, "elapsed_ms": 1},
            {"status": "deadline_exceeded", "loopback_label": False, "elapsed_ms": 5000},
        ]
    )
    monkeypatch.setattr(resolver.sys, "platform", "darwin")
    monkeypatch.setattr(resolver, "resolver_probe", lambda: next(probes))
    monkeypatch.setattr(resolver, "LoopbackPTRResponder", Responder)
    monkeypatch.setattr(resolver, "_run_helper", helper)
    monkeypatch.setattr(resolver, "responder_probe", lambda port: {"passed": True, "requests": 1})
    monkeypatch.setattr(resolver, "owned_configuration", lambda *_args: {"owned_bytes_match": True})
    monkeypatch.setattr(resolver, "system_configuration", lambda _port: {"exact_resolver_selected": False})
    monkeypatch.setattr(resolver.secrets, "token_hex", lambda size: "a" * 32)
    return events


def test_one_environment_encloses_paired_command_and_restores_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events = _experiment(monkeypatch)
    command = ["python", "build_native_qualification_artifacts.py", "--baseline", "base", "--candidate", "candidate"]

    def run(actual):
        assert actual == command
        events.append("both_arms")
        return 0

    monkeypatch.setattr(resolver, "_run_command", run)
    output = tmp_path / "report.json"
    assert resolver.run_wrapped(command, output) == 0
    assert events == ["responder_start", "install", "both_arms", "remove", "responder_stop"]
    report = json.loads(output.read_text())
    assert report["before"]["status"] == "deadline_exceeded" and report["after"]["loopback_label"] is True
    assert report["after_cleanup"]["status"] == "deadline_exceeded"
    assert report["configuration_cleanup"] == "completed"
    assert report["configuration_readback"]["owned_bytes_match"] is True
    assert report["system_configuration_after_install"]["exact_resolver_selected"] is False
    assert report["responder"]["received"] == 1 and report["resolver_packets_received"] == 0
    assert report["environment_scope"] == "disposable_ci_runner_both_arms"
    assert all(
        report[key] is False
        for key in ("runtime_patched", "baseline_artifact_modified", "fixture_deadline_changed", "qualification_pass")
    )


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_command_exception_still_cleans_owned_configuration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure
) -> None:
    events = _experiment(monkeypatch)

    def run(_command):
        raise failure("private-child-diagnostic")

    monkeypatch.setattr(resolver, "_run_command", run)
    output = tmp_path / "report.json"
    with pytest.raises(failure):
        resolver.run_wrapped(["command"], output)
    assert events == ["responder_start", "install", "remove", "responder_stop"]
    report = json.loads(output.read_text())
    assert report["configuration_cleanup"] == "completed"
    assert "private-child-diagnostic" not in output.read_text()


@pytest.mark.parametrize(
    ("install", "cleanup", "command_code", "expected"),
    [
        ("existing_configuration", "refused_unowned", 0, 0),
        ("deadline_exceeded", "completed", 7, 7),
        ("completed", "refused_unowned", 0, 1),
        ("completed", "failed", 8, 8),
    ],
)
def test_setup_failure_preserves_command_outcome_and_cleanup_failure_blocks_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, install: str, cleanup: str, command_code: int, expected: int
) -> None:
    events = _experiment(monkeypatch, install=install, cleanup=cleanup)
    monkeypatch.setattr(resolver, "_run_command", lambda command: command_code)
    output = tmp_path / "report.json"
    assert resolver.run_wrapped(["both-arms"], output) == expected
    if install == "existing_configuration":
        assert "remove" not in events
        assert json.loads(output.read_text())["configuration_cleanup"] == "not_owned"
    else:
        assert "remove" in events


@pytest.mark.parametrize("platform", ["darwin", "linux", "win32"])
def test_healthy_or_other_platform_execution_does_not_configure_dns(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, platform: str
) -> None:
    monkeypatch.setattr(resolver.sys, "platform", platform)
    monkeypatch.setattr(resolver, "resolver_probe", lambda: {"status": "completed", "loopback_label": True})

    def forbidden(*_args):
        raise AssertionError("no DNS fixture was needed")

    monkeypatch.setattr(resolver, "LoopbackPTRResponder", forbidden)
    monkeypatch.setattr(resolver, "_run_helper", forbidden)
    monkeypatch.setattr(resolver, "_run_command", lambda command: 9)
    assert resolver.run_wrapped(["both-arms"], tmp_path / "report.json") == 9


def test_workflow_wraps_the_entire_pair_without_hosts_or_cache_mutation() -> None:
    workflow = Path(".github/workflows/native-performance-qualification.yml").read_text()
    assert "--repair-localhost" not in workflow
    lines = [line.strip() for line in workflow.splitlines()]
    start = lines.index("python candidate-src/scripts/ci/native_loopback_resolver.py \\")
    assert lines[start + 1] == "--output qualification-evidence/aggregate/runner-resolver.json -- \\"
    assert lines[start + 2] == "python candidate-src/scripts/build_native_qualification_artifacts.py \\"
    assert "--baseline baseline-src --candidate candidate-src" in workflow


@pytest.mark.parametrize(
    "path",
    [
        "src/codex_plugin_scanner/guard/runtime/lockfile_text_projection.py",
        "src/codex_plugin_scanner/guard/runtime/supply_chain_bundle_index.py",
        "src/codex_plugin_scanner/guard/secrets/secret_detection.py",
        "src/codex_plugin_scanner/guard/proxy/remote.py",
        "src/codex_plugin_scanner/guard/store_evidence.py",
        "src/codex_plugin_scanner/guard/inventory_contract.py",
        "scripts/bench_guard_secret_scans.py",
        "scripts/bench_guard_package_matrix.py",
        "scripts/profile_guard_package.py",
        "tests/test_guard_supply_chain_evaluator.py",
    ],
)
def test_qualification_path_filters_include_selected_python_routes_and_harness_inputs(path: str) -> None:
    import yaml

    workflow = yaml.load(
        Path(".github/workflows/native-performance-qualification.yml").read_text(), Loader=yaml.BaseLoader
    )
    paths = workflow["on"]["pull_request"]["paths"]
    assert any(fnmatchcase(path, pattern) for pattern in paths)
    assert not any(fnmatchcase("docs/unrelated.md", pattern) for pattern in paths)
    assert workflow["permissions"] == {"contents": "read"}
    assert "head.repo.full_name == github.repository" in str(workflow)
    assert "github.event.label.name == 'rust-performance-qualification'" in workflow["jobs"]["paired-artifacts"]["if"]
