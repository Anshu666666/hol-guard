"""The DNS experiment encloses both immutable arms and always attempts cleanup."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

from scripts.ci import native_loopback_resolver as resolver


@pytest.fixture(autouse=True)
def isolated_scutil(monkeypatch):
    monkeypatch.setattr(
        resolver,
        "scutil_diagnostics",
        lambda **_kwargs: ({"status": "completed", "exact_zone_present": False}, {"raw": "private-scutil-name"}),
    )


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

        def self_test(self, *, deadline):
            assert 0 < deadline - time.monotonic() <= 5
            return {"status": "completed", "response_verified": True, "traffic": {"received": 1, "answered": 1}}

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

    def diagnostics(**_kwargs):
        row = next(probes)
        return {kind: dict(row) for kind in resolver._QUERIES}

    monkeypatch.setattr(resolver.sys, "platform", "darwin")
    monkeypatch.setattr(resolver, "resolver_diagnostics", diagnostics)
    monkeypatch.setattr(resolver, "LoopbackPTRResponder", Responder)
    monkeypatch.setattr(resolver, "_run_helper", helper)
    monkeypatch.setattr(resolver.secrets, "token_hex", lambda size: "a" * 32)
    return events


def test_one_environment_encloses_paired_command_and_restores_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    events = _experiment(monkeypatch)
    command = ["python", "build_native_qualification_artifacts.py", "--baseline", "base", "--candidate", "candidate"]

    def run(actual):
        assert actual == command
        assert not (tmp_path / "private_samples").exists()
        events.append("both_arms")
        return 0

    monkeypatch.setattr(resolver, "_run_command", run)
    output = tmp_path / "report.json"
    assert resolver.run_wrapped(command, output) == 0
    assert events == ["responder_start", "install", "both_arms", "remove", "responder_stop"]
    report = json.loads(output.read_text())
    for phase in ("before", "after", "after_cleanup"):
        assert set(report[f"probes_{phase}"]) == set(resolver._QUERIES)
        assert report[phase] == report[f"probes_{phase}"]["legacy_getfqdn"]
    assert report["probe_timeout_seconds"] == 5
    assert report["probe_execution"] == "independent_concurrent_subprocesses"
    assert report["before"]["status"] == "deadline_exceeded" and report["after"]["loopback_label"] is True
    assert report["after_cleanup"]["status"] == "deadline_exceeded"
    assert report["configuration_cleanup"] == "completed"
    assert report["environment_scope"] == "disposable_ci_runner_both_arms"
    assert report["private_diagnostics_retained"] is True
    assert "private-scutil-name" not in output.read_text()
    assert len(list((tmp_path / "private_samples").glob("resolver-*-scutil.json"))) == 3
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
    monkeypatch.setattr(
        resolver,
        "resolver_diagnostics",
        lambda **_kwargs: {kind: {"status": "completed", "loopback_label": True} for kind in resolver._QUERIES},
    )

    def forbidden(*_args):
        raise AssertionError("no DNS fixture was needed")

    monkeypatch.setattr(resolver, "LoopbackPTRResponder", forbidden)
    monkeypatch.setattr(resolver, "_run_helper", forbidden)
    monkeypatch.setattr(resolver, "_run_command", lambda command: 9)
    assert resolver.run_wrapped(["both-arms"], tmp_path / "report.json") == 9


def test_workflow_wraps_the_entire_pair_without_hosts_or_cache_mutation() -> None:
    import argparse

    from scripts.native_slo_pair_install import command

    workflow = Path(".github/workflows/native-performance-qualification.yml").read_text()
    assert "--repair-localhost" not in workflow
    arguments = argparse.Namespace(
        action="pair",
        environments=Path("isolated"),
        bundle=Path("bundle"),
        output=Path("evidence"),
        mode="qualification",
        pair_index=3,
        target="x86_64-apple-darwin",
        candidate_sha="a" * 40,
        run_id=1,
        run_attempt=1,
    )
    invocation = command(arguments, {"arms": {arm: {"wheel": arm + ".whl"} for arm in ("baseline", "candidate")}})
    assert "native_loopback_resolver.py" in invocation[1]
    wrapped = invocation[invocation.index("--") + 1 :]
    assert "qualify_guard_native.py" in wrapped[1]
    assert "--baseline-python" in wrapped and "--candidate-python" in wrapped
    assert wrapped[wrapped.index("--pair-index") + 1] == "3"
    assert wrapped[wrapped.index("--runs") + 1] == "5"
    assert "native_slo_pair_install.py --action pair" in workflow
    source = Path(resolver.__file__).read_text()
    assert all(
        token not in source
        for token in (
            "--apply-fixed-entry",
            "--repair-localhost",
            "/etc/hosts",
            "dscacheutil",
            "killall",
        )
    )


def test_workflow_retains_encryption_recipient_and_excludes_plaintext_uploads() -> None:
    import yaml

    workflow = yaml.load(
        Path(".github/workflows/native-performance-qualification.yml").read_text(), Loader=yaml.BaseLoader
    )
    assert "docs/guard/rust-performance/qualification-recipient.pem" in workflow["on"]["pull_request"]["paths"]
    steps = workflow["jobs"]["pairs"]["steps"]
    encryption = next(step for step in steps if step.get("id") == "private-evidence")
    assert encryption["if"] == "always()"
    assert (
        encryption["env"]["QUALIFICATION_RECIPIENT"]
        == "db2d2f3b5002f740768855101840eb4a02ee146d0838d92f8611256f93a7379e"
    )
    assert "native_slo_pair_archive.py" in encryption["run"]
    assert "--pair-root qualification-evidence" in encryption["run"]
    uploads = [step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")]
    assert len(uploads) == 1 and all(step["if"] == "always()" for step in uploads)
    assert {path for step in uploads for path in step["with"]["path"].splitlines()} == {
        "qualification-evidence/aggregate/*.json",
        "qualification-evidence/encrypted/*.hge",
        "qualification-evidence/archive-receipt.json",
    }


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
    assert "github.event.label.name == 'rust-performance-qualification'" in workflow["jobs"]["plan"]["if"]


@pytest.mark.parametrize("kind", ["legacy_getfqdn", "reverse_getnameinfo", "numeric_getnameinfo"])
def test_each_probe_runs_exact_fixed_query_and_retains_no_resolved_names(monkeypatch, kind):
    def run(arguments, **kwargs):
        assert arguments == [resolver.sys.executable, "-I", "-c", resolver._query(kind)]
        assert kwargs["timeout"] == 5 and kwargs["capture_output"] is True
        return subprocess.CompletedProcess(
            arguments, 0, resolver._STARTED + '\n{"loopback_label":false}\n', "private stderr name"
        )

    monkeypatch.setattr(resolver.subprocess, "run", run)
    report = resolver.resolver_probe(kind)
    assert report["status"] == "completed" and report["call_started"] is True
    assert report["loopback_label"] is False
    assert "private" not in json.dumps(report)
    query = resolver._query(kind)
    if kind == "numeric_getnameinfo":
        assert "NI_NUMERICHOST|socket.NI_NUMERICSERV" in query and "NI_NAMEREQD" not in query
    elif kind == "reverse_getnameinfo":
        assert "NI_NAMEREQD|socket.NI_NUMERICSERV" in query


@pytest.mark.parametrize("started", [False, True])
def test_timeout_distinguishes_unstarted_child_from_resolver_call(monkeypatch, started):
    output = (resolver._STARTED + "\n").encode() if started else b"private startup output"

    def run(arguments, **kwargs):
        raise subprocess.TimeoutExpired(arguments, kwargs["timeout"], output=output, stderr=b"private trace")

    monkeypatch.setattr(resolver.subprocess, "run", run)
    report = resolver.resolver_probe()
    assert report["status"] == "deadline_exceeded" and report["call_started"] is started
    assert "private" not in json.dumps(report)


def test_four_distinct_probes_run_concurrently_and_keep_all_outcomes(monkeypatch):
    barrier = threading.Barrier(4)
    deadlines = []
    statuses = dict(
        zip(resolver._QUERIES, ("deadline_exceeded", "failed", "completed", "deadline_exceeded"), strict=True)
    )

    def probe(kind, *, deadline):
        deadlines.append(deadline)
        barrier.wait(timeout=1)
        return {"status": statuses[kind], "call_started": True}

    monkeypatch.setattr(resolver, "resolver_probe", probe)
    report = resolver.resolver_diagnostics()
    assert {kind: row["status"] for kind, row in report.items()} == statuses
    assert len(set(deadlines)) == 1 and 0 < deadlines[0] - time.monotonic() <= 5


def test_expired_shared_phase_budget_never_launches_a_child(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("expired phase must not start another five-second probe")

    monkeypatch.setattr(resolver.subprocess, "run", forbidden)
    result = resolver.resolver_probe(deadline=time.monotonic() - 1)
    assert result["status"] == "deadline_exceeded" and result["call_started"] is False


@pytest.mark.parametrize(
    "stdout",
    [
        '{"loopback_label":true}',
        resolver._STARTED + '\n{"loopback_label":true,"private":"name"}\n',
        resolver._STARTED + '\n{"loopback_label":1}\n',
        resolver._STARTED + '\n{"loopback_label":true}\nextra',
    ],
)
def test_nonconforming_output_cannot_become_completed(monkeypatch, stdout):
    monkeypatch.setattr(
        resolver.subprocess, "run", lambda *args, **_: subprocess.CompletedProcess(args, 0, stdout, "private stderr")
    )
    report = resolver.resolver_probe()
    assert report["status"] == "failed" and "private" not in json.dumps(report)
