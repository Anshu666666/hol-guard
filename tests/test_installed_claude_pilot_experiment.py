"""The opt-in experiment cannot replace incomplete evidence with a pass."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from codex_plugin_scanner.guard.adapters.claude_hook_config import guard_command_handler
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from scripts.ci import measure_installed_claude_pilot as installed
from scripts.ci import native_claude_pilot_evidence as evidence
from scripts.ci import native_claude_pilot_measure as measurement
from scripts.ci import native_claude_pilot_registration as registration
from scripts.native_slo_contract import assert_privacy_safe, clear_proof_environment, proof_environment_violations
from scripts.native_slo_numeric_journal import recover_numeric_journal
from scripts.native_slo_priority_launchers import RegisteredLauncher


@contextmanager
def _preserved_experiment_environment():
    """In-process worker tests must not change the enclosing pytest process."""

    names = (*proof_environment_violations(), "PYTHONHOME")
    saved = {name: os.environ.get(name) for name in names}
    try:
        yield
    finally:
        for name in {*proof_environment_violations(), *saved}:
            value = saved.get(name)
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@pytest.fixture(autouse=True)
def _restore_experiment_proof_environment():
    with _preserved_experiment_environment():
        yield


def test_in_process_experiment_restores_explicit_and_prefixed_test_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GUARD_PYTEST_DURATION_OUTPUT", "enclosing-report.json")
    monkeypatch.setenv("GUARD_PYTEST_UNDER_COVERAGE", "1")
    monkeypatch.setenv("PYTHONHOME", "enclosing-python-home")
    with _preserved_experiment_environment():
        clear_proof_environment()
        os.environ.pop("PYTHONHOME")
        assert "GUARD_PYTEST_DURATION_OUTPUT" not in os.environ
        assert "GUARD_PYTEST_UNDER_COVERAGE" not in os.environ
        os.environ["GUARD_PYTEST_LATE_FIXTURE_OVERRIDE"] = "created-inside"
    assert os.environ["GUARD_PYTEST_DURATION_OUTPUT"] == "enclosing-report.json"
    assert os.environ["GUARD_PYTEST_UNDER_COVERAGE"] == "1"
    assert os.environ["PYTHONHOME"] == "enclosing-python-home"
    assert "GUARD_PYTEST_LATE_FIXTURE_OVERRIDE" not in os.environ


@pytest.fixture
def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    session = SimpleNamespace(root=tmp_path, workspace=tmp_path / "workspace", guard_home=tmp_path / ".hol-guard")
    session.workspace.mkdir()
    session.guard_home.mkdir()
    config = {
        "foreign": {"preserve": True},
        "hooks": {
            event: [
                {
                    "matcher": "Bash|Read",
                    "hooks": [
                        guard_command_handler(
                            (sys.executable, "-c", "HOL_GUARD_CLAUDE_DAEMON_HOOK"),
                            timeout=30,
                        )
                    ],
                }
            ]
            for event in (*registration.EVENTS, "PermissionRequest")
        },
    }

    class Adapter:
        def install(self, context: Any) -> dict[str, bool]:
            path = context.home_dir / ".claude" / "settings.json"
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps(config))
            return {"active": True}

    monkeypatch.setattr(registration, "ClaudeCodeHarnessAdapter", Adapter)
    monkeypatch.setattr(
        registration,
        "prepare",
        lambda **args: (
            str(tmp_path / "runtime"),
            "claude-launcher-v1",
            "--config",
            str(tmp_path / "bound.json"),
            "--config-sha256",
            "a" * 64,
            "--event",
            args["event"],
        ),
    )
    return session, registration.PilotRegistration(session), config


def test_only_explicit_fixture_handlers_change_and_original_registration_is_restored(prepared) -> None:
    _session, pair, original = prepared
    before = pair.path.read_bytes()
    selected = pair.activate("native_pilot", "PreToolUse")
    assert selected.argv == pair.native["PreToolUse"]
    after = json.loads(pair.path.read_bytes())
    assert after["foreign"] == original["foreign"]
    assert after["hooks"]["PermissionRequest"] == original["hooks"]["PermissionRequest"]
    for event in registration.EVENTS:
        assert after["hooks"][event][0]["matcher"] == "Bash|Read"
        assert after["hooks"][event][0]["hooks"][0]["timeout"] == 30
    pair.restore()
    assert pair.path.read_bytes() == before
    assert pair.activate("optimized_python", "PostToolUse").argv == pair.python["PostToolUse"].argv


def test_changed_registration_is_not_executed_or_silently_overwritten(prepared) -> None:
    _session, pair, _original = prepared
    pair.path.write_text('{"changed":true}')
    with pytest.raises(RuntimeError, match="registration_invalid"):
        pair.activate("native_pilot", "PreToolUse")
    with pytest.raises(RuntimeError, match="registration_invalid"):
        pair.restore()
    assert pair.path.read_text() == '{"changed":true}'


@pytest.mark.parametrize("arm,event", [("native", "PreToolUse"), ("native_pilot", "PermissionRequest")])
def test_unadmitted_registration_scope_rejects(prepared, arm: str, event: str) -> None:
    with pytest.raises(RuntimeError, match="registration_invalid"):
        prepared[1].activate(arm, event)


def test_actual_returned_failure_is_recorded_before_semantic_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    metrics = SimpleNamespace(snapshot=lambda: {})
    session = SimpleNamespace(
        root=tmp_path,
        workspace=tmp_path,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics))),
    )
    result = BoundedHookProcessResult(3, "not JSON", False, False, stderr="synthetic diagnostic")
    calls = []

    def launch(argv, **kwargs):
        calls.append((argv, kwargs))
        return result

    monkeypatch.setattr(measurement, "run_isolated_hook_process", launch)
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", "must-not-be-inherited")
    values = []
    attempt = measurement.Attempt()
    selected = RegisteredLauncher(
        "claude-code", "PreToolUse", (str(tmp_path / "runtime"), "exact"), (), "a" * 64, tmp_path
    )
    with pytest.raises(RuntimeError, match="process_contract"):
        measurement.observe(session, selected, sample=9, case="benign", attempt=attempt, record=values.extend)
    assert len(values) == 1 and values[0] >= 0
    assert attempt.returncode == 3 and attempt.stderr_present
    assert attempt.captured_stdout_sha256 == hashlib.sha256(b"not JSON").hexdigest()
    assert attempt.captured_stdout_bytes == len(b"not JSON")
    assert attempt.captured_stderr_sha256 == hashlib.sha256(b"synthetic diagnostic").hexdigest()
    assert calls[0][0] == selected.argv
    assert "HOL_GUARD_NATIVE_BINARY" not in calls[0][1]["environment"]
    assert json.loads(calls[0][1]["input_text"])["tool_use_id"] == "priority-qualification-9"


def test_native_availability_allow_is_not_counted_as_authoritative_allow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    metrics = SimpleNamespace(snapshot=lambda: {})
    session = SimpleNamespace(
        root=tmp_path,
        workspace=tmp_path,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics))),
    )
    value = {
        "continue": True,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": (
                "HOL Guard could not reach the local daemon (fixture) and continued this action without native review."
            ),
        },
    }
    monkeypatch.setattr(
        measurement,
        "run_isolated_hook_process",
        lambda *_args, **_kwargs: BoundedHookProcessResult(0, json.dumps(value), False, False),
    )
    selected = RegisteredLauncher("claude-code", "PreToolUse", ("/fixture/runtime",), (), "a" * 64, tmp_path)
    attempt = measurement.Attempt()
    elapsed = []
    with pytest.raises(RuntimeError, match="policy_mismatch"):
        measurement.observe(session, selected, sample=0, case="benign", attempt=attempt, record=elapsed.extend)
    assert attempt.delivery == "availability" and len(elapsed) == 1


@pytest.mark.parametrize(
    "after,state,counts",
    [
        ({"routes": {"native_resident": 67}}, "captured", {"native_resident": 67}),
        ({"routes": {"native_resident": 0}}, "captured", {"native_resident": 0}),
        ({"routes": {"native_degraded": 1}}, "captured", {"native_degraded": 1}),
        ({"routes": {}}, "captured", {}),
        (None, "invalid", {}),
        ({}, "invalid", {}),
        ({"routes": []}, "invalid", {}),
        ({"routes": {"PRIVATE /home/person": 1}}, "invalid", {}),
        ({"routes": {"native_resident": True}}, "invalid", {}),
        ({"routes": {"native_resident": -1}}, "invalid", {}),
        ({"routes": {"native_resident": 1_000_001}}, "invalid", {}),
        ({"routes": {str(index): 1 for index in range(6)}}, "invalid", {}),
        (RuntimeError("PRIVATE snapshot transport detail"), "unavailable", {}),
    ],
)
def test_empty_post_reply_keeps_one_after_snapshot_without_changing_rejection_or_timing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    after: object,
    state: str,
    counts: dict[str, int],
) -> None:
    calls = []
    snapshots = iter(({"routes": {"native_resident": 66}}, after))

    def snapshot():
        calls.append("snapshot")
        value = next(snapshots)
        if isinstance(value, Exception):
            raise value
        return value

    metrics = SimpleNamespace(snapshot=snapshot)
    session = SimpleNamespace(
        root=tmp_path,
        workspace=tmp_path,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics))),
    )

    def launch(*_args, **_kwargs):
        calls.append("process")
        return BoundedHookProcessResult(0, "{}", False, False)

    rejected = []
    validator = measurement.validate_launcher_stdout

    def validate(*args, **kwargs):
        calls.append("validate")
        try:
            validator(*args, **kwargs)
        except RuntimeError as error:
            rejected.append(error)
            raise

    def do_not_wait(*_args, **_kwargs):
        pytest.fail("A rejected reply must not poll for a route counter or infer a route")

    values = []

    def record(samples):
        calls.append("record")
        values.extend(samples)

    ticks = iter((1.0, 1.25))
    monkeypatch.setattr(measurement.time, "perf_counter", lambda: next(ticks))
    monkeypatch.setattr(measurement, "run_isolated_hook_process", launch)
    monkeypatch.setattr(measurement, "validate_launcher_stdout", validate)
    monkeypatch.setattr(measurement, "wait_for_route_corpus", do_not_wait)
    monkeypatch.setattr(measurement, "witnessed_route", do_not_wait)
    selected = RegisteredLauncher("claude-code", "PostToolUse", ("/fixture/runtime",), (), "a" * 64, tmp_path)
    attempt = measurement.Attempt()
    with pytest.raises(RuntimeError, match="priority_launcher_event_mismatch") as raised:
        measurement.observe(session, selected, sample=14, case="benign", attempt=attempt, record=record)
    assert raised.value is rejected[0]
    assert calls == ["snapshot", "process", "record", "validate", "snapshot"]
    assert values == [250.0]
    assert attempt.route_before == {"native_resident": 66}
    assert attempt.route_after == counts
    assert attempt.route_after_state == state
    assert attempt.route_after_scope == "semantic_rejection_snapshot"
    assert attempt.route == "unknown" and attempt.stage == "delivery"
    assert attempt.delivery == "empty_response"
    assert attempt.captured_stdout_sha256 == hashlib.sha256(b"{}").hexdigest()
    assert assert_privacy_safe(vars(attempt)) == vars(attempt)
    assert "PRIVATE" not in json.dumps(vars(attempt))


def test_valid_post_reply_keeps_original_route_check_without_diagnostic_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def snapshot():
        calls.append("snapshot")
        return {"routes": {"native_resident": 66}}

    metrics = SimpleNamespace(snapshot=snapshot)
    session = SimpleNamespace(
        root=tmp_path,
        workspace=tmp_path,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics))),
    )
    response = {"hookSpecificOutput": {"hookEventName": "PostToolUse"}, "policy_action": "allow"}

    def launch(*_args, **_kwargs):
        calls.append("process")
        return BoundedHookProcessResult(0, json.dumps(response), False, False)

    def original_route_check(given_metrics, *, expected):
        assert given_metrics is metrics and expected == 67
        calls.append("route_check")
        return {"routes": {"native_resident": 67}}

    monkeypatch.setattr(measurement, "run_isolated_hook_process", launch)
    monkeypatch.setattr(measurement, "wait_for_route_corpus", original_route_check)
    selected = RegisteredLauncher("claude-code", "PostToolUse", ("/fixture/runtime",), (), "a" * 64, tmp_path)
    attempt = measurement.Attempt()
    values = []
    measurement.observe(session, selected, sample=14, case="benign", attempt=attempt, record=values.extend)
    assert calls == ["snapshot", "process", "route_check"]
    assert len(values) == 1
    assert attempt.route_after == {"native_resident": 67}
    assert attempt.route_after_state == "captured"
    assert attempt.route_after_scope == "validated_delivery_route_check"
    assert attempt.route == "native_resident" and attempt.stage == "complete"


@pytest.mark.parametrize(
    "sample,run,first", [(0, 0, "optimized_python"), (1, 0, "native_pilot"), (0, 1, "native_pilot")]
)
def test_pair_order_is_counterbalanced(sample: int, run: int, first: str) -> None:
    assert measurement._pair_order(sample, run)[0] == first


def test_all_offered_numeric_samples_are_retained_when_native_fails(
    prepared, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    session, pair, _ = prepared
    samples = tmp_path / "samples"
    samples.mkdir(mode=0o700)
    progress = {}

    def observe(_session, launcher, *, sample, case, attempt, record):
        record([12.5])
        attempt.stage = "delivery"
        if sample == 0 and launcher.argv[1] == "claude-launcher-v1":
            attempt.delivery = "availability"
            raise RuntimeError("synthetic native failure")
        return "b" * 64

    monkeypatch.setattr(measurement, "observe", observe)
    with pytest.raises(RuntimeError, match="synthetic native failure"):
        measurement.measure(session, pair, iterations=3, run_index=0, private_samples=samples, progress=progress)
    assert progress["planned"] == 20 and progress["completed"] == 9
    assert progress["attempt"]["delivery"] == "availability"
    for path in samples.glob("*ToolUse.jsonl"):
        evidence = recover_numeric_journal(path)
        assert evidence["qualification_complete"] is False and evidence["collection_complete"] is False
        assert evidence["batches"][-1]["offered"] == 3
        assert evidence["batches"][-1]["status"] == "failed"
    native = recover_numeric_journal(samples / "native_pilot-PreToolUse.jsonl")
    assert native["series"]["INSTALLED_LAUNCHER.native_pilot.PreToolUse"] == [12.5]
    outcomes = [json.loads(line) for line in (samples / "outcomes.jsonl").read_text().splitlines()]
    assert outcomes[-1]["kind"] == "terminal" and outcomes[-1]["status"] == "failed"
    assert outcomes[1]["kind"] == "plan" and outcomes[1]["planned_attempts"] == 20
    assert outcomes[-1]["observed"]["delivery"] == "availability"
    assert len([row for row in outcomes if row["kind"] == "offered"]) == 10


def test_success_retains_pair_counts_and_does_not_claim_qualification(
    prepared, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    session, pair, _ = prepared
    samples = tmp_path / "samples"
    samples.mkdir(mode=0o700)
    progress = {}

    def observe(_session, _launcher, *, sample, case, attempt, record):
        record([10.0])
        return "b" * 64

    monkeypatch.setattr(measurement, "observe", observe)
    result = measurement.measure(session, pair, iterations=2, run_index=1, private_samples=samples, progress=progress)
    assert len(result) == 4 and progress["completed"] == progress["planned"] == 16
    for path in samples.glob("*ToolUse.jsonl"):
        evidence = recover_numeric_journal(path)
        assert evidence["collection_complete"] is True and evidence["qualification_complete"] is False
    outcomes = [json.loads(line) for line in (samples / "outcomes.jsonl").read_text().splitlines()]
    assert outcomes[-1]["kind"] == "collection_complete"
    pairs = [row for row in outcomes if row["kind"] == "pair"]
    assert len(pairs) == 8 and all(row["full_response_equal"] for row in pairs)


def test_setup_failure_is_publicly_bounded_and_preserved_privately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_args):
        raise RuntimeError("untrusted fixture body /home/example must not be printed")

    monkeypatch.setattr(installed, "installed_identity", fail)
    report = installed.run(
        wheel=tmp_path / "absent.whl", build_sha="a" * 40, iterations=2, run_index=0, output=tmp_path / "evidence"
    )
    assert report["contracts_passed"] is False and report["qualification_complete"] is False
    assert report["production_selected"] is False
    assert assert_privacy_safe(report) == report
    assert "untrusted" not in json.dumps(report)
    assert (tmp_path / "evidence/private_samples/attempt-summary.json").is_file()


def test_complete_worker_summary_binds_both_arms_and_reports_target_misses(
    prepared, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session, pair, _ = prepared
    session.readiness_ms = 10.0

    class Fixture:
        def __enter__(self):
            return session

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(installed, "DaemonFixture", lambda *_args, **_kwargs: Fixture())
    monkeypatch.setattr(installed, "PilotRegistration", lambda _session: pair)
    monkeypatch.setattr(
        installed, "installed_identity", lambda *_args: (tmp_path / "runtime", {"wheel_sha256": "a" * 64})
    )
    preflight_calls = []

    def diagnostic(*args):
        preflight_calls.append(args)
        return {"observer_error": True, "authorization_evidence": False}

    monkeypatch.setattr(installed, "windows_discovery_preflight", diagnostic)

    def observe(_session, _launcher, *, sample, case, attempt, record):
        assert len(preflight_calls) == 1
        record([120.0])
        return "b" * 64

    monkeypatch.setattr(measurement, "observe", observe)
    report = installed.run(
        wheel=tmp_path / "fixture.whl", build_sha="a" * 40, iterations=2, run_index=0, output=tmp_path / "complete"
    )
    assert report["contracts_passed"] is True
    assert report["discovery_preflight"] == {"observer_error": True, "authorization_evidence": False}
    assert preflight_calls == [(session.guard_home, Path(pair.native["PreToolUse"][3]), pair.native["PreToolUse"][5])]
    assert report["qualification_complete"] is False and report["production_selected"] is False
    assert report["fixture_registration_restored"] is True
    assert len(report["registrations"]) == 4
    for series in report["latency"].values():
        assert series["latency"]["count"] == 2
        assert series["sampled_p95_within_50ms"] is False
        assert series["sampled_p99_within_100ms"] is False
    assert json.loads((tmp_path / "complete/summary.json").read_text()) == report


def test_workflow_is_opt_in_and_never_uploads_plain_observations() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/native-claude-launcher-experiment.yml").read_text())
    assert set(workflow[True]) == {"workflow_dispatch", "pull_request"}
    assert workflow[True]["pull_request"]["types"] == ["opened", "synchronize", "reopened", "labeled"]
    assert workflow[True]["pull_request"]["branches"] == ["main", "release/3.2"]
    assert workflow["concurrency"]["cancel-in-progress"] is False
    assert "github.run_id" in workflow["concurrency"]["group"]
    assert "github.run_attempt" in workflow["concurrency"]["group"]
    job = workflow["jobs"]["paired-launchers"]
    assert "github.event_name == 'workflow_dispatch' ||" in job["if"]
    assert "github.event.pull_request.head.repo.full_name == github.repository &&" in job["if"]
    assert "contains(github.event.pull_request.labels.*.name, 'native-claude-launcher-experiment') &&" in job["if"]
    assert (
        "github.event.action != 'labeled' || github.event.label.name == 'native-claude-launcher-experiment'"
        in job["if"]
    )
    assert job["steps"][0]["with"]["ref"] == "${{ github.event.pull_request.head.sha || github.sha }}"
    assert job["env"]["PILOT_SOURCE_SHA"] == job["steps"][0]["with"]["ref"]
    assert job["strategy"]["matrix"]["run"] == list(range(5))
    assert len(job["strategy"]["matrix"]["platform"]) == 4
    uploads = [step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/upload-artifact@")]
    assert len(uploads) == 2 and all(step["if"] == "always()" for step in uploads)
    assert all("private_samples" not in step["with"]["path"] and "*." not in step["with"]["path"] for step in uploads)
    seal = next(step for step in job["steps"] if step.get("name") == "Encrypt all retained synthetic observations")
    assert seal["if"] == "always()" and "uv run --frozen" in seal["run"]
    final = job["steps"][-1]
    assert final["if"] == "always()" and final.get("continue-on-error") is not True
    for name in ("SEAL_OUTCOME", "AGGREGATE_OUTCOME", "ENCRYPTED_OUTCOME", "AGGREGATE_ID", "ENCRYPTED_ID"):
        assert name in final["env"] and f'"${name}"' in final["run"]
    assert "native_claude_pilot_evidence.py" in final["run"]


def _validate_environment_scope(workflow: dict) -> None:
    environment = "${{ runner.temp }}/claude-pilot-environment"
    # GitHub admits runner context in step env, not workflow or job env.
    for scope in (workflow, *workflow["jobs"].values()):
        for value in scope.get("env", {}).values():
            assert not re.search(r"\brunner\s*[.\[]", str(value)), "runner context outside step scope"
    consumers = [
        step
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if re.search(r"\buv\s+(?:sync|run)\b", step.get("run", ""))
    ]
    assert len(consumers) == 6
    for step in consumers:
        assert step.get("env", {}).get("UV_PROJECT_ENVIRONMENT") == environment, "external environment missing"


@pytest.mark.parametrize("mutation", [None, "workflow_scope", "job_scope", "archive_step", "final_gate"])
def test_uv_environment_has_valid_context_at_every_consumer(mutation: str | None) -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/native-claude-launcher-experiment.yml").read_text())
    job = workflow["jobs"]["paired-launchers"]
    if mutation in {"workflow_scope", "job_scope"}:
        scope = workflow if mutation == "workflow_scope" else job
        scope.setdefault("env", {})["UV_PROJECT_ENVIRONMENT"] = "${{ runner.temp }}/claude-pilot-environment"
    elif mutation == "archive_step":
        next(step for step in job["steps"] if step.get("id") == "seal")["env"].clear()
    elif mutation == "final_gate":
        job["steps"][-1]["env"].pop("UV_PROJECT_ENVIRONMENT")
    if mutation is None:
        _validate_environment_scope(workflow)
    else:
        with pytest.raises(AssertionError, match=r"runner context outside step scope|external environment missing"):
            _validate_environment_scope(workflow)


def test_mismatching_whole_responses_retain_false_pair_before_rejecting(
    prepared, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session, pair, _ = prepared
    samples = tmp_path / "samples"
    samples.mkdir(mode=0o700)

    def observe(_session, launcher, *, sample, case, attempt, record):
        record([5.0])
        return "a" * 64 if launcher.argv[1] == "claude-launcher-v1" else "b" * 64

    monkeypatch.setattr(measurement, "observe", observe)
    with pytest.raises(RuntimeError, match="full_response_mismatch"):
        measurement.measure(session, pair, iterations=2, run_index=0, private_samples=samples, progress={})
    rows = [json.loads(line) for line in (samples / "outcomes.jsonl").read_text().splitlines()]
    assert rows[1]["planned_attempts"] == 16
    assert rows[-1]["kind"] == "pair" and rows[-1]["full_response_equal"] is False
    assert rows[-1]["attempts"] == [1, 2]
    assert not any(row["kind"] == "collection_complete" for row in rows)


def test_hard_interruption_retains_plan_and_unfinished_offer(tmp_path: Path) -> None:
    path = tmp_path / "outcomes.jsonl"
    code = "\n".join(
        [
            "import os",
            "from pathlib import Path",
            "from scripts.ci.native_claude_pilot_evidence import OutcomeJournal",
            f"with OutcomeJournal(Path({str(path)!r})) as journal:",
            "    journal.append({'kind': 'plan', 'planned_attempts': 88, 'run_index': 3})",
            "    journal.append({'kind': 'offered', 'attempt': 1}, reserve=2)",
            "    os._exit(9)",
        ]
    )
    result = subprocess.run([sys.executable, "-c", code], check=False, timeout=20, capture_output=True)
    assert result.returncode == 9
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["kind"] for row in rows] == ["header", "plan", "offered"]
    assert rows[1]["planned_attempts"] == 88 and rows[1]["run_index"] == 3
    assert rows[0]["capture_identity"] == "utf8_reencoded_contained_capture"


@pytest.mark.parametrize(
    "mutation",
    [
        {},
        {"status": "no_observations"},
        {"schema": "unknown"},
        {"archive_created": False},
        {"files": 5},
        {"files": "6"},
        {"recipient_key_id": "0" * 64},
        {"archive_bytes": 1},
        {"archive_sha256": "0" * 64},
    ],
)
def test_retention_requires_exact_encrypted_receipt_and_archive(tmp_path: Path, mutation: dict) -> None:
    archive = tmp_path / "archive.enc"
    archive.write_bytes(b"synthetic ciphertext")
    receipt = tmp_path / "receipt.json"
    value = {
        "schema": "hol-guard.native-qualification-archive-receipt.v1",
        "status": "encrypted",
        "archive_created": True,
        "files": 6,
        "recipient_key_id": evidence.RECIPIENT_ID,
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        **mutation,
    }
    receipt.write_text(json.dumps(value))
    if mutation:
        with pytest.raises(RuntimeError, match="retention_incomplete"):
            evidence.verify_retention(receipt, archive)
    else:
        evidence.verify_retention(receipt, archive)
        archive.write_bytes(b"different ciphertext")
        with pytest.raises(RuntimeError, match="retention_incomplete"):
            evidence.verify_retention(receipt, archive)
