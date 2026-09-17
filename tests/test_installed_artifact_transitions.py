"""Replacement evidence binds actual artifacts, persistent floors and failures."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError
from codex_plugin_scanner.guard.store import GuardStore
from scripts.ci import installed_artifact_transition_probe as probe
from scripts.ci import verify_installed_artifact_transitions as driver
from scripts.ci.installed_transition_state import write_private
from scripts.native_slo_command_fixture import prepare_empty_command_authority
from scripts.native_slo_contract import assert_privacy_safe


def _result(report, **changes):
    fields = dict(
        returncode=0, timed_out=False, containment_failed=False, output_limit_exceeded=False, stdout=json.dumps(report)
    )
    return SimpleNamespace(**(fields | changes))


def _report(expected, phase="clean_baseline"):
    return {
        "schema": "hol-guard.installed-artifact-transition-phase.v1",
        "phase": phase,
        "passed": True,
        "cleanup_confirmed": True,
        "registered_native_cases": 2,
        "prior_receipts_verified": next(index for index, item in enumerate(driver._PHASES) if item[0] == phase) * 2,
        "control_revision": 1,
        "stale_control_write_rejected": True,
        "native_program_downgrade_qualified": False,
        "prior_binding_interpretation_qualified": False,
        "registration_preserved": phase != "clean_baseline",
        "authority_health": "protected",
        "identity": {
            **expected,
            "runtime_sha256": expected.get("runtime_sha256", "c" * 64),
            "installed_origin_verified": True,
            "native_program_supported": True,
        },
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "build",
        "runtime",
        "origin",
        "cleanup",
        "receipt_count",
        "registration",
        "boolean_revision",
        "float_case_count",
        "timeout",
        "containment",
        "exit",
        "missing_stdout",
    ],
)
def test_worker_success_needs_complete_artifact_process_and_floor_evidence(mutation) -> None:
    expected = {"build_sha": "a" * 40, "wheel_sha256": "b" * 64, "installed_package_sha256": "d" * 64}
    report = _report(expected)
    changes = {}
    if mutation == "build":
        report["identity"]["build_sha"] = "0" * 40
    elif mutation == "runtime":
        del report["identity"]["runtime_sha256"]
    elif mutation == "origin":
        report["identity"]["installed_origin_verified"] = False
    elif mutation == "cleanup":
        report["cleanup_confirmed"] = False
    elif mutation == "receipt_count":
        report["prior_receipts_verified"] = 2
    elif mutation == "registration":
        report["registration_preserved"] = True
    elif mutation == "boolean_revision":
        report["control_revision"] = True
    elif mutation == "float_case_count":
        report["registered_native_cases"] = 2.0
    elif mutation == "timeout":
        changes["timed_out"] = True
    elif mutation == "containment":
        changes["containment_failed"] = True
    elif mutation == "exit":
        changes["returncode"] = 1
    elif mutation == "missing_stdout":
        changes["stdout"] = ""
    assert driver.worker_evidence(_result(report, **changes), expected, "clean_baseline")["passed"] is False


def test_successful_worker_metadata_survives_complete_outer_sanitizer() -> None:
    expected = {"build_sha": "a" * 40, "wheel_sha256": "b" * 64, "installed_package_sha256": "d" * 64}
    result = assert_privacy_safe(
        {"phases": [driver.worker_evidence(_result(_report(expected)), expected, "clean_baseline")]}
    )
    assert result["phases"][0]["passed"] is True
    assert result["phases"][0]["worker"]["identity"]["native_program_supported"] is True
    assert result["phases"][0]["worker"]["identity"]["build_sha"] == "a" * 40


@pytest.mark.parametrize("executable", ["uv", "python"])
def test_child_environment_cannot_select_the_paired_prefix_or_runtime_override(executable, monkeypatch, tmp_path):
    for key in ("VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT", "UV_PYTHON", "PYTHONHOME", "PYTHONPATH", "HOL_GUARD_NATIVE"):
        monkeypatch.setenv(key, "untrusted-inherited-value")
    observed = {}

    def run(*_args, **kwargs):
        observed.update(kwargs["environment"])
        return _result({})

    monkeypatch.setattr(driver, "run_isolated_hook_process", run)
    driver._run((executable, "--version"), tmp_path)
    assert all(
        key not in observed for key in ("VIRTUAL_ENV", "UV_PYTHON", "PYTHONHOME", "PYTHONPATH", "HOL_GUARD_NATIVE")
    )
    if executable == "uv":
        assert observed["UV_PROJECT_ENVIRONMENT"] == str(tmp_path / "installation")
    else:
        assert "UV_PROJECT_ENVIRONMENT" not in observed


def _wheel(path, text):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("codex_plugin_scanner/__init__.py", text)
        runtime = text.encode()
        archive.writestr("codex_plugin_scanner/_native/hol-guard-runtime", runtime)
        archive.writestr(
            "codex_plugin_scanner/_native/runtime-manifest.json",
            json.dumps(
                {
                    "schema": "hol-guard-native-runtime.v1",
                    "source_sha": ("b" if text == "candidate" else "a") * 40,
                    "runtime_size": len(runtime),
                    "runtime_sha256": hashlib.sha256(runtime).hexdigest(),
                }
            ),
        )
    return path


@pytest.mark.parametrize("fail_phase", [None, "candidate_upgrade"])
def test_replacement_uses_only_third_prefix_and_stops_after_failed_worker(fail_phase, monkeypatch, tmp_path) -> None:
    baseline = _wheel(tmp_path / "baseline.whl", "baseline")
    candidate = _wheel(tmp_path / "candidate.whl", "candidate")
    installs, workers, roots = [], [], []
    source_python = tmp_path / "candidate-env/bin/python"
    (tmp_path / "uv.lock").write_text("pinned-test-lock")
    monkeypatch.setattr(driver.shutil, "which", lambda _name: "/usr/bin/uv")
    monkeypatch.setattr(driver, "prepare_private_interpreter", lambda *_args, **_kwargs: {"private_copy": True})

    def required(argv, root):
        installs.append(argv)
        if root not in roots:
            roots.append(root)
        if argv[1] == "pip":
            target = argv[argv.index("--python") + 1]
            assert target != str(source_python) and str(root / "installation") in target
            assert "--no-index" in argv and "--no-deps" in argv

    def run(argv, root):
        assert argv[1] == "-I"
        phase = argv[-1]
        workers.append(phase)
        expected = json.loads(Path(argv[argv.index("--expected") + 1]).read_text())
        report = _report(expected, phase)
        if phase == fail_phase:
            report["cleanup_confirmed"] = False
        return _result(report)

    monkeypatch.setattr(driver, "_required_command", required)
    monkeypatch.setattr(driver, "_run", run)
    result = driver.verify(source_python, baseline, candidate, "a" * 40, "b" * 40, dependency_root=tmp_path)
    assert result["passed"] is (fail_phase is None)
    assert result["fixture_retained_for_unverified_retirement"] is (fail_phase is not None)
    assert roots[0].exists() is (fail_phase is not None)
    if fail_phase is not None:
        driver.shutil.rmtree(roots[0])
    assert workers == [item[0] for item in driver._PHASES][: 5 if fail_phase is None else 2]
    assert len(installs) == 2 + len(workers)
    assert installs[1][1:7] == ("sync", "--frozen", "--extra", "dev", "--no-install-project", "--project")
    assert all(
        result[field] is False
        for field in (
            "version_downgrade_qualified",
            "native_program_downgrade_qualified",
            "in_progress_replacement_qualified",
            "signing_changes_qualified",
            "program_qualification_complete",
        )
    )


def test_same_artifact_cannot_supply_an_upgrade_or_rollback(monkeypatch, tmp_path) -> None:
    wheel = _wheel(tmp_path / "same.whl", "unchanged")
    monkeypatch.setattr(
        driver, "_required_command", lambda *_args: pytest.fail("same artifact must fail before installation")
    )
    assert (
        driver.verify(tmp_path / "python", wheel, wheel, "a" * 40, "b" * 40, dependency_root=tmp_path)["passed"]
        is False
    )


def test_dependency_change_retains_completed_phases_but_cannot_qualify(monkeypatch, tmp_path) -> None:
    baseline = _wheel(tmp_path / "baseline.whl", "baseline")
    candidate = _wheel(tmp_path / "candidate.whl", "candidate")
    lock = tmp_path / "uv.lock"
    lock.write_text("original-lock")
    monkeypatch.setattr(driver.shutil, "which", lambda _name: "/usr/bin/uv")
    monkeypatch.setattr(driver, "prepare_private_interpreter", lambda *_args, **_kwargs: {"private_copy": True})
    monkeypatch.setattr(driver, "_required_command", lambda *_args: None)

    def run(argv, root):
        if argv[-1] == "candidate_restore":
            lock.write_text("changed-lock")
        expected = json.loads(Path(argv[argv.index("--expected") + 1]).read_text())
        return _result(_report(expected, argv[-1]))

    monkeypatch.setattr(driver, "_run", run)
    result = driver.verify(tmp_path / "python", baseline, candidate, "a" * 40, "b" * 40, dependency_root=tmp_path)
    assert result["passed"] is False
    assert result["completed_phase_count"] == 5
    assert "failure" in result


def test_private_journal_is_bounded_and_retains_exact_records(tmp_path) -> None:
    path = tmp_path / "journal.json"
    record = {"password": "private-fixture-password", "receipts": [{"decision_id": "a" * 64}]}
    write_private(path, record)
    assert probe.read_private(path) == record
    with pytest.raises(RuntimeError, match="private_state_limit"):
        write_private(path, {"value": "x" * (64 * 1024)})
    assert probe.read_private(path) == record


def test_preserved_authority_cannot_regress_or_drop_existing_control(tmp_path) -> None:
    store = GuardStore(tmp_path)
    prepare_empty_command_authority(store)
    password = "private-fixture-password"
    update_settings(
        tmp_path, {"enabled": True, "new_password": password, "confirm_password": password, "cooldown_seconds": 0}
    )
    probe.commit_layer(store, password, revision=0, enabled=False)
    previous = {"revision": 1, "ollama_state": "disabled"}
    assert probe.authority_view(store, previous).revision == 1
    with pytest.raises(RuntimeError, match="revision_regressed"):
        probe.authority_view(store, {**previous, "revision": 2})
    with pytest.raises(RuntimeError, match="control_not_preserved"):
        probe.authority_view(store, {**previous, "ollama_state": "enabled"})
    with pytest.raises(ExtensionControlAuthorityError, match="extension control authority revision conflict"):
        probe.commit_layer(store, password, revision=0, enabled=True)
    assert probe.authority_view(store, previous).revision == 1


def test_mismatched_installation_never_constructs_a_daemon(monkeypatch, tmp_path) -> None:
    def identity(_expected):
        raise RuntimeError("private-fixture-path")

    monkeypatch.setattr(probe, "installed_identity", identity)
    monkeypatch.setattr(probe, "GuardStore", lambda *_args: pytest.fail("unverified wheel cannot open authority"))
    result = probe.run_phase({}, tmp_path, "clean_baseline")
    assert result["passed"] is result["cleanup_confirmed"] is False
    assert "identity" not in result and "private-fixture-path" not in json.dumps(result)


@pytest.mark.parametrize("final_status", ["failed", "contained_client_cleanup_failed", "already-stopped"])
def test_final_cleanup_can_withdraw_earlier_native_retirement(final_status, monkeypatch) -> None:
    session = object.__new__(probe.RetainedSession)
    session.retirement_confirmed = True

    def close(self):
        self.last_stop_diagnostic = {"status": final_status}

    monkeypatch.setattr(probe.AdapterSession, "close", close)
    session.close()
    assert session.retirement_confirmed is (final_status == "already-stopped")


def test_changed_prior_registration_fails_without_repair_or_native_launch(monkeypatch, tmp_path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text('{"changed":true}')
    monkeypatch.setattr(probe, "claude_managed_settings_path", lambda _context: settings)
    monkeypatch.setattr(
        probe.ClaudeCodeHarnessAdapter,
        "install",
        lambda *_args: pytest.fail("later phases must not repair registration"),
    )
    session = SimpleNamespace(root=tmp_path, workspace=tmp_path / "workspace", guard_home=tmp_path / ".hol-guard")
    with pytest.raises(RuntimeError, match="registration_changed"):
        probe.observe_registered(session, {}, {"registration_sha256": "0" * 64}, None)


def test_worker_projection_discards_arbitrary_extra_text() -> None:
    expected = {"build_sha": "a" * 40, "wheel_sha256": "b" * 64, "installed_package_sha256": "d" * 64}
    report = _report(expected)
    report["notes"] = "PRIVATE_SENTINEL"
    report["identity"]["debug"] = "PRIVATE_SENTINEL"
    report["failure"] = {"reason": "PRIVATE_SENTINEL", "notes": "PRIVATE_SENTINEL", "diagnostic_digest": "e" * 64}
    evidence = driver.worker_evidence(_result(report), expected, "clean_baseline")
    assert evidence["passed"] is False
    assert "PRIVATE_SENTINEL" not in json.dumps(evidence)
    assert evidence["worker"]["failure"] == {"reason": "transition_worker_failed", "diagnostic_digest": "e" * 64}


def test_wheel_contract_binds_exact_runtime_bytes_and_manifest(tmp_path) -> None:
    wheel = _wheel(tmp_path / "baseline.whl", "baseline")
    contract = driver.artifact_contract(wheel, "a" * 40)
    assert contract["runtime_sha256"] == hashlib.sha256(b"baseline").hexdigest()
    assert contract["runtime_filename"] == "hol-guard-runtime"
    with pytest.raises(ValueError, match="wheel_runtime_identity"):
        driver.artifact_contract(wheel, "b" * 40)


@pytest.mark.parametrize("fault", ["bytes", "origin"])
def test_installed_runtime_must_match_exact_wheel_bytes_and_location(fault, monkeypatch, tmp_path) -> None:
    prefix = tmp_path / "installation"
    package = prefix / "lib" / "codex_plugin_scanner"
    binary = package / "_native" / "hol-guard-runtime"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"expected")
    other = tmp_path / "other-runtime"
    other.write_bytes(b"expected")
    distribution = SimpleNamespace(locate_file=lambda _name: package, version="3.0.1")
    expected = {
        "build_sha": "a" * 40,
        "installed_package_sha256": "b" * 64,
        "runtime_sha256": "c" * 64,
        "runtime_filename": "hol-guard-runtime",
    }
    monkeypatch.setattr(probe.importlib.metadata, "distribution", lambda _name: distribution)
    monkeypatch.setattr(probe.sys, "prefix", str(prefix))
    monkeypatch.setattr(probe, "assert_installed_import_origin", lambda _distribution: None)
    monkeypatch.setattr(probe, "installed_package_digest", lambda _distribution: "b" * 64)
    monkeypatch.setattr(
        probe,
        "native_runtime_status",
        lambda: SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(
                path=other if fault == "origin" else binary, sha256="d" * 64 if fault == "bytes" else "c" * 64
            ),
            capabilities=SimpleNamespace(build_sha="a" * 40, features=[]),
        ),
    )
    with pytest.raises(RuntimeError, match=f"runtime_{fault}_mismatch"):
        probe.installed_identity(expected)


def test_private_checkpoint_export_is_flat_private_and_never_in_public_report(tmp_path) -> None:
    root = tmp_path / "fixture"
    source = root / "transition-checkpoints" / "clean_baseline.json"
    checkpoint = {"password": "PRIVATE_SENTINEL", "phase": "clean_baseline", "receipts": []}
    write_private(source, checkpoint)
    destination = tmp_path / "private_samples"
    report = driver._retain_checkpoints(root, destination)
    retained = destination / "installed-transition-clean_baseline.json"
    assert report == {"files": 1, "complete": True}
    assert probe.read_private(retained) == checkpoint
    assert "PRIVATE_SENTINEL" not in json.dumps(report)
    repeated = driver._retain_checkpoints(root, destination)
    assert repeated["complete"] is False and repeated["files"] == 0
    assert probe.read_private(retained) == checkpoint


def test_retention_failure_keeps_exact_completed_prefix_count(tmp_path, monkeypatch) -> None:
    root = tmp_path / "fixture"
    for phase in ("clean_baseline", "candidate_upgrade"):
        write_private(root / "transition-checkpoints" / f"{phase}.json", {"phase": phase})
    original = driver.evidence_files.atomic_exclusive

    def fail_second(path, content):
        if "candidate_upgrade" in path.name:
            raise OSError("PRIVATE_SENTINEL")
        original(path, content)

    monkeypatch.setattr(driver.evidence_files, "atomic_exclusive", fail_second)
    report = driver._retain_checkpoints(root, tmp_path / "private_samples")
    assert report["files"] == 1 and report["complete"] is False
    assert "PRIVATE_SENTINEL" not in json.dumps(report)


@pytest.mark.parametrize("claim", ["native_program_downgrade_qualified", "prior_binding_interpretation_qualified"])
def test_worker_cannot_claim_unexercised_qualification(claim) -> None:
    expected = {"build_sha": "a" * 40, "wheel_sha256": "b" * 64, "installed_package_sha256": "d" * 64}
    report = _report(expected)
    report[claim] = True
    evidence = driver.worker_evidence(_result(report), expected, "clean_baseline")
    assert evidence["passed"] is False
    assert evidence["worker"].get(claim) is not True


def test_uncontained_installer_preserves_fixture_and_stops_all_offers(tmp_path, monkeypatch) -> None:
    baseline = _wheel(tmp_path / "baseline.whl", "baseline")
    candidate = _wheel(tmp_path / "candidate.whl", "candidate")
    (tmp_path / "uv.lock").write_text("fixture-lock")
    roots = []
    monkeypatch.setattr(driver.shutil, "which", lambda _name: "/usr/bin/uv")

    def run(_argv, root):
        roots.append(root)
        return _result({}, containment_failed=True)

    monkeypatch.setattr(driver, "_run", run)
    report = driver.verify(tmp_path / "python", baseline, candidate, "a" * 40, "b" * 40, dependency_root=tmp_path)
    assert report["passed"] is False and report["fixture_retained_for_unverified_retirement"] is True
    assert report["failure"]["installer_containment_failed"] is True
    assert report["phases"] == [] and len(roots) == 1 and roots[0].exists()
    driver.shutil.rmtree(roots[0])


def test_verified_retirement_does_not_delete_checkpoints_after_export_failure(tmp_path, monkeypatch) -> None:
    baseline = _wheel(tmp_path / "baseline.whl", "baseline")
    candidate = _wheel(tmp_path / "candidate.whl", "candidate")
    (tmp_path / "uv.lock").write_text("fixture-lock")
    roots = []
    monkeypatch.setattr(driver.shutil, "which", lambda _name: "/usr/bin/uv")
    monkeypatch.setattr(driver, "_required_command", lambda *_args: None)
    monkeypatch.setattr(driver, "prepare_private_interpreter", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(driver, "_retain_checkpoints", lambda *_args: {"complete": False, "files": 1})

    def run(argv, root):
        roots.append(root)
        expected = json.loads(Path(argv[argv.index("--expected") + 1]).read_text())
        return _result(_report(expected, argv[-1]))

    monkeypatch.setattr(driver, "_run", run)
    report = driver.verify(
        tmp_path / "python",
        baseline,
        candidate,
        "a" * 40,
        "b" * 40,
        dependency_root=tmp_path,
        private_evidence=tmp_path / "private_samples",
    )
    assert report["passed"] is False and report["completed_phase_count"] == 5
    assert report["fixture_retained_for_evidence_failure"] is True
    assert report["fixture_retained_for_unverified_retirement"] is False
    assert report["private_checkpoints_retained"] == 1 and roots[-1].exists()
    driver.shutil.rmtree(roots[-1])


@pytest.mark.parametrize("failure", ["PRIVATE_SENTINEL", True, None, []])
def test_any_failure_field_prevents_success_without_echoing_child_text(failure) -> None:
    expected = {"build_sha": "a" * 40, "wheel_sha256": "b" * 64, "installed_package_sha256": "d" * 64}
    report = _report(expected)
    report["failure"] = failure
    evidence = driver.worker_evidence(_result(report), expected, "clean_baseline")
    assert evidence["passed"] is False
    assert evidence["worker"]["failure"] == {"reason": "transition_worker_failed"}
    assert "PRIVATE_SENTINEL" not in json.dumps(evidence)


def test_disposable_prefix_cannot_be_created_inside_source_checkout(tmp_path, monkeypatch) -> None:
    baseline = _wheel(tmp_path / "baseline.whl", "baseline")
    candidate = _wheel(tmp_path / "candidate.whl", "candidate")
    (tmp_path / "uv.lock").write_text("fixture-lock")
    nested = tmp_path / "accidentally-nested"
    nested.mkdir()
    monkeypatch.setattr(driver.shutil, "which", lambda _name: "/usr/bin/uv")
    monkeypatch.setattr(driver.tempfile, "mkdtemp", lambda **_kwargs: str(nested))
    monkeypatch.setattr(driver, "_required_command", lambda *_args: pytest.fail("source prefix must never install"))
    report = driver.verify(tmp_path / "python", baseline, candidate, "a" * 40, "b" * 40, dependency_root=tmp_path)
    assert report["passed"] is False and report["phases"] == []
    assert report["failure"]["reason"] == "qualification_transition_fixture_not_external"
    assert not nested.exists()
