"""Strict original semantics, source-scoped profiling and real isolated startup."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from scripts import native_slo_workloads as oracle
from scripts.ci.cline_witness import installation, invocation, profile_runtime, run, validation
from scripts.native_slo_workloads import ExpectedResponse


@pytest.mark.parametrize("field", oracle._SEMANTIC_FIELDS)
def test_original_oracle_rejects_every_unexpected_semantic_field_without_exporting_value(field: str) -> None:
    secret = "private marker must not be exported"
    native: dict[str, Any] = {}
    current = native
    names = field.split(".")
    for name in names[:-1]:
        current[name] = {}
        current = current[name]
    current[names[-1]] = secret
    case = SimpleNamespace(case_id="cline/fake", native_expected=ExpectedResponse("allow", "none", "fake", {}))
    passed, facts = validation.semantic_facts(oracle, case, native)
    assert not passed and facts[field]["present"]
    assert secret not in json.dumps(facts)


@pytest.mark.parametrize("mutation", ("missing_minimum", "wrong_type", "wrong_value", "unexpected_null", "nonempty"))
def test_complete_original_predicates_are_called(mutation: str) -> None:
    expected = ExpectedResponse("allow", "none", "fake", {"minimum_action": "allow"}, ("human_reason",))
    case = SimpleNamespace(case_id="cline/fake", native_expected=expected)
    native: dict[str, Any] = {"minimum_action": "allow", "human_reason": "present"}
    if mutation == "missing_minimum":
        del native["minimum_action"]
    elif mutation == "wrong_type":
        native["minimum_action"] = True
    elif mutation == "wrong_value":
        native["minimum_action"] = "block"
    elif mutation == "unexpected_null":
        native["reviewed_excerpt"] = None
    else:
        native["human_reason"] = " "
    assert validation.semantic_facts(oracle, case, native)[0] is False


def test_original_native_object_is_not_reconstructed(monkeypatch: pytest.MonkeyPatch) -> None:
    native = {"minimum_action": "allow"}
    case = SimpleNamespace(case_id="cline/fake", native_expected=ExpectedResponse("allow", "none", "fake", native))
    seen = []
    original = oracle.validate_native_result

    def check(first: Any, second: Any) -> None:
        seen.append((first is case, second is native))
        original(first, second)

    monkeypatch.setattr(oracle, "validate_native_result", check)
    assert validation.semantic_facts(oracle, case, native)[0]
    assert seen == [(True, True)]


class Worker:
    def __init__(self) -> None:
        self.calls = 0

    def edge(self, payload: object, error: BaseException | None = None) -> object:
        self.calls += 1
        if error is not None:
            raise error
        return payload

    def review(self, value: object, error: BaseException | None = None) -> object:
        return self.edge(value, error)


def profiler() -> profile_runtime.Profile:
    frames = []
    for role, operation in (("edge", Worker.edge), ("worker", Worker.review)):
        code = operation.__code__
        frames.append(
            {"file": code.co_filename, "qualname": code.co_qualname, "line": code.co_firstlineno, "role": role}
        )
    return profile_runtime.Profile({"frames": frames})


@pytest.mark.parametrize("raised", (False, True))
@pytest.mark.parametrize("capture_fault", (False, True))
def test_profile_preserves_actual_return_exception_and_one_call(raised: bool, capture_fault: bool) -> None:
    profile = profiler()
    if capture_fault:
        profile.counts = {}  # Selected-event failure must not escape.
    worker, value, error = Worker(), {"value": "same object"}, RuntimeError("original-private-error")
    previous = sys.getprofile()
    assert profile.start()
    try:
        if raised:
            with pytest.raises(RuntimeError) as caught:
                worker.review(value, error)
            assert caught.value is error
        else:
            assert worker.review(value) is value
    finally:
        profile.restore()
    assert worker.calls == 1 and sys.getprofile() is previous and profile.restored
    if capture_fault:
        assert profile.faults == ["capture_failed"]
    else:
        assert all(value == 1 for value in profile.counts.values())
        assert not profile.open_frames
        assert profile.edge is (None if raised else value)


def test_duplicate_call_overflow_and_preexisting_profile_are_not_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = profiler()
    assert profile.start()
    try:
        worker = Worker()
        worker.review(None)
        worker.review(None)
    finally:
        profile.restore()
    assert profile.faults == ["duplicate_selected_call"]
    profile = profiler()
    monkeypatch.setattr(profile_runtime, "MAX_CALLBACKS", 0)
    assert profile.start()
    profile.restore()
    assert profile.faults == ["callback_limit"]

    def existing(*_: object) -> None:
        return

    sys.setprofile(existing)
    try:
        refused = profiler()
        assert not refused.start() and sys.getprofile() is existing
    finally:
        sys.setprofile(None)


def test_restore_failure_stays_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = profiler()
    monkeypatch.setattr(sys, "getprofile", lambda: object())
    profile.restore()
    monkeypatch.setattr(sys, "getprofile", lambda: None)
    profile.restore()
    assert profile.restoration_failed and not profile.restored


@pytest.fixture
def isolated(tmp_path: Path) -> tuple[Path, Path]:
    python = tmp_path / "venv/bin/python"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(python.parent.parent)], check=True, timeout=30)
    result = subprocess.run(
        [str(python), "-I", "-c", "import sysconfig;print(sysconfig.get_path('purelib'))"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return python, Path(result.stdout.strip())


@pytest.mark.skipif(os.name != "posix", reason="The declared three hosted lanes use POSIX venvs")
@pytest.mark.parametrize(
    "behavior", ("normal", "system_exit", "exception", "profile_tamper", "config_tamper", "source_tamper")
)
def test_real_isolated_worker_and_cli_forms_activate_and_non_cline_is_inert(
    isolated: tuple[Path, Path], tmp_path: Path, behavior: str
) -> None:
    python, site = isolated
    output = tmp_path / "evidence"
    output.mkdir(mode=0o700)
    worker = tmp_path / "worker.py"
    package = site / "codex_plugin_scanner"
    package.mkdir()
    (package / "__init__.py").write_text("")
    ending = {
        "system_exit": "raise SystemExit(17)\n",
        "exception": "raise RuntimeError('original private exception')\n",
    }.get(behavior, "")
    (package / "cli.py").write_text("print('original cli output')\n" + ending)
    cli = [str(python), "-I", "-s", "-m", "codex_plugin_scanner.cli", "guard", "hook", "--harness", "cline", "--json"]
    worker.write_text("import subprocess\nraise SystemExit(subprocess.run(" + repr(cli) + ",check=False).returncode)\n")
    command = [str(python), "-I", "-s", str(worker)]
    validate = tmp_path / "validate.py"
    validate.write_text("def validate(*args): return {'complete':False}\n")
    observed_argv0, metadata = invocation.preflight(str(python), str(python.parent.parent))
    assert metadata["all_arguments_after_argv0_exact"]
    config = {
        "executable": str(python),
        "parent_pid": os.getpid(),
        "argv": [command, cli],
        "observed_argv": [[observed_argv0, *row[1:]] for row in (command, cli)],
        "frames": [],
        "sources": {str(validate): hashlib.sha256(validate.read_bytes()).hexdigest()},
        "validation_path": str(validate),
        "validation_sha256": hashlib.sha256(validate.read_bytes()).hexdigest(),
    }
    with installation.Installation(site, output, config) as installed:
        original = subprocess.run(
            [str(python), "-I", "-s", "-c", "print('unrelated')"], capture_output=True, text=True, timeout=10
        )
        assert original.stdout == "unrelated\n" and not list(output.iterdir())
        other = [part if part != "cline" else "other-harness" for part in cli]
        unrelated = subprocess.run(other, capture_output=True, text=True, timeout=10)
        assert unrelated.stdout == "original cli output\n" and not list(output.iterdir())
        changed: Path | None = None
        before = b""
        if behavior.endswith("_tamper"):
            changed = {
                "profile_tamper": site / (installation.PROFILE_NAME + ".py"),
                "config_tamper": site / installation.CONFIG_NAME,
                "source_tamper": validate,
            }[behavior]
            before = changed.read_bytes()
            changed.write_bytes(before + b" ")
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        finally:
            if changed is not None:
                changed.write_bytes(before)
        assert result.returncode == {"system_exit": 17, "exception": 1}.get(behavior, 0)
        assert result.stdout == "original cli output\n"
        if behavior == "exception":
            assert "RuntimeError: original private exception" in result.stderr
        else:
            assert result.stderr == ""
        if behavior.endswith("_tamper"):
            assert not (output / "child.json").exists()
            assert (output / "worker.json").exists() is (behavior == "source_tamper")
        else:
            worker_row = json.loads((output / "worker.json").read_text())
            child = json.loads((output / "child.json").read_text())
            assert child["parent_pid"] == worker_row["pid"] and child["isolated"] and child["no_user_site"]
            assert child["profile_restored"] and not child["observation_complete"]
    assert not installed.created and not installed.cleanup_faults
    assert not (site / "sitecustomize.py").exists()


def test_private_reader_rejects_symlink_and_duplicate_json(tmp_path: Path) -> None:
    path = tmp_path / "private"
    path.write_text("secret")
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        profile_runtime.private_read(link, 100)
    with pytest.raises(ValueError, match="duplicate"):
        json.loads('{"a":1,"a":2}', object_pairs_hook=profile_runtime.pairs)


def test_install_preserves_existing_customization(tmp_path: Path) -> None:
    site, output = tmp_path / "site", tmp_path / "out"
    site.mkdir()
    output.mkdir(mode=0o700)
    path = site / "sitecustomize.py"
    path.write_text("original")
    with pytest.raises(ValueError, match="preexisting"):
        installation.Installation(site, output, {}).__enter__()
    assert path.read_text() == "original"


@pytest.mark.parametrize(
    "missing",
    (
        "original_validator_called",
        "original_native_validation_passed",
        "payload_equal",
        "request_context_equal",
        "policy_binding_valid",
        "receipt_matches_original_edge",
        "receipt_accepted_by_original_worker",
        "python_oracle_disabled",
    ),
)
def test_report_complete_flag_cannot_replace_original_edge_facts(missing: str) -> None:
    worker, child, config, manifest = joined_reports()
    del child["original_edge"][missing]
    with pytest.raises(ValueError, match="original_edge_" + missing):
        run.reconcile(worker, child, config, manifest)


def joined_reports() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    config: dict[str, Any] = {
        "parent_pid": 1,
        "argv": [["python", "-I", "-s", "worker"], ["python", "-I", "-s", "-m", "cli"]],
    }
    config["observed_argv"] = config["argv"]
    base = {"configuration_sha256": "a" * 64, "isolated": True, "no_user_site": True}
    worker = {
        **base,
        "schema": "hol-guard.cline-worker-start.v1",
        "pid": 2,
        "parent_pid": 1,
        "registered_argv_sha256": hashlib.sha256(profile_runtime.encoded(config["argv"][0])).hexdigest(),
        "observed_argv_sha256": hashlib.sha256(profile_runtime.encoded(config["argv"][0])).hexdigest(),
    }
    child: dict[str, Any] = {
        **base,
        "schema": "hol-guard.cline-child-edge.v1",
        "pid": 3,
        "parent_pid": 2,
        "registered_argv_sha256": hashlib.sha256(profile_runtime.encoded(config["argv"][1])).hexdigest(),
        "observed_argv_sha256": hashlib.sha256(profile_runtime.encoded(config["argv"][1])).hexdigest(),
        "observation_complete": True,
        "original_values_stable": True,
        "faults": [],
        "profile_restored": True,
        "open_frames": 0,
        "counts": {"edge_call": 1, "edge_return_or_unwind": 1, "worker_call": 1, "worker_return_or_unwind": 1},
        "original_edge": {
            name: True
            for name in (
                "complete",
                "original_validator_called",
                "original_native_validation_passed",
                "payload_equal",
                "edge_shape_valid",
                "receipt_matches_original_edge",
                "receipt_accepted_by_original_worker",
                "python_oracle_disabled",
                "request_context_equal",
                "policy_binding_valid",
            )
        },
    }
    child["original_edge"].update(
        original_worker_route="native_resident", original_worker_routes={"native_resident": 1}
    )
    return worker, child, config, {"configuration_sha256": "a" * 64}


@pytest.mark.parametrize(
    "mutation", ("none", "pid", "config", "argv", "isolation", "loss", "restore", "calls", "open", "route")
)
def test_exact_child_parent_call_route_and_loss_join(mutation: str) -> None:
    worker, child, config, manifest = joined_reports()
    if mutation == "pid":
        child["parent_pid"] = 9
    elif mutation == "config":
        child["configuration_sha256"] = "b" * 64
    elif mutation == "argv":
        child["observed_argv_sha256"] = "b" * 64
    elif mutation == "isolation":
        child["isolated"] = False
    elif mutation == "loss":
        child["faults"] = ["callback_limit"]
    elif mutation == "restore":
        child["profile_restored"] = False
    elif mutation == "calls":
        child["counts"]["edge_call"] = True
    elif mutation == "open":
        child["open_frames"] = 1
    elif mutation == "route":
        child["original_edge"]["original_worker_routes"]["native_fail_safe"] = 1
    if mutation == "none":
        run.reconcile(worker, child, config, manifest)
    else:
        with pytest.raises(ValueError, match="cline_witness_"):
            run.reconcile(worker, child, config, manifest)


def test_registered_and_observed_argv_domains_remain_separate() -> None:
    worker, child, config, manifest = joined_reports()
    config["observed_argv"] = [["/framework/Python", *row[1:]] for row in config["argv"]]
    for index, row in enumerate((worker, child)):
        row["observed_argv_sha256"] = hashlib.sha256(
            profile_runtime.encoded(config["observed_argv"][index])
        ).hexdigest()
        assert row["observed_argv_sha256"] != row["registered_argv_sha256"]
    run.reconcile(worker, child, config, manifest)
    child["registered_argv_sha256"] = child["observed_argv_sha256"]
    with pytest.raises(ValueError, match="registered_argv_join"):
        run.reconcile(worker, child, config, manifest)


def test_finish_export_failure_does_not_replace_original_exception_or_leak_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = profiler()
    profile.config.update(
        configuration_sha256="a" * 64, argv=[[], []], output=str(tmp_path), validation_path=str(tmp_path / "absent")
    )
    original = RuntimeError("private original error")
    profile.arguments = {"private": original}

    def fail_export(*_: object) -> None:
        raise SystemExit("private recording error")

    monkeypatch.setattr(profile_runtime, "write_report", fail_export)
    with pytest.raises(RuntimeError) as caught:
        try:
            raise original
        finally:
            profile.finish()
    assert caught.value is original
    assert profile.closed and profile.restored and profile.arguments is None and profile.edge is None


def test_complete_observer_uses_actual_compact_snapshot_and_separate_bound_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import asdict

    from codex_plugin_scanner.guard import native_decision_receipt as receipts

    private = "private payload and result marker"
    expected = ExpectedResponse("allow", "none", "fixture", {"minimum_action": "allow"})
    case = oracle.QualificationCase(
        "cline/PreToolUse/benign/small",
        "cline",
        "PreToolUse",
        "PreToolUse",
        "small",
        {"private": private},
        expected,
        "native_resident",
        "normal",
        "fixture",
        0,
        0,
        "inline",
        native_expected=expected,
    )
    receipt = {"policy_generation": 1, "policy_digest": "p", "runtime_identity": "r", "rule_digest": "rules"}
    snapshot = {"mode": "enforce", "generation": 1, "policy_digest": "p", "runtime_identity": "r"}
    native = {"minimum_action": "allow"}
    edge = {"result": native, "receipt": receipt}
    worker = SimpleNamespace(
        last_native_decision_receipt=receipt,
        test_oracle=None,
        metrics=SimpleNamespace(snapshot=lambda: {"routes": {"native_resident": 1}}),
    )
    config = {
        "source_root": str(run.ROOT),
        "case": asdict(case),
        "home": "home",
        "workspace": "workspace",
        "guard_home": "guard",
        "runtime_identity": "r",
        "rule_digest": "rules",
    }
    args = {
        "policy_snapshot": snapshot,
        "payload": case.payload,
        "harness": "cline",
        "event": "PreToolUse",
        "cwd": "workspace",
        "home_dir": "home",
        "guard_home": "guard",
        "source_ref_external_allowed": False,
        "observe_mode": False,
    }
    monkeypatch.setattr(
        receipts, "validate_native_decision_receipt", lambda value: receipt if value is receipt else None
    )
    monkeypatch.setattr(receipts, "receipt_matches_edge", lambda first, second: first is edge and second is receipt)
    result = validation.validate(config, args, edge, worker, {"private": private})
    assert result["complete"] and result["original_native_validation_passed"]
    assert "rule_digest" not in snapshot and private not in json.dumps(result)
    missing = validation.validate(config, args, None, worker, {"private": private})
    assert not missing["complete"] and not missing["original_validator_called"]
    assert missing["original_worker_routes"] == {"native_resident": 1}
    assert missing["original_worker_route"] == "native_resident" and not missing["edge_shape_valid"]
    config["rule_digest"] = "wrong"
    refused = validation.validate(config, args, edge, worker, {"private": private})
    assert not refused["complete"] and not refused["policy_binding_valid"]


@pytest.mark.parametrize("mutation", (None, "entry", "edge_return"))
def test_nested_original_values_must_stay_equal_to_selected_boundary_snapshots(
    tmp_path: Path, mutation: str | None
) -> None:
    class SeparateResultWorker:
        def edge(self, payload: dict[str, Any]) -> dict[str, Any]:
            return {"result": {"nested": ["original result"]}}

        def review(self, payload: dict[str, Any]) -> dict[str, Any]:
            return self.edge(payload)

    frames = []
    for role, function in (("edge", SeparateResultWorker.edge), ("worker", SeparateResultWorker.review)):
        code = function.__code__
        frames.append(
            {"file": code.co_filename, "qualname": code.co_qualname, "line": code.co_firstlineno, "role": role}
        )
    helper = tmp_path / "validate.py"
    helper.write_text("def validate(*args): return {'complete':True}\n")
    profile = profile_runtime.Profile(
        {
            "frames": frames,
            "configuration_sha256": "a" * 64,
            "argv": [[], []],
            "output": str(tmp_path),
            "validation_path": str(helper),
            "validation_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        }
    )
    payload: dict[str, Any] = {"nested": ["original entry"]}
    assert profile.start()
    try:
        returned = SeparateResultWorker().review(payload)
        if mutation == "entry":
            payload["nested"][0] = "changed private entry"
        elif mutation == "edge_return":
            returned["result"]["nested"][0] = "changed private result"
    finally:
        profile.finish()
    report = json.loads((tmp_path / "child.json").read_text())
    assert report["original_values_stable"] is (mutation is None)
    assert report["observation_complete"] is (mutation is None)
    assert ("original_edge" in report) is (mutation is None)
    assert "changed private" not in json.dumps(report)
    assert profile.arguments is None and profile.entry_image is None and profile.edge_image is None


@pytest.mark.parametrize("stage", ("registration", "process", "delivery", "readback_after"))
def test_original_failure_survives_and_unknown_containment_defers_owned_cleanup(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    original = RuntimeError("original operation")
    calls: list[str] = []
    owner = SimpleNamespace(
        __enter__=lambda: calls.append("enter"), close=lambda: calls.append("close"), cleanup_faults=[]
    )
    attempt = run.SurfaceAttempt()

    def operation(*args: Any, **kwargs: Any) -> Any:
        assert kwargs["attempt"] is attempt
        attempt.stage = stage
        calls.append("original")
        raise original

    monkeypatch.setattr(run, "observe_registered_surface", operation)
    with pytest.raises(RuntimeError) as caught:
        run.observed_delivery(None, None, None, attempt, cast(Any, owner))
    assert caught.value is original
    assert calls == (["enter", "original"] if stage == "process" else ["enter", "original", "close"])
    assert owner.cleanup_faults == (["original_containment_unproved_cleanup_deferred"] if stage == "process" else [])
