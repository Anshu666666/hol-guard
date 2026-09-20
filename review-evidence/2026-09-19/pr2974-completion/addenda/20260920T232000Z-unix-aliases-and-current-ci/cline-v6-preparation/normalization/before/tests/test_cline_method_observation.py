"""Selected-method forwarding, exact loader ownership and real isolated startup."""

from __future__ import annotations

import builtins
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from scripts import native_slo_workloads as oracle
from scripts.ci.cline_witness import installation, invocation, method_observation, profile_runtime, run, validation

SOURCE = '''class HookWorker:
    def review_http_payload(self, *, payload, deadline=None):
        return self._review_raw_hook_native(payload=payload, policy_snapshot=payload.get("snapshot"))
    def _review_raw_hook_native(self, *, payload, policy_snapshot=None):
        return operation(payload, policy_snapshot)
'''
PRIVATE = "private-marker-not-for-export"


def model(tmp_path: Path, operation: Any, source: str = SOURCE) -> tuple[Any, Any, Any]:
    path = tmp_path / "hook_worker.py"
    path.write_text(source)
    module = ModuleType(method_observation.MODULE)
    module.__file__ = str(path)
    module.__dict__["operation"] = operation
    exec(compile(source, str(path), "exec", dont_inherit=True), module.__dict__)
    config = {"frames": [], "method_source": str(path), "sources": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()}}
    capture = profile_runtime.Profile(config)
    observer = method_observation.MethodObservation(config, capture)
    capture.method_observation = observer
    observer.bind(module)
    return module, capture, observer


def finish_configuration(capture: Any, tmp_path: Path) -> None:
    validator = tmp_path / "validation.py"
    validator.write_text("def validate(*args): return {'complete': True}\n")
    capture.config.update(configuration_sha256="a" * 64, argv=[[], []], output=str(tmp_path),
                          validation_path=str(validator), validation_sha256=hashlib.sha256(validator.read_bytes()).hexdigest())


def test_original_instances_args_and_result_forward_once_without_profile(tmp_path: Path) -> None:
    calls = []
    result = {"result": {"minimum_action": "allow"}}
    payload = {"private": PRIVATE, "snapshot": {"nested": [1]}}

    def original(first: Any, second: Any) -> Any:
        calls.append((first, second))
        return result

    module, capture, observer = model(tmp_path, original)
    owner = module.HookWorker
    worker = owner()
    before = sys.getprofile()
    try:
        actual = worker.review_http_payload(payload=payload)
        assert actual is result and module.HookWorker is owner
        assert capture.worker is worker and capture.edge is result and capture.worker_result is result
        assert len(calls) == 1 and calls[0][0] is payload and calls[0][1] is payload["snapshot"]
        assert capture.arguments["payload"] is payload
        assert all(value == 1 for value in capture.counts.values()) and not capture.open_frames
        assert sys.getprofile() is before and capture.callbacks == 0
    finally:
        observer.restore()
    assert observer.methods_restored
    assert all(owner.__dict__[name] is value for name, value in observer.originals.items())


@pytest.mark.parametrize("error", [RuntimeError(PRIVATE), KeyboardInterrupt(PRIVATE), builtins.BaseExceptionGroup(PRIVATE, [KeyboardInterrupt(PRIVATE)])])
@pytest.mark.parametrize("capture_failure", [False, True])
def test_original_exception_identity_survives_observer_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: BaseException, capture_failure: bool) -> None:
    calls = []
    def original(*args: Any) -> Any:
        calls.append(args)
        raise error
    module, _capture, observer = model(tmp_path, original)
    if capture_failure:
        def fail(*_args: Any) -> Any:
            raise SystemExit(PRIVATE)
        monkeypatch.setattr(observer, "before", fail)
        monkeypatch.setattr(observer, "after", fail)
    try:
        with pytest.raises(BaseException) as caught:
            module.HookWorker().review_http_payload(payload={})
        assert caught.value is error and len(calls) == 1
    finally:
        observer.restore()
    assert PRIVATE not in json.dumps(observer.document())


@pytest.mark.parametrize("stage", ["before", "after"])
def test_original_return_identity_survives_capture_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str) -> None:
    result = {"private": PRIVATE}
    module, _capture, observer = model(tmp_path, lambda *_args: result)
    def fail(*_args: Any) -> Any:
        raise KeyboardInterrupt(PRIVATE)
    monkeypatch.setattr(observer, stage, fail)
    try:
        assert module.HookWorker().review_http_payload(payload={}) is result
    finally:
        observer.restore()
    assert observer.faults and PRIVATE not in json.dumps(observer.document())


@pytest.mark.parametrize("change", ["second_call", "second_worker", "entry_mutation", "edge_mutation", "worker_mutation"])
def test_duplicate_and_nested_mutation_never_gain_complete_gate(tmp_path: Path, change: str) -> None:
    edge = {"nested": [1]}
    module, capture, observer = model(tmp_path, lambda *_args: edge)
    finish_configuration(capture, tmp_path)
    worker = module.HookWorker()
    payload = {"nested": [1]}
    try:
        worker.review_http_payload(payload=payload)
        if change == "second_call":
            worker.review_http_payload(payload=payload)
        elif change == "second_worker":
            module.HookWorker().review_http_payload(payload=payload)
        elif change == "entry_mutation":
            payload["nested"].append(2)
        elif change == "edge_mutation":
            edge["nested"].append(2)
        else:
            capture.worker_result = {"nested": [2]}
        capture.finish()
    finally:
        observer.restore()
    report = json.loads((tmp_path / "child.json").read_bytes())
    assert report["observation_complete"] is False
    if change.startswith("second"):
        assert observer.faults and capture.counts["worker_call"] == 2
    else:
        assert report["original_values_stable"] is False


@pytest.mark.parametrize("mutation", ["code_constant", "source", "defaults", "module_owner"])
def test_same_named_runtime_rebinding_is_not_admitted(tmp_path: Path, mutation: str) -> None:
    module, capture, observer = model(tmp_path, lambda *_args: {})
    observer.restore()
    original = module.HookWorker._review_raw_hook_native
    if mutation == "code_constant":
        original.__code__ = original.__code__.replace(co_consts=(*original.__code__.co_consts, PRIVATE))
    elif mutation == "source":
        Path(module.__file__).write_text(SOURCE + "\n# changed\n")
    elif mutation == "defaults":
        original.__kwdefaults__ = {"policy_snapshot": PRIVATE}
    else:
        original.__module__ = "foreign"
    fresh = method_observation.MethodObservation(capture.config, capture)
    with pytest.raises(ValueError, match="cline_method_"):
        fresh.bind(module)
    assert not fresh.bound and fresh.installed == []


def test_unknown_code_constant_never_dispatches_hash_or_equality() -> None:
    touches = []
    class Hostile:
        def __hash__(self) -> int:
            touches.append("hash")
            raise AssertionError
        def __eq__(self, other: object) -> bool:
            touches.append("eq")
            raise AssertionError
    code = compile("pass", "fixed", "exec").replace(co_consts=(Hostile(),))
    with pytest.raises(ValueError, match="constant_type"):
        method_observation.code_image(code)
    assert touches == []


def test_changed_code_after_binding_is_observed_without_replacing_original_result(tmp_path: Path) -> None:
    result = {"native": 1}
    module, _capture, observer = model(tmp_path, lambda *_args: result)
    function = observer.originals["_review_raw_hook_native"]
    function.__code__ = function.__code__.replace(co_consts=(*function.__code__.co_consts, PRIVATE))
    try:
        assert module.HookWorker().review_http_payload(payload={}) is result
        assert "selected_code_changed" in observer.faults
    finally:
        observer.restore()


@pytest.mark.parametrize("mutation", ["none", "minimum_action", "extra_semantic", "context", "policy"])
def test_captured_original_object_reaches_full_unchanged_oracle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    from codex_plugin_scanner.guard import native_decision_receipt as receipts
    source = '''class HookWorker:
    def review_http_payload(self, *, payload, deadline=None):
        return self._review_raw_hook_native(payload=payload, **ARGUMENTS)
    def _review_raw_hook_native(self, *, payload, harness, event, guard_home, home_dir, cwd, source_ref_external_allowed, observe_mode, deadline, policy_snapshot=None):
        return operation(payload, policy_snapshot)
'''
    expected = oracle.ExpectedResponse("allow", "none", "fixture", {"minimum_action": "allow"})
    payload = {"private": PRIVATE}
    case = oracle.QualificationCase("cline/PreToolUse/benign/small", "cline", "PreToolUse", "PreToolUse", "small", payload, expected, "native_resident", "normal", "fixture", 0, 0, "inline", native_expected=expected)
    native: dict[str, Any] = {"minimum_action": "allow"}
    if mutation == "minimum_action":
        del native["minimum_action"]
    elif mutation == "extra_semantic":
        native["continue"] = None
    receipt = {"policy_generation": 1, "policy_digest": "p", "runtime_identity": "r", "rule_digest": "rules", "workspace_bound": False}
    edge = {"result": native, "receipt": receipt}
    module, capture, observer = model(tmp_path, lambda *_args: edge, source)
    module.__dict__["ARGUMENTS"] = {
        "harness": "cline", "event": "PreToolUse", "guard_home": "guard", "home_dir": "home",
        "cwd": "changed" if mutation == "context" else None,
        "source_ref_external_allowed": False, "observe_mode": False, "deadline": None,
        "policy_snapshot": {"mode": "enforce", "generation": 1, "policy_digest": "bad" if mutation == "policy" else "p", "runtime_identity": "r"},
    }
    worker = module.HookWorker()
    worker.metrics = SimpleNamespace(snapshot=lambda: {"routes": {"native_resident": 1}})
    worker.last_native_decision_receipt = receipt
    worker.test_oracle = None
    original_validator = oracle.validate_native_result
    seen = []
    def same_original(case_value: Any, native_value: Any) -> None:
        seen.append(native_value is native)
        original_validator(case_value, native_value)
    monkeypatch.setattr(oracle, "validate_native_result", same_original)
    # Receipt crypto/producer authenticity is intentionally modeled in this
    # source-only forwarding control; the original semantic oracle is real.
    monkeypatch.setattr(receipts, "validate_native_decision_receipt", lambda value: receipt if value is receipt else None)
    monkeypatch.setattr(receipts, "receipt_matches_edge", lambda first, second: first is edge and second is receipt)
    try:
        assert worker.review_http_payload(payload=payload) is edge
        config = {"source_root": str(run.ROOT), "case": asdict(case), "home": "home", "guard_home": "guard", "runtime_identity": "r", "rule_digest": "rules"}
        report = validation.validate(config, capture.arguments, capture.edge, capture.worker, capture.worker_result)
        assert seen == [True] and report["complete"] is (mutation == "none")
        assert capture.entry_image == profile_runtime.entry_snapshot(capture.arguments)
        assert capture.edge_image == profile_runtime.snapshot(edge)
        assert PRIVATE not in json.dumps(report)
    finally:
        observer.restore()


def test_lost_method_owner_is_not_overwritten_and_cannot_clear_on_second_restore(tmp_path: Path) -> None:
    module, _, observer = model(tmp_path, lambda *_args: {})
    def replacement(*args: Any, **kwargs: Any) -> None:
        return None
    module.HookWorker.review_http_payload = replacement
    observer.restore()
    observer.restore()
    assert module.HookWorker.review_http_payload is replacement
    assert not observer.methods_restored and "method_ownership_lost" in observer.faults


def test_partial_method_install_restores_only_assigned_original(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, capture, observer = model(tmp_path, lambda *_args: {})
    observer.restore()
    fresh = method_observation.MethodObservation(capture.config, capture)
    original = fresh.make_hook
    def partial(name: str, function: Any) -> Any:
        if name == "_review_raw_hook_native":
            raise RuntimeError(PRIVATE)
        return original(name, function)
    monkeypatch.setattr(fresh, "make_hook", partial)
    with pytest.raises(RuntimeError):
        fresh.bind(module)
    fresh.restore_methods()
    assert module.HookWorker.review_http_payload is observer.originals["review_http_payload"]
    assert module.HookWorker._review_raw_hook_native is observer.originals["_review_raw_hook_native"]
    assert not fresh.bound


def test_loader_exec_exception_is_same_object_and_finder_restores(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    error = RuntimeError(PRIVATE)
    path = tmp_path / "hook_worker.py"
    path.write_text("raise ORIGINAL\n")
    config = {"frames": [], "method_source": str(path), "sources": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()}}
    capture = profile_runtime.Profile(config)
    observer = method_observation.MethodObservation(config, capture)
    monkeypatch.delitem(sys.modules, method_observation.MODULE, raising=False)
    assert observer.start()
    original = importlib.machinery.SourceFileLoader(method_observation.MODULE, str(path))
    spec = importlib.util.spec_from_file_location(method_observation.MODULE, path, loader=original)
    assert spec is not None
    module = ModuleType(method_observation.MODULE)
    module.__dict__["ORIGINAL"] = error
    module.__spec__ = spec
    loader = method_observation._Loader(observer, original, spec)
    try:
        with pytest.raises(RuntimeError) as caught:
            loader.exec_module(module)
        assert caught.value is error and module.__loader__ is original and spec.loader is original
        assert observer.finder_restored and not any(x is observer for x in sys.meta_path)
    finally:
        observer.restore()


def test_nonselected_imports_are_inert_and_finder_loss_is_sticky(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, capture, observer = model(tmp_path, lambda *_args: {})
    observer.restore()
    monkeypatch.delitem(sys.modules, method_observation.MODULE, raising=False)
    fresh = method_observation.MethodObservation(capture.config, capture)
    before = tuple(sys.meta_path)
    assert fresh.start()
    assert fresh.find_spec("unrelated.module") is None and fresh.selected_imports == 0
    sys.meta_path.remove(fresh)
    fresh.restore()
    assert "finder_ownership_lost" in fresh.faults and tuple(sys.meta_path) == before


@pytest.mark.parametrize("behavior", ["normal", "system_exit", "exception", "duplicate", "source_tamper", "helper_tamper"])
def test_actual_isolated_startup_uses_selected_methods_and_forwards_exit(tmp_path: Path, behavior: str) -> None:
    python = tmp_path / "venv/bin/python"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(python.parent.parent)], check=True, timeout=30)
    site_result = subprocess.run([str(python), "-I", "-c", "import sysconfig;print(sysconfig.get_path('purelib'))"], check=True, capture_output=True, text=True, timeout=10)
    site = Path(site_result.stdout.strip())
    package = site / "codex_plugin_scanner"
    for rel in ("", "guard", "guard/daemon"):
        directory = package / rel
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "__init__.py").write_text("")
    source = package / "guard/daemon/hook_worker.py"
    source.write_text(SOURCE + "\ndef operation(payload, snapshot): return {'native': [1]}\n")
    ending = {"system_exit": "raise SystemExit(17)\n", "exception": "raise RuntimeError('original-private')\n"}.get(behavior, "")
    duplicate = "worker.review_http_payload(payload={})\n" if behavior == "duplicate" else ""
    (package / "cli.py").write_text("import sys\nfrom codex_plugin_scanner.guard.daemon.hook_worker import HookWorker\nassert sys.getprofile() is None\nworker=HookWorker()\nworker.review_http_payload(payload={})\n" + duplicate + "print('original cli output')\n" + ending)
    worker_path = tmp_path / "worker.py"
    cli = [str(python), "-I", "-s", "-m", "codex_plugin_scanner.cli", "guard", "hook", "--harness", "cline", "--json"]
    worker_path.write_text("import subprocess\nraise SystemExit(subprocess.run(" + repr(cli) + ",check=False).returncode)\n")
    command = [str(python), "-I", "-s", str(worker_path)]
    validator = tmp_path / "validation.py"
    validator.write_text("def validate(*args): return {'complete': True}\n")
    output = tmp_path / "evidence"
    output.mkdir(mode=0o700)
    observed, _ = invocation.preflight(str(python), str(python.parent.parent))
    config = {"executable": str(python), "parent_pid": os.getpid(), "argv": [command, cli],
              "observed_argv": [[observed, *row[1:]] for row in (command, cli)], "frames": [],
              "sources": {str(source): hashlib.sha256(source.read_bytes()).hexdigest()},
              "method_source": str(source), "validation_path": str(validator),
              "validation_sha256": hashlib.sha256(validator.read_bytes()).hexdigest()}
    with installation.Installation(site, output, config) as installed:
        unrelated = subprocess.run([str(python), "-I", "-s", "-c", "import sys;assert sys.getprofile() is None;print('inert')"], capture_output=True, text=True, timeout=10)
        assert unrelated.stdout == "inert\n" and not list(output.iterdir())
        changed = source if behavior == "source_tamper" else site / (installation.METHOD_NAME + ".py")
        prior = changed.read_bytes()
        if behavior.endswith("tamper"):
            changed.write_bytes(prior + b"\n# changed\n")
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        finally:
            changed.write_bytes(prior)
        assert result.returncode == {"system_exit": 17, "exception": 1}.get(behavior, 0)
        assert result.stdout == "original cli output\n"
        if behavior == "source_tamper":
            assert not (output / "child.json").exists()
        else:
            report = json.loads((output / "child.json").read_bytes())
            assert report["observation_complete"] is (behavior in {"normal", "system_exit", "exception"})
            if behavior != "helper_tamper":
                assert report["schema"] == "hol-guard.cline-child-edge.v3"
                assert report["callbacks"] == 0 and report["maximum_counted_callbacks"] == 0
                assert report["method_observation"]["global_profile_installed"] is False
                assert report["method_observation"]["methods_restored"] is True
    assert not installed.created and not installed.cleanup_faults


@pytest.mark.parametrize("mutation", ["unknown_constant", "late_defaults"])
def test_cleanup_restores_both_owned_methods_despite_invalid_live_binding(tmp_path: Path, mutation: str) -> None:
    module, _capture, observer = model(tmp_path, lambda *_args: {})
    original = observer.originals["_review_raw_hook_native"]
    if mutation == "unknown_constant":
        original.__code__ = original.__code__.replace(co_consts=(*original.__code__.co_consts, object()))
    else:
        original.__kwdefaults__ = {"policy_snapshot": PRIVATE}
    observer.restore()
    assert all(module.HookWorker.__dict__[name] is original for name, original in observer.originals.items())
    assert observer.methods_restored and observer.faults and observer.document()["complete"] is False


@pytest.mark.parametrize("mutation", ["none", "missing", "extra", "bool_imports", "profile", "restore", "fault", "callbacks", "saturation", "duplicate", "oracle", "context"])
def test_selected_method_consumer_keeps_closed_population_and_full_original_gates(mutation: str) -> None:
    from tests.test_cline_child_witness import joined_reports
    worker, child, config, manifest = joined_reports()
    config["method_source"] = "fixed-source"
    child.update(schema="hol-guard.cline-child-edge.v3", callbacks=0, callbacks_saturated=False,
                 callback_count_scope="selected_methods_only", maximum_counted_callbacks=0)
    methods: dict[str, Any] = {
        "schema": "hol-guard.cline-selected-method-observation.v1", "selected_imports": 1,
        "bound": True, "finder_restored": True, "methods_restored": True,
        "faults": [], "global_profile_installed": False, "complete": True,
    }
    child["method_observation"] = methods
    if mutation == "missing":
        del methods["selected_imports"]
    elif mutation == "extra":
        methods["unproved"] = True
    elif mutation == "bool_imports":
        methods["selected_imports"] = True
    elif mutation == "profile":
        methods["global_profile_installed"] = True
    elif mutation == "restore":
        methods["methods_restored"] = False
    elif mutation == "fault":
        methods["faults"] = ["method_binding_failed"]
    elif mutation == "callbacks":
        child["callbacks"] = False
    elif mutation == "saturation":
        child["callbacks_saturated"] = True
    elif mutation == "duplicate":
        child["counts"]["edge_call"] = 2
    elif mutation == "oracle":
        child["original_edge"]["original_native_validation_passed"] = False
    elif mutation == "context":
        del child["original_edge"]["request_context_fields"]["cwd"]
    if mutation == "none":
        run.reconcile(worker, child, config, manifest)
    else:
        with pytest.raises(ValueError, match="cline_witness_"):
            run.reconcile(worker, child, config, manifest)


def test_exact_current_product_methods_bind_without_running_a_product_request() -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker
    path = Path(str(hook_worker.__file__))
    config: dict[str, Any] = {"frames": [], "method_source": str(path), "sources": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()}}
    capture = profile_runtime.Profile(config)
    observer = method_observation.MethodObservation(config, capture)
    owner = hook_worker.HookWorker
    originals = {name: owner.__dict__[name] for name in method_observation.METHODS}
    try:
        observer.bind(hook_worker)
        assert observer.bound and hook_worker.HookWorker is owner
        assert all(owner.__dict__[name] is observer.hooks[name] for name in originals)
    finally:
        observer.restore()
    assert all(owner.__dict__[name] is original for name, original in originals.items())
