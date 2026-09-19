from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_runtime

ROOT = Path(__file__).resolve().parents[1]
_REAL_NATIVE_STATUS = native_runtime.native_runtime_status


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


benchmark = _load_script("bench_guard_native_release_gate")
diagnostic = _load_script("bench_guard_native_phase_diagnostic")


@pytest.fixture
def actual_adapter(tmp_path, monkeypatch):
    calls = {"status": [], "request": [], "inputs": []}
    response = SimpleNamespace(decision="allow")
    snapshot = {"generation": 7, "policy_digest": "private-policy-canary", "runtime_identity": "private-runtime-canary"}
    identity = SimpleNamespace(path=tmp_path / "private-path-canary", sha256="a" * 64)
    status = SimpleNamespace(
        available=True, compatible=True, identity=identity,
        capabilities=SimpleNamespace(features=frozenset({"resident-protocol-v2"})),
    )
    original_request = benchmark._request

    def request(**kwargs):
        result = original_request(**kwargs)
        calls["inputs"].append(result)
        return result

    def status_call():
        calls["status"].append(True)
        return status

    def client_call(**kwargs):
        calls["request"].append(kwargs)
        return b'{"decision":"allow"}'

    monkeypatch.setattr(benchmark, "_request", request)
    monkeypatch.setattr(benchmark, "review_post_tool_native", native_runtime.review_post_tool_native)
    monkeypatch.setattr(native_runtime, "native_runtime_status", status_call)
    monkeypatch.setattr(native_runtime, "native_resident_client_request", client_call)
    monkeypatch.setattr(native_runtime, "_response_from_payload", lambda _payload: response)
    monkeypatch.setattr(native_runtime, "native_record_resident_success", lambda *_args: None)
    return calls, snapshot, response


def _run(observer, tmp_path, snapshot, *, iterations=2):
    with observer.install(benchmark, native_runtime):
        return benchmark._bench_native_warm_production(
            workspace=tmp_path, guard_home=tmp_path / "guard-home",
            iterations=iterations, policy_snapshot=snapshot,
        )


def test_actual_benchmark_and_adapter_forward_payload_deadline_and_restore(actual_adapter, tmp_path):
    calls, snapshot, _response = actual_adapter
    originals = (
        benchmark._bench_native_warm_production, benchmark.review_post_tool_native,
        native_runtime.native_runtime_status, native_runtime.native_resident_client_request,
    )
    observer = diagnostic.ProductionPhaseObserver()
    values = _run(observer, tmp_path, snapshot)
    assert len(values) == 2
    assert len(calls["status"]) == len(calls["request"]) == 2
    for request, sent in zip(calls["inputs"], calls["request"], strict=True):
        assert sent["deadline_monotonic"] == request.deadline_monotonic
        assert sent["guard_home"] == request.guard_home
        envelope = json.loads(sent["payload"])
        assert envelope["raw_payload"] == request.payload
        assert envelope["request_id"] == request.request_id
        assert envelope["policy_snapshot"] == snapshot
    assert originals == (
        benchmark._bench_native_warm_production, benchmark.review_post_tool_native,
        native_runtime.native_runtime_status, native_runtime.native_resident_client_request,
    )
    report = observer.report()
    assert report["complete"] is True
    assert report["samples_seen"] == report["samples_retained"] == 2
    assert report["acceptance_adjusted"] is False
    assert report["measurement_overhead_included"] is True
    rendered = json.dumps(report)
    for private_value in ("private-policy-canary", "private-runtime-canary", "private-path-canary", str(tmp_path)):
        assert private_value not in rendered


@pytest.mark.parametrize("phase", ["native_runtime_status", "native_resident_client_request"])
def test_actual_adapter_exception_identity_and_bindings_survive(actual_adapter, tmp_path, monkeypatch, phase):
    _calls, snapshot, _response = actual_adapter
    error = RuntimeError("private-exception-canary")

    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(native_runtime, phase, fail)
    originals = (
        benchmark._bench_native_warm_production, benchmark.review_post_tool_native,
        native_runtime.native_runtime_status, native_runtime.native_resident_client_request,
    )
    observer = diagnostic.ProductionPhaseObserver()
    with pytest.raises(RuntimeError) as caught:
        _run(observer, tmp_path, snapshot)
    assert caught.value is error
    assert originals == (
        benchmark._bench_native_warm_production, benchmark.review_post_tool_native,
        native_runtime.native_runtime_status, native_runtime.native_resident_client_request,
    )
    report = observer.report()
    assert report["complete"] is False
    assert report["production_completed"] is False
    assert report["adapter_p95_sample"]["raised"] is True
    assert "private-exception-canary" not in json.dumps(report)


@pytest.mark.parametrize("boundary", ["decision", "route"])
def test_original_benchmark_still_rejects_wrong_decision_or_route(actual_adapter, tmp_path, monkeypatch, boundary):
    _calls, snapshot, response = actual_adapter
    if boundary == "decision":
        response.decision = "deny"
        message = "unexpected decision"
    else:
        monkeypatch.setattr(benchmark, "native_hook_route", lambda: "native_fail_safe")
        message = "did not use the authenticated resident route"
    observer = diagnostic.ProductionPhaseObserver()
    with pytest.raises(RuntimeError, match=message):
        _run(observer, tmp_path, snapshot)
    assert observer.report()["complete"] is False


def test_observation_bound_never_truncates_original_calls(actual_adapter, tmp_path):
    calls, snapshot, _response = actual_adapter
    observer = diagnostic.ProductionPhaseObserver()
    values = _run(observer, tmp_path, snapshot, iterations=diagnostic._MAX_SAMPLES + 1)
    assert len(values) == len(calls["request"]) == diagnostic._MAX_SAMPLES + 1
    report = observer.report()
    assert report["samples_seen"] == diagnostic._MAX_SAMPLES + 1
    assert report["samples_retained"] == diagnostic._MAX_SAMPLES
    assert report["complete"] is False


@pytest.mark.parametrize("raises", [False, True])
def test_main_preserves_original_arguments_exit_and_exception(actual_adapter, monkeypatch, capsys, raises):
    error = RuntimeError("private-main-error-canary")
    arguments = ["diagnostic", "--enforce", "--json", "private-artifact-canary"]
    seen = []

    def main():
        seen.append(list(sys.argv))
        if raises:
            raise error
        return 37

    monkeypatch.setitem(sys.modules, "bench_guard_native_release_gate", benchmark)
    monkeypatch.setattr(benchmark, "main", main)
    monkeypatch.setattr(sys, "argv", arguments)
    original = benchmark._bench_native_warm_production
    if raises:
        with pytest.raises(RuntimeError) as caught:
            diagnostic.main()
        assert caught.value is error
    else:
        assert diagnostic.main() == 37
    assert seen == [arguments]
    assert benchmark._bench_native_warm_production is original
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["complete"] is False
    assert "private-main-error-canary" not in output
    assert "private-artifact-canary" not in output


@pytest.fixture
def status_details(actual_adapter, tmp_path, monkeypatch):
    calls, snapshot, _response = actual_adapter
    ticks = [0.0]
    executable = tmp_path / "private-validation-path-canary"
    identity = SimpleNamespace(path=executable, size=17, mtime_ns=31, sha256="b" * 64)
    candidates = (executable,)
    calls["discovery"] = []
    calls["validation"] = []

    def discover():
        calls["discovery"].append(candidates)
        ticks[0] += 0.002
        return candidates

    def validate(path):
        calls["validation"].append(path)
        ticks[0] += 0.003
        return identity

    capabilities = SimpleNamespace(
        protocol_version=native_runtime._NATIVE_PROTOCOL_VERSION,
        runtime_version="fixture-version",
        features=frozenset({"resident-protocol-v2"}),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", _REAL_NATIVE_STATUS)
    monkeypatch.setattr(native_runtime, "native_mode", lambda: "force")
    monkeypatch.setattr(native_runtime, "_runtime_candidates", discover)
    monkeypatch.setattr(native_runtime, "_validate_binary", validate)
    monkeypatch.setattr(native_runtime, "_is_bundled_candidate", lambda _path: False)
    monkeypatch.setattr(native_runtime, "_capabilities_for_identity", lambda *_args: capabilities)
    monkeypatch.setattr(native_runtime, "_python_package_version", lambda: "fixture-version")
    return calls, snapshot, ticks, executable, identity


def test_real_status_nested_phases_forward_exact_values_and_restore(status_details, tmp_path):
    calls, snapshot, ticks, executable, _identity = status_details
    originals = (native_runtime._runtime_candidates, native_runtime._validate_binary)
    observer = diagnostic.ProductionPhaseObserver(clock=lambda: ticks[0])
    values = _run(observer, tmp_path, snapshot)
    assert len(values) == 2
    assert calls["discovery"] == [(executable,), (executable,)]
    assert calls["validation"] == [executable, executable]
    assert all(sent["executable"] is executable for sent in calls["request"])
    assert originals == (native_runtime._runtime_candidates, native_runtime._validate_binary)
    report = observer.report()
    assert report["complete"] is True
    assert report["status_detail_complete"] is True
    sample = report["adapter_p95_sample"]
    assert sample["discovery_ms"] == pytest.approx(2.0)
    assert sample["validation_ms"] == pytest.approx(3.0)
    assert sample["status_ms"] == sample["adapter_ms"] == pytest.approx(5.0)
    assert sample["status_remaining_ms"] == pytest.approx(0.0)
    assert sample["discovery_calls"] == sample["validation_calls"] == 1
    assert report["acceptance_adjusted"] is False
    assert "private-validation-path-canary" not in json.dumps(report)
    assert str(tmp_path) not in json.dumps(report)


@pytest.mark.parametrize("dependency", ["_runtime_candidates", "_validate_binary"])
def test_nested_status_exception_identity_and_all_bindings_survive(
    status_details, tmp_path, monkeypatch, dependency
):
    _calls, snapshot, ticks, _executable, _identity = status_details
    error = RuntimeError("private-validation-error-canary")

    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(native_runtime, dependency, fail)
    originals = (
        benchmark.review_post_tool_native, native_runtime.native_runtime_status,
        native_runtime.native_resident_client_request, native_runtime._runtime_candidates,
        native_runtime._validate_binary,
    )
    observer = diagnostic.ProductionPhaseObserver(clock=lambda: ticks[0])
    with pytest.raises(RuntimeError) as caught:
        _run(observer, tmp_path, snapshot)
    assert caught.value is error
    assert originals == (
        benchmark.review_post_tool_native, native_runtime.native_runtime_status,
        native_runtime.native_resident_client_request, native_runtime._runtime_candidates,
        native_runtime._validate_binary,
    )
    report = observer.report()
    assert report["complete"] is False
    assert report["status_detail_complete"] is False
    assert report["adapter_p95_sample"]["raised"] is True
    assert "private-validation-error-canary" not in json.dumps(report)


def test_dependency_calls_outside_status_do_not_enter_nested_totals(status_details, tmp_path, monkeypatch):
    calls, snapshot, ticks, executable, identity = status_details
    original_request = native_runtime.native_resident_client_request

    def request(**kwargs):
        assert native_runtime._runtime_candidates() == (executable,)
        assert native_runtime._validate_binary(executable) is identity
        return original_request(**kwargs)

    monkeypatch.setattr(native_runtime, "native_resident_client_request", request)
    observer = diagnostic.ProductionPhaseObserver(clock=lambda: ticks[0])
    _run(observer, tmp_path, snapshot)
    assert len(calls["discovery"]) == len(calls["validation"]) == 4
    sample = observer.report()["adapter_p95_sample"]
    assert sample["discovery_calls"] == sample["validation_calls"] == 1
    assert sample["discovery_ms"] == pytest.approx(2.0)
    assert sample["validation_ms"] == pytest.approx(3.0)
    assert sample["status_ms"] == sample["request_ms"] == pytest.approx(5.0)
    assert sample["adapter_ms"] == pytest.approx(10.0)
    assert sample["remaining_ms"] == sample["status_remaining_ms"] == pytest.approx(0.0)
