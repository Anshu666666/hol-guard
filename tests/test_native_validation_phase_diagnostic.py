from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_runtime
from tests.test_native_performance_phase_diagnostic import benchmark
from tests.test_native_performance_phase_diagnostic import diagnostic as phases

SPEC = importlib.util.spec_from_file_location(
    "bench_guard_native_validation_diagnostic",
    Path(__file__).resolve().parents[1] / "scripts" / "bench_guard_native_validation_diagnostic.py",
)
assert SPEC is not None and SPEC.loader is not None
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)
ORIGINAL = native_runtime._validate_binary


def _binary(tmp_path: Path, data: bytes = b"private-binary-content") -> Path:
    path = tmp_path / "private-binary-path"
    path.write_bytes(data)
    path.chmod(0o700)
    return path


def test_real_full_byte_validation_and_closed_subphase_report(tmp_path: Path) -> None:
    data = b"guard-bytes" * 230_000
    path = _binary(tmp_path, data)
    previous = sys.gettrace()
    observer = diagnostic.ValidatorPhaseObserver()
    result = observer.call(ORIGINAL, path)
    assert result is not None and result.sha256 == hashlib.sha256(data).hexdigest()
    assert sys.gettrace() is previous
    report = observer.report()
    assert report["complete"] is True
    sample = report["validation_wall_p95_sample"]
    assert sample["entries"] == 1 and sample["segments"] > 10
    assert sample["wall_ms"] >= 0 and sample["thread_cpu_ms"] >= 0 and sample["process_cpu_ms"] >= 0
    assert sample["phases"]["read_loop"]["wall_ms"] > 0
    assert sample["phases"]["digest_update"]["wall_ms"] > 0
    assert sample["phases"]["path"]["wall_ms"] > 0
    assert sample["phases"]["trust"]["wall_ms"] > 0
    assert report["acceptance_adjusted"] is False and report["measurement_overhead_included"] is True
    assert report["waiting_attribution"] == "unassigned"
    assert report["process_cpu_scope"] == "all-process-threads"
    rendered = json.dumps(report)
    for private in (str(tmp_path), path.name, data[:20].decode(), result.sha256):
        assert private not in rendered


def test_each_real_call_still_hashes_changed_bytes_with_unchanged_metadata(tmp_path: Path) -> None:
    path = _binary(tmp_path, b"first-bytes")
    metadata = path.stat()
    observer = diagnostic.ValidatorPhaseObserver()
    first = observer.call(ORIGINAL, path)
    path.write_bytes(b"other-bytes")
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    second = observer.call(ORIGINAL, path)
    assert first is not None and second is not None
    assert first.size == second.size and first.mtime_ns == second.mtime_ns
    assert first.sha256 != second.sha256
    assert observer.report()["samples_seen"] == 2


def test_real_validator_exception_identity_and_trace_restoration(tmp_path: Path, monkeypatch) -> None:
    path = _binary(tmp_path)
    previous = sys.gettrace()
    error = LookupError("private-validation-exception")
    observer = diagnostic.ValidatorPhaseObserver()

    def fail():
        raise error

    with monkeypatch.context() as patch:
        patch.setattr(native_runtime.hashlib, "sha256", fail)
        with pytest.raises(LookupError) as caught:
            observer.call(ORIGINAL, path)
    assert caught.value is error and sys.gettrace() is previous
    assert observer.report()["validation_wall_p95_sample"]["raised"] is True
    assert str(error) not in json.dumps(observer.report())


def test_real_validator_handled_read_error_still_refuses(tmp_path: Path, monkeypatch) -> None:
    path = _binary(tmp_path)
    original_open = Path.open

    def fail(self, *args, **kwargs):
        if self == path:
            raise OSError("private-read-failure")
        return original_open(self, *args, **kwargs)

    observer = diagnostic.ValidatorPhaseObserver()
    previous = sys.gettrace()
    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", fail)
        assert observer.call(ORIGINAL, path) is None
    assert sys.gettrace() is previous
    assert observer.report()["validation_wall_p95_sample"]["raised"] is False
    assert "private-read-failure" not in json.dumps(observer.report())


def test_existing_trace_is_preserved_without_detailed_instrumentation(tmp_path: Path) -> None:
    path = _binary(tmp_path)
    previous = sys.gettrace()

    def existing(_frame, _event, _arg):
        return existing

    observer = diagnostic.ValidatorPhaseObserver()
    try:
        sys.settrace(existing)
        result = observer.call(ORIGINAL, path)
        assert result is not None and sys.gettrace() is existing
    finally:
        sys.settrace(previous)
    report = observer.report()
    assert report["complete"] is False
    assert report["detail_counts"]["existing-trace"] == 1
    assert report["validation_wall_p95_sample"]["entries"] == 0


def test_other_callable_forwards_same_arguments_and_result_without_tracing() -> None:
    positional, keyword, result = object(), object(), object()
    observed = []

    def unrelated(*args, **kwargs):
        observed.append((args, kwargs))
        return result

    observer = diagnostic.ValidatorPhaseObserver()
    assert observer.call(unrelated, positional, named=keyword) is result
    assert observed == [((positional,), {"named": keyword})]
    assert observer.report()["detail_counts"]["different-code"] == 1


def test_trace_install_refusal_delegates_original_call(tmp_path: Path, monkeypatch) -> None:
    path = _binary(tmp_path)
    observer = diagnostic.ValidatorPhaseObserver()
    previous = sys.gettrace()

    def refused(_trace):
        raise RuntimeError("private-trace-refusal")

    with monkeypatch.context() as patch:
        patch.setattr(sys, "settrace", refused)
        assert observer.call(ORIGINAL, path) is not None
    assert sys.gettrace() is previous
    assert observer.report()["detail_counts"]["trace-unavailable"] == 1
    assert "private-trace-refusal" not in json.dumps(observer.report())


def test_bounded_retention_preserves_every_original_call(tmp_path: Path) -> None:
    path = _binary(tmp_path)
    observer = diagnostic.ValidatorPhaseObserver(limit=2)
    for _ in range(5):
        assert observer.call(ORIGINAL, path) is not None
    report = observer.report()
    assert report["samples_seen"] == 5 and report["samples_retained"] == 2
    assert report["complete"] is False


@pytest.mark.parametrize("background", [False, True])
def test_real_production_loop_keeps_original_arguments_results_and_gates(
    tmp_path: Path, monkeypatch, capsys, background
) -> None:
    path = _binary(tmp_path)
    original_production = benchmark._bench_native_warm_production
    original_validation = native_runtime._validate_binary
    argv = ["benchmark", "--warm-iterations", "2", "--enforce"]
    requests = []
    background_results = []

    def worker():
        try:
            background_results.append((native_runtime._validate_binary(path), sys.gettrace()))
        except BaseException as error:
            background_results.append(error)

    def status():
        if background and not background_results:
            thread = threading.Thread(target=worker)
            thread.start()
            thread.join(timeout=5)
            assert not thread.is_alive()
            assert len(background_results) == 1
            value = background_results[0]
            assert isinstance(value, tuple) and value[0] is not None and value[1] is None
        identity = native_runtime._validate_binary(path)
        assert identity is not None
        return SimpleNamespace(
            available=True,
            compatible=True,
            identity=identity,
            capabilities=SimpleNamespace(features=frozenset({"resident-protocol-v2"})),
        )

    def request(**kwargs):
        requests.append(kwargs)
        return b'{"decision":"allow"}'

    def original_main():
        assert sys.argv is argv
        assert native_runtime._validate_binary(path) is not None
        values = benchmark._bench_native_warm_production(
            workspace=tmp_path,
            guard_home=tmp_path / "guard-home",
            iterations=2,
            policy_snapshot={
                "generation": 7,
                "policy_digest": "diagnostic-policy",
                "runtime_identity": "diagnostic-runtime",
            },
        )
        assert len(values) == 2
        assert native_runtime._validate_binary(path) is not None
        return 37

    monkeypatch.setitem(sys.modules, "bench_guard_native_release_gate", benchmark)
    monkeypatch.setitem(sys.modules, "bench_guard_native_phase_diagnostic", phases)
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(benchmark, "main", original_main)
    monkeypatch.setattr(benchmark, "review_post_tool_native", native_runtime.review_post_tool_native)
    monkeypatch.setattr(native_runtime, "native_runtime_status", status)
    monkeypatch.setattr(native_runtime, "native_resident_client_request", request)
    monkeypatch.setattr(native_runtime, "_response_from_payload", lambda _value: SimpleNamespace(decision="allow"))
    monkeypatch.setattr(native_runtime, "native_record_resident_success", lambda *_args: None)
    assert diagnostic.main() == 37
    assert benchmark._bench_native_warm_production is original_production
    assert native_runtime._validate_binary is original_validation
    assert len(requests) == 2 and all(call["deadline_monotonic"] > 0 for call in requests)
    reports = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(reports) == 2
    assert reports[0]["iterations_requested"] == 2 and reports[0]["acceptance_adjusted"] is False
    assert reports[1]["samples_seen"] == 2 and reports[1]["complete"] is True
    assert reports[0]["adapter_p95_sample"]["validation_calls"] == 1
    assert len(background_results) == int(background)
    assert str(tmp_path) not in json.dumps(reports)


def test_wall_thread_and_process_clocks_remain_distinct_in_real_validator(tmp_path: Path, monkeypatch) -> None:
    path = _binary(tmp_path)
    ticks = [0]

    def clock():
        ticks[0] += 1
        return ticks[0] * 1_000_000, ticks[0] * 200_000, ticks[0] * 500_000

    monkeypatch.setattr(diagnostic, "_clock", clock)
    observer = diagnostic.ValidatorPhaseObserver()
    assert observer.call(ORIGINAL, path) is not None
    sample = observer.report()["validation_wall_p95_sample"]
    assert sample["wall_ms"] == pytest.approx(5 * sample["thread_cpu_ms"])
    assert sample["wall_ms"] == pytest.approx(2 * sample["process_cpu_ms"])
    assert sample["unassigned_wait_ms"] == pytest.approx(sample["wall_ms"] - sample["thread_cpu_ms"])
    for phase in sample["phases"].values():
        assert phase["wall_ms"] == pytest.approx(5 * phase["thread_cpu_ms"])
        assert phase["wall_ms"] == pytest.approx(2 * phase["process_cpu_ms"])
    assert sample["phases"]["read_loop"]["wall_ms"] > 0
    assert sample["phases"]["digest_update"]["wall_ms"] > 0
