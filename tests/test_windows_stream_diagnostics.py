"""Controls for the diagnostic's original-call, byte-binding and privacy contract."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.ci import windows_stream_diagnostics as driver
from scripts.ci import windows_stream_json_capture as capture_module
from scripts.ci.windows_stream_json_capture import InvalidJsonCapture, json_shape

ERROR = b'{"error":"native_request_invalid_json","retryable":false}'


def test_full_original_256k_string_remains_bounded_without_value_retention() -> None:
    sentinel = "never-export-this-private-value"
    encoded = json.dumps({"raw_payload": {"content": sentinel + "x" * (262144 - len(sentinel))}}).encode()
    shape = json_shape(encoded)
    assert shape["sha256"] == hashlib.sha256(encoded).hexdigest()
    assert shape["byte_count"] == len(encoded)
    assert shape["maximum_string_bytes"] == 262144
    assert shape["maximum_depth"] == 2
    assert shape["json_syntax_valid"] is shape["recorded_structural_bounds_met"] is True
    assert shape["rust_parser_equivalence_claim"] is False
    assert sentinel not in json.dumps(shape)
    assert "content" not in json.dumps(shape)


@pytest.mark.parametrize(
    ("encoded", "key", "expected"),
    [
        (b'{"x":', "json_syntax_valid", False),
        (b'{"x":"\xff"}', "utf8_valid", False),
        (b'{"x":1,"x":2}', "duplicate_keys", True),
        (b'{"x":NaN}', "finite_numbers", False),
        (b'{"x":1e999}', "finite_numbers", False),
        (b'{"x":"\\ud800"}', "decoded_strings_utf8_valid", False),
        (b"[" * 33 + b"0" + b"]" * 33, "maximum_depth", 33),
        (json.dumps([0] * 4097).encode(), "maximum_collection_items", 4097),
        (json.dumps({"x": "a" * (1024 * 1024 + 1)}).encode(), "maximum_string_bytes", 1024 * 1024 + 1),
        (json.dumps({"a" * (1024 * 1024 + 1): 1}).encode(), "maximum_key_bytes", 1024 * 1024 + 1),
    ],
)
def test_malformed_or_out_of_bounds_shapes_stay_failed(encoded: bytes, key: str, expected: object) -> None:
    shape = json_shape(encoded)
    assert shape[key] == expected
    assert shape["recorded_structural_bounds_met"] is False


def test_byte_and_traversal_limits_remain_explicit() -> None:
    large = json_shape(b"x" * (capture_module.MAX_BYTES + 1))
    assert large["byte_bound_met"] is False and large["sha256"] is None
    wide = json_shape(json.dumps([[0] * 4096] * 17).encode())
    assert wide["node_bound_met"] is False
    assert wide["nodes_observed"] <= capture_module.MAX_NODES
    assert wide["recorded_structural_bounds_met"] is False


def test_failure_capture_forwards_same_arguments_and_result_once() -> None:
    payload = b'{"test":"private-material"}'
    arguments: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def original(*args: Any, **kwargs: Any) -> bytes:
        arguments.append((args, kwargs))
        return ERROR

    edge = SimpleNamespace(native_resident_client_request=original)
    observer = InvalidJsonCapture(edge)
    with observer:
        assert edge.native_resident_client_request("runtime", payload=payload, deadline_monotonic=123.5) is ERROR
    assert arguments == [(("runtime",), {"payload": payload, "deadline_monotonic": 123.5})]
    assert edge.native_resident_client_request is original
    report = observer.report({})
    assert report["provider_restored"] is report["failure_reproduced"] is True
    assert report["observation_complete"] is False  # No stream frame was supplied for this unit control.
    assert "private-material" not in json.dumps(report)
    assert report["failures"][0]["request"]["sha256"] == hashlib.sha256(payload).hexdigest()


def test_success_does_not_parse_or_hash_caller_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(_payload: object) -> None:
        pytest.fail("successful response triggered failure-only inspection")

    monkeypatch.setattr(capture_module, "json_shape", forbidden)
    response = b'{"ok":true}'
    edge = SimpleNamespace(native_resident_client_request=lambda **_kwargs: response)
    with InvalidJsonCapture(edge) as observer:
        assert edge.native_resident_client_request(payload=b"private") is response
    assert observer.report({})["failures"] == []


def test_original_exception_and_collector_faults_preserve_the_original_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = TimeoutError("private-original-message")

    def original(**_kwargs: object) -> None:
        raise expected

    edge = SimpleNamespace(native_resident_client_request=original)
    with InvalidJsonCapture(edge) as observer, pytest.raises(TimeoutError) as caught:
        edge.native_resident_client_request(payload=b"{}")
    assert caught.value is expected
    assert observer.report({})["failures"] == []

    def failing_observer(_payload: bytes) -> None:
        raise RuntimeError("private-observer-message")

    edge.native_resident_client_request = lambda **_kwargs: ERROR
    monkeypatch.setattr(capture_module, "json_shape", failing_observer)
    with InvalidJsonCapture(edge) as observer:
        assert edge.native_resident_client_request(payload=b"{}") is ERROR
    report = observer.report({})
    assert report["collector_faults"] == 1 and report["observation_complete"] is False
    assert "private" not in json.dumps(report)


def test_capture_never_waits_on_its_busy_lock_and_reports_loss() -> None:
    edge = SimpleNamespace(native_resident_client_request=lambda **_kwargs: ERROR)
    with InvalidJsonCapture(edge) as observer:
        with observer.lock:
            assert edge.native_resident_client_request(payload=b"{}") is ERROR
        for _ in range(capture_module.MAX_FAILURES + 1):
            assert edge.native_resident_client_request(payload=b"{}") is ERROR
    report = observer.report({})
    assert len(report["failures"]) == capture_module.MAX_FAILURES
    assert report["dropped_failures"] == 2 and report["observation_complete"] is False


def test_only_same_request_response_bytes_join_to_one_native_frame() -> None:
    payload = b'{"x":1}'
    digest, response_digest = hashlib.sha256(payload).hexdigest(), hashlib.sha256(ERROR).hexdigest()
    edge = SimpleNamespace(native_resident_client_request=lambda **_kwargs: ERROR)
    with InvalidJsonCapture(edge) as observer:
        edge.native_resident_client_request(payload=payload)
    call = {
        "payload_sha256": digest,
        "payload_bytes": len(payload),
        "response_sha256": response_digest,
        "response_bytes": len(ERROR),
        "process_index": 7,
    }
    frame = {
        "frame_sequence": 3,
        "response_sha256": response_digest,
        "response_bytes": len(ERROR),
        "report": {"payload_sha256": digest, "payload_bytes": len(payload)},
    }
    stream: dict[str, Any] = {"calls": [call], "processes": [{"process_index": 7, "records": [frame]}]}
    assert observer.report(stream)["joins"][0]["unambiguous_original_request_join"] is True
    assert observer.report(stream)["observation_complete"] is True
    frame["response_sha256"] = "0" * 64
    assert observer.report(stream)["joins"][0]["unambiguous_original_request_join"] is False
    assert observer.report(stream)["observation_complete"] is False
    frame["response_sha256"] = response_digest
    stream["calls"].append(dict(call))
    assert observer.report(stream)["joins"][0]["unambiguous_original_request_join"] is False


def test_redirect_preserves_every_original_argument_except_explicit_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime.exe"
    report = tmp_path / "fixture.json"
    calls: list[tuple[Any, dict[str, object]]] = []
    returned = object()

    def spawn(argv: object, **kwargs: object) -> object:
        calls.append((argv, kwargs))
        return returned

    monkeypatch.setattr(driver.native_slo_daemon_fixture, "_spawn_hook_process", spawn)
    fixture_file = str(Path(driver.native_slo_daemon_fixture.__file__).resolve())
    argv = (sys.executable, "-u", fixture_file, "--serve", str(runtime), "normal", "none")
    environment = {"unchanged": "opaque"}
    kwargs: dict[str, Any] = {
        "cwd": tmp_path,
        "environment": environment,
        "allow_windows_breakaway": False,
        "windows_kill_on_job_close": True,
        "parent_liveness": False,
    }
    with driver.FixtureRedirect(runtime, "a" * 64, report) as redirect:
        assert driver.native_slo_daemon_fixture._spawn_hook_process(argv, **kwargs) is returned
        other = (*argv[:5], "expired", "none")
        assert driver.native_slo_daemon_fixture._spawn_hook_process(other, **kwargs) is returned
    selected = calls[0][0]
    assert selected[:2] == argv[:2]
    assert selected[2] == str(Path(driver.__file__).resolve())
    assert selected[3:7] == ("--fixture-report", str(report), "--expected-runtime-sha256", "a" * 64)
    assert selected[7:] == argv[3:]
    assert calls[0][1] == calls[1][1] == kwargs
    assert calls[0][1]["environment"] is environment
    assert calls[1][0] is other
    assert redirect.selected_spawns == redirect.other_spawns == 1
    assert redirect.restored and driver.native_slo_daemon_fixture._spawn_hook_process is spawn


def test_original_source_hashes_are_exact_and_report_cannot_overwrite(tmp_path: Path) -> None:
    assert driver.verify_source() == driver._ORIGINAL_LF_HASHES
    output = tmp_path / "evidence.json"
    driver.write_report(output, {"fixed": True})
    original = output.read_bytes()
    with pytest.raises(FileExistsError):
        driver.write_report(output, {"fixed": False})
    assert output.read_bytes() == original


@pytest.mark.parametrize("original_raises", [False, True])
def test_child_original_arguments_result_and_exception_survive_observer_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, original_raises: bool
) -> None:
    from scripts import native_slo_stream_diagnostic

    operations: list[object] = []
    expected = TimeoutError("private-original-failure")

    class Capture:
        def __init__(self, runtime: Path) -> None:
            operations.append(("capture_construct", runtime))

        def __enter__(self) -> Capture:
            operations.append("capture_enter")
            return self

        def __exit__(self, *_args: object) -> None:
            operations.append("capture_exit")
            raise RuntimeError("private-cleanup-failure")

        def report(self) -> dict[str, object]:
            operations.append("capture_report")
            return {"observation_complete": True, "calls": [], "processes": []}

    def original(*args: object, **kwargs: object) -> int:
        operations.append(("original", args, kwargs))
        if original_raises:
            raise expected
        return 23

    monkeypatch.setattr(native_slo_stream_diagnostic, "StreamCapture", Capture)
    monkeypatch.setattr(driver, "verify_imports", lambda: None)
    monkeypatch.setattr(driver.native_slo_daemon_fixture, "_serve", original)
    identity = SimpleNamespace(sha256="a" * 64)
    monkeypatch.setattr(driver.native_runtime, "_validate_binary", lambda _runtime: identity)
    runtime = tmp_path / "runtime.exe"
    output = tmp_path / "child.json"
    arguments: dict[str, Any] = {"native_phases": False, "report_path": output, "expected_digest": "a" * 64}
    if original_raises:
        with pytest.raises(TimeoutError) as caught:
            driver.serve_captured(runtime, "normal", "none", None, **arguments)
        assert caught.value is expected
    else:
        assert driver.serve_captured(runtime, "normal", "none", None, **arguments) == 23
    assert operations == [
        ("capture_construct", runtime),
        "capture_enter",
        ("original", (runtime, "normal", "none", None), {"native_phases": False}),
        "capture_exit",
        "capture_report",
    ]
    report = json.loads(output.read_bytes())
    assert report["observer_cleanup_failed"] is True
    assert report["observation_complete"] is False
    assert report["original_fixture_entered"] is True
    assert report["original_fixture_returned"] is not original_raises
    assert "private" not in json.dumps(report)


def test_child_argument_adapter_preserves_the_original_entrypoint_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import native_slo_daemon_entrypoint

    runtime = tmp_path / "runtime.exe"
    runtime.write_bytes(b"unit-control")
    report = tmp_path / "child.json"
    observed: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def captured(*args: object, **kwargs: object) -> int:
        observed.append((args, kwargs))
        return 17

    monkeypatch.setattr(driver, "serve_captured", captured)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "driver.py",
            "--fixture-report",
            str(report),
            "--expected-runtime-sha256",
            "a" * 64,
            "--serve",
            str(runtime),
            "normal",
            "none",
        ],
    )
    original_entrypoint = native_slo_daemon_entrypoint.main
    assert callable(original_entrypoint)
    assert driver.main() == 17
    assert observed == [
        (
            (runtime.resolve(), "normal", "none", None),
            {"native_phases": False, "report_path": report, "expected_digest": "a" * 64},
        )
    ]
