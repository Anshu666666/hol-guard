from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ci.native_runtime.windows_startup_capture import (
    MAX_OUTPUT_BYTES,
    PAYLOAD,
    SELECTOR,
    Capture,
    CapturePlugin,
    _body,
)
from ci.native_runtime.windows_startup_record import CODES, EVENTS, PREFIX, STAGES, parse_stderr


def record() -> dict[str, Any]:
    phases = [[0] * 7 for _ in STAGES]
    phases[0] = [1, 1, 0, 100, 110, 0, 0]
    return {
        "schema": "hol-guard-native-windows-startup.v1",
        "parent_only": True, "child_observed": False, "complete_run": False,
        "headline_timing_eligible": False, "qualification_complete": False,
        "original_error": 0, "original_budget_us": 750000,
        "observed_elapsed_us": 10000, "observed_remaining_us": 740000,
        "phases": phases, "events": [[0] * 4 for _ in EVENTS],
        "retries": [0] * 5, "counter_or_clock_overflow": False,
        "observation_lost": False,
    }


def frame(value: dict[str, Any], original: bytes = b"") -> bytes:
    return original + PREFIX + json.dumps(value, separators=(",", ":")).encode() + b"\n"


def invocation() -> tuple[tuple[str, ...], dict[str, Any]]:
    return ("/owned/runtime.exe", "hook-client", "--stdin", "/owned/native-runtime"), {
        "input": PAYLOAD, "check": False, "capture_output": True, "timeout": 3,
    }


def test_actual_zero_state_count_and_original_failure_join() -> None:
    value = record()
    value["events"][EVENTS.index("States")] = [1, 0, 100, 200]
    error = "native_resident_start_timeout"
    value["original_error"] = CODES.index(error) + 2
    value["observed_elapsed_us"] = 800000
    value["observed_remaining_us"] = 0
    parsed = parse_stderr(frame(value, error.encode() + b"\n"), 2)
    assert parsed["status"] == "valid"
    assert parsed["original_stderr"] == error.encode() + b"\n"
    assert parsed["record"]["events"][EVENTS.index("States")][:2] == [1, 0]
    assert parsed["record"]["events"][EVENTS.index("Paths")] == [0, 0, 0, 0]
    assert not parsed["record"]["child_observed"]


@pytest.mark.parametrize(("field", "bad"), [
    ("schema", "different"),
    ("parent_only", False), ("child_observed", True), ("complete_run", True),
    ("headline_timing_eligible", True), ("qualification_complete", True),
    ("observation_lost", 0), ("counter_or_clock_overflow", "false"),
    ("original_budget_us", 751000), ("original_budget_us", True),
    ("observed_elapsed_us", -1), ("observed_remaining_us", 750001),
    ("original_error", len(CODES) + 2), ("original_error", False),
    ("phases", []), ("events", []), ("retries", [0, 0, 0]),
])
def test_reader_rejects_wrong_schema_scope_types_and_bounds(field: str, bad: Any) -> None:
    value = record()
    value[field] = bad
    with pytest.raises(ValueError):
        parse_stderr(frame(value), 0)


@pytest.mark.parametrize("bad_phase", [
    [0, 1, 0, 0, 0, 0, 0],
    [1, 1, 2, 1, 2, 2, 2],
    [1, 1, 1, 1, 2, 0, 0],
    [1, 1, 0, 2, 1, 0, 0],
    [1, 1, 0, 1, 10001, 0, 0],
    [1, 0, 0, 1, 2, 0, 0],
    [65536, 65536, 0, 1, 2, 0, 0],
])
def test_reader_rejects_inconsistent_phase_rows(bad_phase: list[int]) -> None:
    value = record()
    value["phases"][0] = bad_phase
    with pytest.raises(ValueError):
        parse_stderr(frame(value), 0)


@pytest.mark.parametrize("mutation", [
    "missing_field", "extra_field", "duplicate_key", "duplicate_frame",
    "truncated", "after_frame", "nonfinite", "too_large", "wrong_exit",
    "wrong_error", "bad_event", "bad_retry", "clock_mismatch",
])
def test_reader_rejects_unjoinable_or_truncated_records(mutation: str) -> None:
    value = record()
    code = 0
    if mutation == "missing_field":
        del value["parent_only"]
    elif mutation == "extra_field":
        value["path"] = "forbidden"
    elif mutation == "bad_event":
        value["events"][0] = [0, 1, 0, 0]
    elif mutation == "bad_retry":
        value["retries"] = [1, 2, 2, 0, 2]
    elif mutation == "clock_mismatch":
        value["observed_remaining_us"] -= 2
    raw = frame(value)
    if mutation == "duplicate_key":
        raw = raw.replace(b'{"schema":', b'{"schema":"duplicate","schema":', 1)
    elif mutation == "duplicate_frame":
        raw += raw
    elif mutation == "truncated":
        raw = raw[:-1]
    elif mutation == "after_frame":
        raw += b"unexpected\n"
    elif mutation == "nonfinite":
        raw = raw.replace(b'"observed_elapsed_us":10000', b'"observed_elapsed_us":NaN')
    elif mutation == "too_large":
        raw = PREFIX + b" " * 4096 + b"{}\n"
    elif mutation == "wrong_exit":
        code = 7
    elif mutation == "wrong_error":
        raw = b"native_resident_start_timeout\n" + raw
        code = 2
    with pytest.raises(ValueError):
        parse_stderr(raw, code)


@pytest.mark.parametrize("reason", ["lost", "overflow", "unknown", "unfinished"])
def test_incomplete_observation_never_becomes_complete(reason: str) -> None:
    value = record()
    if reason == "lost":
        value["observation_lost"] = True
    elif reason == "overflow":
        value["counter_or_clock_overflow"] = True
    elif reason == "unknown":
        value["phases"][0] = [1, 1, 1, 100, 110, 1, 1]
    else:
        value["phases"][0] = [2, 1, 0, 100, 110, 0, 0]
    assert parse_stderr(frame(value), 0)["status"] == "incomplete"
    assert parse_stderr(b"native_resident_start_timeout\n", 2)["status"] == "missing"


def test_spy_forwards_original_target_once_and_retains_result_before_assertions() -> None:
    argv, kwargs = invocation()
    returned = subprocess.CompletedProcess(argv, 0, b'{"error":"native_request_invalid_json","retryable":false}', frame(record()))
    seen: list[tuple[Any, Any]] = []

    def original(*args: Any, **options: Any) -> Any:
        seen.append((args, options))
        assert args[0] is argv
        assert options["input"] is kwargs["input"]
        assert options == kwargs
        return returned

    capture = Capture(original, argv[0])
    assert capture.invoke(argv, **kwargs) is returned
    assert len(seen) == capture.target_calls == capture.exact_calls == 1
    assert capture.returned is not None
    assert capture.returned["observation"]["status"] == "valid"
    assert capture.returned["stdout"]["complete"]
    assert capture.returned["returncode"] == 0


@pytest.mark.parametrize("error", [
    subprocess.TimeoutExpired(("runtime",), 3), OSError(5, "private-sentinel"),
    KeyboardInterrupt(), RuntimeError("private-sentinel"),
])
def test_spy_preserves_original_exception_identity(error: BaseException) -> None:
    argv, kwargs = invocation()
    calls = 0

    def original(*args: Any, **options: Any) -> Any:
        nonlocal calls
        calls += 1
        raise error

    capture = Capture(original, argv[0])
    with pytest.raises(type(error)) as raised:
        capture.invoke(argv, **kwargs)
    assert raised.value is error and calls == 1
    assert "private-sentinel" not in json.dumps(capture.result(1))


def test_spy_rejects_changed_call_without_changing_its_execution() -> None:
    argv, kwargs = invocation()
    kwargs["timeout"] = 4
    returned = subprocess.CompletedProcess(argv, 2, b"", b"original\n")
    capture = Capture(lambda *args, **options: returned, argv[0])
    assert capture.invoke(argv, **kwargs) is returned
    assert capture.target_calls == 1 and capture.exact_calls == 0 and capture.lost


def test_duplicate_target_calls_remain_two_original_calls_and_fail_capture() -> None:
    argv, kwargs = invocation()
    calls: list[object] = []
    returned = subprocess.CompletedProcess(argv, 0, b"{}", frame(record()))
    def original(*args: Any, **options: Any) -> Any:
        calls.append(args)
        return returned
    capture = Capture(original, argv[0])
    capture.invoke(argv, **kwargs)
    first = copy.deepcopy(capture.returned)
    capture.invoke(argv, **kwargs)
    assert len(calls) == capture.target_calls == 2
    assert capture.lost and capture.returned == first


def test_capture_failure_does_not_replace_original_return(monkeypatch: pytest.MonkeyPatch) -> None:
    argv, kwargs = invocation()
    returned = subprocess.CompletedProcess(argv, 0, b"{}", b"")
    capture = Capture(lambda *args, **options: returned, argv[0])
    def unavailable(_result: Any) -> None:
        raise RuntimeError("observer failure")
    monkeypatch.setattr(capture, "_returned", unavailable)
    assert capture.invoke(argv, **kwargs) is returned
    assert capture.lost


def test_original_stop_result_is_observed_without_extra_cleanup_call() -> None:
    argv, _kwargs = invocation()
    stop = (argv[0], "resident-stop", "--state-dir", argv[3])
    returned = subprocess.CompletedProcess(stop, 2, b"", b"native_resident_stop_unavailable\n")
    seen: list[Any] = []
    def original(*args: Any, **kwargs: Any) -> Any:
        seen.append((args, kwargs))
        return returned
    capture = Capture(original, argv[0])
    assert capture.invoke(stop, check=False, capture_output=True, timeout=2) is returned
    assert len(seen) == 1 and capture.target_calls == 0 and capture.stop_calls == 1
    result = capture.result(0)
    assert result["original_stop_result"]["returncode"] == 2
    assert result["complete_descendant_cleanup"] is False


def test_unrelated_call_is_forwarded_without_observer_data() -> None:
    value = object()
    capture = Capture(lambda *args, **kwargs: value, "/runtime")
    assert capture.invoke(("python", "--version"), timeout=1) is value
    assert capture.other_calls == 1 and capture.target_calls == 0
    assert capture.returned is None


def test_output_caps_retain_only_prefix_with_no_false_full_digest() -> None:
    raw = b"x" * (MAX_OUTPUT_BYTES + 1)
    retained = _body(raw)
    assert retained["bytes"] == len(raw) and not retained["complete"]
    assert retained["sha256"] is None
    assert len(retained["base64"]) < len(raw) * 2
    assert _body("wrong type")["present"] is False


def test_original_phase_failure_and_duplicate_phase_are_preserved() -> None:
    capture = Capture(lambda: None, "/runtime")
    capture.phase(SELECTOR, "setup", "passed")
    capture.phase(SELECTOR, "call", "failed")
    capture.phase(SELECTOR, "teardown", "passed")
    capture.phase(SELECTOR, "call", "passed")
    result = capture.result(1)
    assert result["original_pytest_exit"] == 1 and result["phases"]["call"] == "failed"
    assert result["capture_lost"] and not result["qualification_complete"]


def test_existing_capture_file_is_preserved_and_original_run_restored(tmp_path: Path) -> None:
    output = tmp_path / "capture.json"
    output.write_text("original", encoding="utf-8")
    original = subprocess.run
    plugin = CapturePlugin("/runtime", output)
    try:
        plugin.pytest_sessionfinish(None, 1)
        assert output.read_text(encoding="utf-8") == "original"
        assert subprocess.run is original
    finally:
        plugin.pytest_unconfigure(None)

@pytest.mark.parametrize(("elapsed", "valid"), [
    (749999, True), (750000, True), (750001, True), (749998, False),
])
def test_zero_remaining_preserves_microsecond_flooring_boundary(elapsed: int, valid: bool) -> None:
    value = record()
    value["observed_elapsed_us"] = elapsed
    value["observed_remaining_us"] = 0
    if valid:
        assert parse_stderr(frame(value), 0)["status"] == "valid"
    else:
        with pytest.raises(ValueError):
            parse_stderr(frame(value), 0)
