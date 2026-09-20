"""Untimed parser and exact original-call forwarding controls."""

from __future__ import annotations

import json
import signal
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from ci.native_runtime import mac_recovery_plugin as plugin
from ci.native_runtime.mac_recovery_capture import Capture
from ci.native_runtime.mac_recovery_record import CODES, PREFIX, decode


def native_record() -> dict[str, Any]:
    return {
        "schema": "hol-guard-macos-recovery-failure.v1",
        "complete_run": False,
        "headline_timing_eligible": False,
        "stage": "live_exchange_pre_collapse",
        "known_code": "native_client_frame_read_failed",
        "retryable_teardown": False,
        "retained_observations": 1,
        "maximum_retained_observations": 1,
        "additional_observation_lost": False,
        "snapshot_atomic": False,
        "scope": "first_observed_non_retryable_live_exchange_error",
        "generation": 42,
        "process_id": 123,
        "owner_process_id": 456,
        "transport": "unix",
        "state_fields_coherent": True,
        "owner_liveness_observed": False,
    }


def encoded(value: dict[str, Any]) -> bytes:
    return b"native_resident_live_request_failed\n" + PREFIX + json.dumps(value).encode() + b"\n"


def test_all_known_codes_and_maximum_scalars_roundtrip() -> None:
    for code in CODES:
        value = native_record()
        value.update(known_code=code, generation=2**64 - 1, process_id=2**32 - 1, owner_process_id=0)
        assert decode(encoded(value)) == value


@pytest.mark.parametrize(
    "fault",
    ["extra", "bool_pid", "negative", "overflow", "code", "transport", "bool_fixed", "float_fixed", "loss_type"],
)
def test_invalid_native_records_are_rejected(fault: str) -> None:
    value = native_record()
    updates = {
        "extra": {"private": "secret"},
        "bool_pid": {"process_id": True},
        "negative": {"generation": -1},
        "overflow": {"owner_process_id": 2**32},
        "code": {"known_code": "private secret"},
        "transport": {"transport": "private endpoint"},
        "bool_fixed": {"retained_observations": True},
        "float_fixed": {"retained_observations": 1.0},
        "loss_type": {"additional_observation_lost": 0},
    }
    value.update(updates[fault])
    with pytest.raises(ValueError):
        decode(encoded(value))


@pytest.mark.parametrize("fault", ["duplicate", "placement", "two_frames", "oversized", "extra_line"])
def test_invalid_frame_grammar_is_rejected(fault: str) -> None:
    body = encoded(native_record())
    if fault == "duplicate":
        body = body.replace(b'"generation": 42', b'"generation": 42, "generation": 42')
    elif fault == "placement":
        body = body.replace(b"native_resident_live_request_failed", b"different_error")
    elif fault == "two_frames":
        body += body.splitlines(keepends=True)[1]
    elif fault == "oversized":
        body = b"x" * 8193
    else:
        body += b"extra\n"
    with pytest.raises(ValueError):
        decode(body)


def test_native_loss_is_retained_and_blocks_complete_observation() -> None:
    capture = Capture("runtime", "state")
    value = native_record()
    value["additional_observation_lost"] = True
    result = subprocess.CompletedProcess([], 2, b"", encoded(value))
    capture.run(lambda *_a, **_k: result, ("runtime", "resident-client", "--stdin", "state"))
    capture.restored, capture.test_outcome = True, "failed"
    document = capture.document()
    assert document["native_observation_lost"] is True
    assert document["observation_complete"] is False
    assert capture.rows[-1]["native_failure"] == value


@pytest.mark.parametrize("raises", [False, True])
def test_exact_subprocess_forwarding_despite_capture_failure(raises: bool) -> None:
    capture = Capture("runtime", "state")
    argv = ("runtime", "resident-client", "--stdin", "state")
    payload = b"private original bytes"
    error = RuntimeError("original private error")
    result = subprocess.CompletedProcess(argv, 7, b"original stdout", b"original stderr")
    calls = []

    def original(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        if raises:
            raise error
        return result

    def bad_capture(row: dict[str, Any]) -> None:
        raise RuntimeError("capture failure")

    capture.append = bad_capture
    if raises:
        with pytest.raises(RuntimeError) as caught:
            capture.run(original, argv, input=payload, check=False, capture_output=True, timeout=8)
        assert caught.value is error
    else:
        assert capture.run(original, argv, input=payload, check=False, capture_output=True, timeout=8) is result
    assert len(calls) == 1 and calls[0][0][0] is argv and calls[0][1]["input"] is payload
    assert calls[0][1] == {"input": payload, "check": False, "capture_output": True, "timeout": 8}
    assert capture.faults == 2


def test_nonowned_command_forwards_without_capture() -> None:
    capture = Capture("runtime", "state")
    result = object()
    assert capture.run(lambda *_a, **_k: result, ("runtime", "resident-client", "--stdin", "other")) is result
    assert capture.rows == [] and capture.faults == 0


def test_state_projection_rejects_bool_and_never_formats_unknown_values() -> None:
    class Hostile:
        def __str__(self) -> str:
            raise AssertionError("must not format")

    capture = Capture("runtime", "state")
    for value in (True, Hostile(), -1, 2**32):
        capture.safe(
            lambda value=value: capture.observe_state({"generation": 1, "process_id": 123, "owner_process_id": value})
        )
    assert capture.faults == 4 and capture.owner is None and capture.rows == []


def test_state_and_kill_observations_preserve_original_objects() -> None:
    capture = Capture("runtime", "state")
    state = {"generation": 42, "process_id": 123, "owner_process_id": 456, "private": "not exported"}
    capture.observe_state(state)
    marker = object()
    calls = []

    def original(*args: Any, **kwargs: Any) -> object:
        calls.append((args, kwargs))
        return marker

    assert capture.kill(original, 456, signal.SIGTERM) is marker
    error = ProcessLookupError("private")

    def gone(*_args: Any) -> None:
        raise error

    with pytest.raises(ProcessLookupError) as caught:
        capture.kill(gone, 456, 0)
    assert caught.value is error and calls == [((456, signal.SIGTERM), {})]
    assert capture.rows[-1]["result"] == "not_found"
    assert "private" not in json.dumps(capture.document())


def test_bounded_capture_marks_loss_without_replacing_original() -> None:
    capture = Capture("runtime", "state")
    for _ in range(513):
        capture.append({"kind": "fixture"})
    assert len(capture.rows) == 512 and capture.overflow


def test_actual_module_origin_is_bound_before_attachment() -> None:
    from ci.native_runtime import native_hook_client_support, test_native_hook_client

    plugin.verify_origins(test_native_hook_client, native_hook_client_support)
    for test, support in (
        (SimpleNamespace(__file__=__file__), native_hook_client_support),
        (test_native_hook_client, SimpleNamespace(__file__=__file__)),
    ):
        with pytest.raises(ValueError, match="actual_module_origin"):
            plugin.verify_origins(test, support)


def test_partial_attachment_unwinds_before_original_continues() -> None:
    class RefuseOS:
        def __init__(self) -> None:
            object.__setattr__(self, "os", ModuleType("os_fixture"))
            object.__setattr__(self, "subprocess", subprocess)

        def __setattr__(self, name: str, value: object) -> None:
            if name == "os":
                raise RuntimeError("original setup refusal")
            object.__setattr__(self, name, value)

    test, support = SimpleNamespace(json=json), RefuseOS()
    capture = plugin.attach(test, support, Path("runtime"), Path("state"))
    assert test.json is json and plugin._restore == []
    assert capture.faults == 1 and not capture.restored
    plugin.restore(capture)
    assert not capture.restored and capture.restoration_failed


def test_original_termination_loop_has_no_added_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    from ci.native_runtime import native_hook_client_support as support

    capture = Capture("runtime", "state")
    capture.owner = 456
    calls: list[tuple[int, int]] = []
    clock = [0.0]

    def original_kill(pid: int, sig: int) -> None:
        calls.append((pid, sig))

    def sleep(delay: float) -> None:
        clock[0] += delay

    monkeypatch.setattr(support, "os", SimpleNamespace(kill=lambda *a: capture.kill(original_kill, *a), name="posix"))
    monkeypatch.setattr(support, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep))
    assert support._terminate_process(456) is None
    assert calls[0] == (456, signal.SIGTERM)
    assert len(calls) == 201 and all(row == (456, 0) for row in calls[1:])
    assert len(capture.rows) == len(calls)
    assert all(row["result"] == "returned" for row in capture.rows)


def test_json_alias_preserves_value_and_all_aliases_restore() -> None:
    test, support = SimpleNamespace(json=json), SimpleNamespace(os=__import__("os"), subprocess=subprocess)
    original_os = support.os
    capture = plugin.attach(test, support, Path("runtime"), Path("state"))
    value = test.json.loads('{"generation":42,"process_id":123,"owner_process_id":456}')
    assert value == {"generation": 42, "process_id": 123, "owner_process_id": 456}
    assert capture.owner == 456
    plugin.restore(capture)
    assert test.json is json and support.os is original_os and support.subprocess is subprocess and capture.restored


def test_failed_export_does_not_change_original_outcome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    capture = Capture("runtime", "state")
    capture.test_outcome = "failed"
    monkeypatch.setattr(plugin, "_active", capture)
    monkeypatch.setenv("MAC_RECOVERY_OBSERVATION", str(tmp_path / "absent" / "result.json"))
    hook = plugin.pytest_runtest_protocol(SimpleNamespace(nodeid=plugin.NODE), None)
    next(hook)
    with pytest.raises(StopIteration):
        next(hook)
    assert capture.test_outcome == "failed" and capture.restored
