"""Finite Windows diagnostics preserve the original failing operations."""

from __future__ import annotations

import ctypes
import json
import struct
import subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.native_slo_contract import assert_privacy_safe

from . import windows_failure_witness as witness


def descriptor(*, inherited=True, ace_count=1):
    owner = b"\x01\x01\x00\x00\x00\x00\x00\x05" + struct.pack("<L", 18)
    group = b"\x01\x01\x00\x00\x00\x00\x00\x05" + struct.pack("<L", 19)
    ace = struct.pack("<BBHL", 0, 0x10 if inherited else 0, 20, 0x1F01FF) + owner
    acl = struct.pack("<BBHHH", 2, 0, 8 + ace_count * len(ace), ace_count, 0) + ace * ace_count
    return struct.pack("<BBHLLLL", 1, 0, 0x8004 if inherited else 0x9004, 20, 32, 0, 44) + owner + group + acl


def snapshot(raw):
    return (7, 8, 9), witness._descriptor_components(raw), b"private synthetic contents"


@pytest.mark.parametrize("fault", [None, "status", "informational", "short", "oversized", "unavailable"])
def test_nt_query_is_one_bounded_read_and_closes_on_all_outcomes(monkeypatch, fault):
    from ctypes import wintypes

    calls, raw = [], descriptor()

    class Query:
        def __call__(self, handle, flags, buffer, capacity, needed):
            calls.append((handle, flags, capacity))
            size = {"short": 19, "oversized": 65_537}.get(fault, len(raw))
            ctypes.cast(needed, ctypes.POINTER(wintypes.ULONG))[0] = size
            ctypes.memmove(buffer, raw, len(raw))
            return {"status": -1073741790, "informational": 0x40000000}.get(fault, 0)

    query = Query()

    def opened(path, **kwargs):
        assert path == Path("private") and kwargs == {"directory": True}
        calls.append("open")
        return "kernel", 17, object()

    def library(name):
        assert name == "ntdll"
        if fault == "unavailable":
            raise OSError("private error")
        return SimpleNamespace(NtQuerySecurityObject=query)

    monkeypatch.setattr(witness.api, "_windows_open_handle", opened)
    monkeypatch.setattr(witness.api, "_windows_dll", library)
    monkeypatch.setattr(witness.api, "_windows_close_handle", lambda kernel, handle: calls.append((kernel, handle)))
    if fault is None:
        assert witness._nt_descriptor(Path("private"), directory=True) == raw
    else:
        with pytest.raises((witness._NtQueryError, ValueError, OSError)):
            witness._nt_descriptor(Path("private"), directory=True)
    assert calls == ["open", *(([(17, 7, 65_536)]) if fault != "unavailable" else []), ("kernel", 17)]
    if fault != "unavailable":
        assert query.restype is ctypes.c_int32
        assert query.argtypes == [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
        ]


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"x" * 65_537,
        bytes(20),
        descriptor()[:25],
        descriptor()[:16] + struct.pack("<L", 65_535) + descriptor()[20:],
    ],
)
def test_invalid_self_relative_descriptors_are_explicit(raw):
    with pytest.raises(ValueError):
        witness._descriptor_components(raw)


def test_stages_distinguish_get_representation_from_stored_descriptor(monkeypatch, capsys):
    legacy, changed = descriptor(), descriptor(inherited=False)
    state = {"raw": legacy, "get": legacy}
    monkeypatch.setattr(witness, "_nt_descriptor", lambda *_args, **_kwargs: state["raw"])
    before = [snapshot(legacy)] * 3
    observer = witness.WindowsParentWitness(
        [(Path(str(i)), i == 1) for i in range(3)], before, lambda *_a, **_k: snapshot(state["get"])
    )
    failure = AssertionError("original private assertion")
    with pytest.raises(AssertionError) as caught, observer.failure_only():
        observer.capture("before_key_verification")
        observer.capture("after_key_verification")
        state["get"] = changed
        observer.capture("after_manager")
        state["raw"] = changed
        observer.capture("after_discovery_binding")
        raise failure
    assert caught.value is failure
    report = json.loads(capsys.readouterr().err)
    assert report["complete"] is True and len(report["rows"]) == 12
    after_manager, after_binding = report["rows"][6], report["rows"][9]
    assert after_manager["descriptor_equal_before"] is True
    assert after_manager["nt_before_matches_get"] is after_manager["nt_after_matches_get"] is False
    assert after_manager["get_security_info"]["control"] == 0x9004
    assert after_manager["nt_before_get"]["control"] == 0x8004
    assert after_manager["get_security_info"]["ace_flags"] == [0]
    assert after_manager["get_security_info"]["owner_equal_before"] is True
    assert after_manager["get_security_info"]["group_equal_before"] is True
    assert after_manager["get_security_info"]["dacl_equal_before"] is False
    assert after_manager["get_security_info"]["bytes_equal_before"] is True
    assert report["rows"][7]["get_security_info"]["bytes_equal_before"] is None
    assert after_manager["nt_before_get"]["ace_flags"] == [0x10]
    assert after_binding["descriptor_equal_before"] is False and after_binding["nt_after_matches_get"] is True
    assert all(row["descriptor_equal_around_get"] is True for row in report["rows"])
    assert all(row["get_security_info"]["identity_equal_before"] is True for row in report["rows"])
    assert "private" not in json.dumps(report) and len(json.dumps(report)) < 20_000
    assert assert_privacy_safe(report) == report


def test_query_missingness_over_cap_aces_and_extra_stages_are_not_zero(monkeypatch):
    raw = descriptor(ace_count=33)
    monkeypatch.setattr(witness, "_nt_descriptor", lambda *_a, **_k: raw)
    observer = witness.WindowsParentWitness(
        [(Path(str(i)), False) for i in range(3)], [snapshot(raw)] * 3, lambda *_a, **_k: snapshot(raw)
    )
    for stage in witness._STAGES:
        observer.capture(stage)
    observer.capture("private fifth stage")
    report = observer.report()
    assert report["complete"] is False and len(report["rows"]) == 12
    assert report["rows"][0]["nt_before_get"]["ace_count"] is None
    assert report["rows"][0]["nt_before_get"]["ace_flags"] is None

    def unavailable(*_args, **_kwargs):
        raise witness._NtQueryError(-1073741790)

    monkeypatch.setattr(witness, "_nt_descriptor", unavailable)
    missing = witness.WindowsParentWitness([(Path(str(i)), False) for i in range(3)], [snapshot(raw)] * 3, unavailable)
    missing.capture(witness._STAGES[0])
    row = missing.report()["rows"][0]
    assert row["nt_before_get"]["ntstatus"] == -1073741790
    assert row["nt_before_get"]["control"] is row["descriptor_equal_before"] is None
    assert row["get_security_info"]["observed"] is False
    assert row["get_security_info"]["security_equal_before"] is None


def test_get_read_side_effect_is_separately_observable(monkeypatch):
    legacy, changed = descriptor(), descriptor(inherited=False)
    state = [legacy]
    monkeypatch.setattr(witness, "_nt_descriptor", lambda *_a, **_k: state[0])

    def reader(*_args, **_kwargs):
        state[0] = changed
        return snapshot(changed)

    observer = witness.WindowsParentWitness([(Path(str(i)), False) for i in range(3)], [snapshot(legacy)] * 3, reader)
    observer.capture(witness._STAGES[0])
    row = observer.report()["rows"][0]
    assert row["descriptor_equal_around_get"] is False
    assert row["nt_before_matches_get"] is False and row["nt_after_matches_get"] is True


def test_observer_failure_preserves_original_and_success_is_quiet(monkeypatch, capsys):
    observer = witness.WindowsParentWitness([], [], lambda *_a: None)
    with observer.failure_only(), witness.retry_status_witness({"running": True}):
        pass
    assert capsys.readouterr() == ("", "")

    def fail(_report):
        raise KeyboardInterrupt("observer failed")

    monkeypatch.setattr(witness, "_emit", fail)
    for context in [observer.failure_only(), witness.retry_status_witness({"running": False})]:
        original = AssertionError("original")
        with pytest.raises(AssertionError) as caught, context:
            raise original
        assert caught.value is original


def test_retry_status_projection_is_closed_and_preserves_missingness():
    status = {
        "running": False,
        "pid": 42,
        "port": 1234,
        "url": "private token",
        "guard_home": "private path",
        "daemon_version": "3.0.1",
        "cli_version": "3.0.1",
        "last_lifecycle_event": {"event": "stopped", "reason": "requested_shutdown", "pid": 42, "session_id": "secret"},
    }
    before = json.dumps(status)
    result = witness.retry_status_projection(status)
    assert result["running"] is False and result["lifecycle_event"] == "stopped"
    assert result["lifecycle_reason"] == "requested_shutdown" and result["lifecycle_pid_matches_status"] is True
    assert result["daemon_version_matches_cli"] is True and result["listener_present"] is True
    assert json.dumps(status) == before and assert_privacy_safe(result) == result
    assert all(value not in json.dumps(result) for value in ["secret", "private path", "private token", "3.0.1"])
    missing = witness.retry_status_projection(
        {"running": "secret", "pid": True, "last_lifecycle_event": {"event": "secret", "reason": "secret"}}
    )
    assert missing["running"] is missing["lifecycle_pid_matches_status"] is None
    assert missing["pid_valid"] is False and missing["lifecycle_event"] == missing["lifecycle_reason"] == "other"


def test_real_frozen_retry_assertion_uses_original_status_and_stops_without_retry(tmp_path, monkeypatch, capsys):
    from . import test_frozen_windows_daemon_bootstrap as gate

    executable = tmp_path / "fixture.exe"
    executable.touch()
    monkeypatch.setenv("HOL_GUARD_FROZEN_TEST_EXECUTABLE", str(executable))
    outputs = iter(
        [
            {"schema": "guard-desktop-bootstrap.v1"},
            {"running": True, "pid": 123},
            {"running": False, "stopped": True, "pid": 123},
            {"schema": "guard-desktop-bootstrap.v1"},
            {
                "running": False,
                "pid": 456,
                "url": "private token",
                "last_lifecycle_event": {"event": "stopped", "reason": "requested_shutdown"},
            },
            {"running": False, "stopped": False},
        ]
    )
    calls = []

    def run(_executable, args, *, env):
        calls.append(args[:2])
        return subprocess.CompletedProcess(args, 0, json.dumps(next(outputs)), "")

    monkeypatch.setattr(gate, "_run_core", run)
    monkeypatch.setattr(gate, "_assert_windows_process_stopped", lambda pid: None)
    with pytest.raises(AssertionError):
        gate.test_packaged_windows_core_bootstrap_retry_and_repair(tmp_path)
    assert calls == [
        ["desktop", "bootstrap"],
        ["daemon", "status"],
        ["daemon", "stop"],
        ["desktop", "bootstrap"],
        ["daemon", "status"],
        ["daemon", "stop"],
    ]
    report = json.loads(capsys.readouterr().err)
    assert report["running"] is False and report["lifecycle_event"] == "stopped"
    assert "private" not in json.dumps(report)


def test_real_parent_assertion_keeps_original_product_calls_and_stopping_point(tmp_path, monkeypatch, capsys):
    from . import test_daemon_parent_windows as gate

    legacy, changed = descriptor(), descriptor(inherited=False)
    state, calls = [legacy], []
    monkeypatch.setattr(witness, "_nt_descriptor", lambda *_a, **_k: state[0])
    monkeypatch.setattr(gate, "_windows_child_snapshot", lambda *_a, **_k: snapshot(state[0]))
    monkeypatch.setattr(
        gate, "_windows_native_child_snapshot", lambda *_a, **_k: ((7, 8, 9), state[0], b"private synthetic contents")
    )

    def verify(path):
        calls.append("verify")
        raise gate.api.NativePolicySnapshotError("native_policy_windows_acl_not_private")

    def manager(path):
        calls.append("manager")
        state[0] = changed

    @contextmanager
    def binding(*_args, **_kwargs):
        calls.append("binding")
        yield

    monkeypatch.setattr(gate.api, "_windows_verify_private_file", verify)
    monkeypatch.setattr(gate.manager, "_ensure_private_directory", manager)
    monkeypatch.setattr(gate.discovery_windows, "_directory_binding", binding)
    monkeypatch.setattr(gate.discovery, "ensure_daemon_discovery_key", lambda *_a: pytest.fail("past original stop"))
    with pytest.raises(AssertionError):
        gate.test_windows_parent_provisioning_preserves_inherited_key_and_nested_child(tmp_path)
    assert calls == ["verify", "manager", "binding"]
    report = json.loads(capsys.readouterr().err)
    assert report["stages_observed"] == 4 and len(report["rows"]) == 12
    assert report["rows"][3]["descriptor_equal_before"] is True
    assert report["rows"][6]["descriptor_equal_before"] is False
