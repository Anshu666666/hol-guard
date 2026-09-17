"""Native preservation comparisons retain every descriptor byte and strict keys."""

from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from . import test_daemon_parent_windows as gate
from . import windows_failure_witness as witness
from .test_windows_failure_witness import descriptor, snapshot


@pytest.mark.parametrize(
    ("fault", "directory"),
    [(None, False), (None, True), ("query", False), ("format", False), ("identity", False), ("payload", False)],
)
def test_native_snapshot_retains_complete_bytes_and_closes_the_read_handle(monkeypatch, fault, directory):
    calls = []
    # Bytes outside the parsed components must survive unchanged too.
    raw = descriptor() + b"\x00\x01\x00\x02"
    information = SimpleNamespace(dwVolumeSerialNumber=7, nFileIndexHigh=8, nFileIndexLow=9)

    def read_bytes():
        calls.append("payload")
        assert directory is False
        if fault == "payload":
            raise OSError("synthetic read failure")
        return b"unchanged payload"

    path = SimpleNamespace(read_bytes=read_bytes)

    def opened(candidate, **kwargs):
        assert candidate is path and kwargs == {"directory": directory}
        calls.append("open")
        return "kernel", 17, object() if fault == "identity" else information

    def query(handle):
        assert handle == 17
        calls.append("query")
        if fault == "query":
            raise witness._NtQueryError(-1073741790)
        return bytes(20) if fault == "format" else raw

    monkeypatch.setattr(gate.api, "_windows_open_handle", opened)
    monkeypatch.setattr(gate, "_nt_descriptor_for_handle", query)
    monkeypatch.setattr(gate.api, "_windows_close_handle", lambda kernel, handle: calls.append((kernel, handle)))
    if fault is None:
        assert gate._windows_native_child_snapshot(path, directory=directory) == (
            (7, 8, 9),
            raw,
            None if directory else b"unchanged payload",
        )
    else:
        with pytest.raises((witness._NtQueryError, ValueError, AssertionError, OSError)):
            gate._windows_native_child_snapshot(path, directory=directory)
    assert calls == [
        "open",
        "query",
        *(["payload"] if not directory and fault in {None, "payload"} else []),
        ("kernel", 17),
    ]


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "control",
        "ace_flags",
        "access_mask",
        "owner",
        "group",
        "reserved",
        "padding",
        "identity",
        "payload",
        "key_load",
    ],
)
def test_real_parent_gate_distinguishes_get_projection_from_native_or_payload_mutation(
    tmp_path, monkeypatch, capsys, fault
):
    raw = descriptor() + b"\x00\x00"
    state = {"raw": raw, "get": descriptor(), "identity": (7, 8, 9), "payload": b"unchanged payload"}
    calls, get_controls = [], []

    def native_snapshot(_path, *, directory=False):
        return state["identity"], state["raw"], None if directory else state["payload"]

    def get_snapshot(*_args, **_kwargs):
        value = snapshot(state["get"])
        get_controls.append(value[1][3])
        return value

    monkeypatch.setattr(witness, "_nt_descriptor", lambda *_a, **_k: state["raw"])
    monkeypatch.setattr(gate, "_windows_native_child_snapshot", native_snapshot)
    monkeypatch.setattr(gate, "_windows_child_snapshot", get_snapshot)

    def verify(_path):
        calls.append("verify")
        raise gate.api.NativePolicySnapshotError("native_policy_windows_acl_not_private")

    def manager(_path):
        calls.append("manager")
        state["get"] = descriptor(inherited=False)
        # Distinguish full byte equality from a masked/control-free projection.
        offsets = {
            "control": 3,
            "ace_flags": 53,
            "access_mask": 56,
            "owner": 28,
            "group": 40,
            "reserved": 1,
            "padding": -1,
        }
        if fault in offsets:
            changed = bytearray(raw)
            changed[offsets[fault]] ^= 0x10 if fault in {"control", "ace_flags"} else 1
            state["raw"] = bytes(changed)
        elif fault == "identity":
            state["identity"] = (7, 8, 10)
        elif fault == "payload":
            state["payload"] = b"changed payload"

    @contextmanager
    def binding(*_args, **_kwargs):
        calls.append("binding")
        yield

    def load_key(_parent):
        calls.append("key")
        if fault == "key_load":
            state["raw"] = descriptor(inherited=False)
        return "19" * 32

    monkeypatch.setattr(gate.api, "_windows_verify_private_file", verify)
    monkeypatch.setattr(gate.manager, "_ensure_private_directory", manager)
    monkeypatch.setattr(gate.discovery_windows, "_directory_binding", binding)
    monkeypatch.setattr(gate.discovery, "ensure_daemon_discovery_key", load_key)
    if fault is None:
        gate.test_windows_parent_provisioning_preserves_inherited_key_and_nested_child(tmp_path)
        assert calls == ["verify", "manager", "binding", "key", "verify"]
        assert capsys.readouterr().err == ""
    else:
        with pytest.raises(AssertionError):
            gate.test_windows_parent_provisioning_preserves_inherited_key_and_nested_child(tmp_path)
        assert calls == ["verify", "manager", "binding", *(["key"] if fault == "key_load" else [])]
        report = json.loads(capsys.readouterr().err)
        assert report["complete"] is True and len(report["rows"]) == 12
    assert 0x8004 in get_controls and 0x9004 in get_controls


def test_real_parent_gate_still_rejects_newly_admitted_legacy_key(tmp_path, monkeypatch):
    raw, calls = descriptor(), []
    monkeypatch.setattr(witness, "_nt_descriptor", lambda *_a, **_k: raw)
    monkeypatch.setattr(gate, "_windows_child_snapshot", lambda *_a, **_k: snapshot(raw))
    monkeypatch.setattr(gate, "_windows_native_child_snapshot", lambda *_a, **_k: ((7, 8, 9), raw, b"unchanged"))

    def verify(_path):
        calls.append("verify")
        if len(calls) == 1:
            raise gate.api.NativePolicySnapshotError("native_policy_windows_acl_not_private")

    @contextmanager
    def binding(*_args, **_kwargs):
        yield

    monkeypatch.setattr(gate.api, "_windows_verify_private_file", verify)
    monkeypatch.setattr(gate.manager, "_ensure_private_directory", lambda *_a: None)
    monkeypatch.setattr(gate.discovery_windows, "_directory_binding", binding)
    monkeypatch.setattr(gate.discovery, "ensure_daemon_discovery_key", lambda *_a: "19" * 32)
    with pytest.raises(pytest.fail.Exception, match="DID NOT RAISE"):
        gate.test_windows_parent_provisioning_preserves_inherited_key_and_nested_child(tmp_path)
    assert calls == ["verify", "verify"]
