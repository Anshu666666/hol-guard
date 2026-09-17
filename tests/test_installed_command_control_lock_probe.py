"""The independent child must reach LockFileEx through a compatible open."""

from __future__ import annotations

import ctypes
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.native_runtime import probe_installed_command_control_lock as probe


class _Function:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


@pytest.mark.parametrize("shared,flags", [(True, 1), (False, 3)])
def test_independent_open_shares_delete_with_retained_creator(monkeypatch, capsys, shared, flags):
    calls = []
    handle = 0x123456789

    def create(path, access, sharing, security, disposition, attributes, template):
        calls.append(("open", path, access, sharing, security, disposition, attributes, template))
        # A current creator requesting DELETE cannot coexist with CRT sharing3.
        return handle if sharing & 4 else ctypes.c_void_p(-1).value

    def lock(opened, selected_flags, reserved, low, high, overlapped):
        calls.append(("lock", opened, selected_flags, reserved, low, high))
        return 1

    kernel = SimpleNamespace(
        CreateFileW=_Function(create),
        LockFileEx=_Function(lock),
        CloseHandle=_Function(lambda opened: calls.append(("close", opened)) or 1),
    )
    monkeypatch.setattr(probe.ctypes, "WinDLL", lambda *args, **kwargs: kernel, raising=False)
    assert probe._raw_child(Path("fixture.lock"), shared) == 0
    assert calls == [
        ("open", "fixture.lock", 0xC0000000, 7, None, 3, 0x00200080, None),
        ("lock", handle, flags, 0, 0xFFFFFFFF, 0xFFFFFFFF),
        ("close", handle),
    ]
    assert json.loads(capsys.readouterr().out) == {"stage": "lock", "acquired": True, "win32_error": 0}
    assert kernel.CreateFileW.restype is ctypes.c_void_p


@pytest.mark.parametrize("stage,code", [("open", 32), ("open", 5), ("lock", 33), ("lock", 87)])
def test_child_preserves_fixed_open_or_lock_failure_code(monkeypatch, capsys, stage, code):
    calls = []
    kernel = SimpleNamespace(
        CreateFileW=_Function(lambda *args: ctypes.c_void_p(-1).value if stage == "open" else 123),
        LockFileEx=_Function(lambda *args: calls.append("lock") or 0),
        CloseHandle=_Function(lambda *args: calls.append("close") or 1),
    )
    monkeypatch.setattr(probe.ctypes, "WinDLL", lambda *args, **kwargs: kernel, raising=False)
    monkeypatch.setattr(probe.ctypes, "get_last_error", lambda: code, raising=False)
    assert probe._raw_child(Path("private-fixture.lock"), True) == 0
    assert calls == ([] if stage == "open" else ["lock", "close"])
    assert json.loads(capsys.readouterr().out) == {"stage": stage, "acquired": False, "win32_error": code}


@pytest.mark.parametrize("acquired,code", [(True, 0), (False, 33)])
def test_only_real_lock_result_can_satisfy_lease_or_contention(monkeypatch, acquired, code):
    child = {"stage": "lock", "acquired": acquired, "win32_error": code}
    monkeypatch.setattr(
        probe.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(child).encode(),
            stderr=b"",
        ),
    )
    assert probe._child_result(Path("fixture.lock"), shared=True) is acquired


@pytest.mark.parametrize("stage,code", [("open", 32), ("open", 5), ("lock", 87)])
def test_parent_exposes_only_bounded_stage_and_numeric_error(monkeypatch, stage, code):
    child = {"stage": stage, "acquired": False, "win32_error": code}
    monkeypatch.setattr(
        probe.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(child).encode(),
            stderr=b"",
        ),
    )
    with pytest.raises(RuntimeError, match=f"child_failed:stage={stage}:win32_error={code}"):
        probe._child_result(Path("private-fixture.lock"), shared=True)


@pytest.mark.parametrize(
    "child",
    [
        {"stage": "private text", "acquired": False, "win32_error": 32},
        {"stage": "lock", "acquired": 1, "win32_error": 0},
        {"stage": "lock", "acquired": True, "win32_error": False},
        {"stage": "lock", "acquired": False, "win32_error": -1},
        {"stage": "lock", "acquired": False, "win32_error": 2**32},
        {"stage": "lock", "acquired": True, "win32_error": 0, "path": "private"},
    ],
)
def test_invalid_child_metadata_is_rejected_without_echo(monkeypatch, child):
    monkeypatch.setattr(
        probe.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(child).encode(),
            stderr=b"",
        ),
    )
    with pytest.raises(RuntimeError) as raised:
        probe._child_result(Path("private-fixture.lock"), shared=True)
    assert str(raised.value) == "installed_command_control_lock_child_invalid"
