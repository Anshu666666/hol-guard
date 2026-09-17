"""FFI setup is reusable; every handle and security observation remains fresh."""

from __future__ import annotations

import ctypes
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as snapshot
from codex_plugin_scanner.guard import native_policy_snapshot_windows_io as windows_io
from codex_plugin_scanner.guard import native_policy_snapshot_windows_support as support


@pytest.fixture(autouse=True)
def isolated_definitions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(support, "_cached_windows_dll_context", None)
    monkeypatch.setattr(support, "_WINDOWS_DLLS", {})
    monkeypatch.setattr(support, "_cached_windows_file_information_type", None)
    monkeypatch.setattr(support, "_cached_windows_security_attributes_type", None)
    monkeypatch.setattr(windows_io, "_cached_windows_open_functions", None)


def test_fixed_libraries_load_once_without_caching_unbounded_names(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, bool]] = []

    def load(name: str, *, use_last_error: bool) -> object:
        calls.append((name, use_last_error))
        return object()

    monkeypatch.setattr(ctypes, "WinDLL", load, raising=False)
    for name in ("kernel32", "advapi32"):
        first = support._windows_dll(name)
        assert all(support._windows_dll(name) is first for _ in range(100))
    assert calls == [("kernel32", True), ("advapi32", True)]
    assert support._windows_dll("other") is not support._windows_dll("other")
    assert set(support._WINDOWS_DLLS) == {"kernel32", "advapi32"}


def test_concurrent_first_use_shares_one_dll_and_layout(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    start = threading.Barrier(12)

    def load(name: str, *, use_last_error: bool) -> object:
        assert use_last_error
        calls.append(name)
        return object()

    def acquire(_index: int) -> tuple[Any, Any, Any]:
        start.wait(timeout=10)
        return (
            support._windows_dll("kernel32"),
            support._windows_file_information_type(),
            support._windows_security_attributes_type(),
        )

    monkeypatch.setattr(ctypes, "WinDLL", load, raising=False)
    with ThreadPoolExecutor(max_workers=12) as executor:
        definitions = list(executor.map(acquire, range(12)))
    assert calls == ["kernel32"]
    assert all(all(left is right for left, right in zip(row, definitions[0], strict=True)) for row in definitions)
    for layout in definitions[0][1:]:
        assert layout() is not layout()


def test_failed_or_removed_loader_never_reuses_success(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def load(_name: str, *, use_last_error: bool) -> object:
        nonlocal calls
        assert use_last_error
        calls += 1
        if calls == 1:
            raise OSError("synthetic load failure")
        return object()

    monkeypatch.setattr(ctypes, "WinDLL", load, raising=False)
    with pytest.raises(snapshot.NativePolicySnapshotError, match="acl_unavailable"):
        support._windows_dll("kernel32")
    assert support._WINDOWS_DLLS == {}
    assert support._windows_dll("kernel32") is support._windows_dll("kernel32")
    assert calls == 2
    monkeypatch.setattr(ctypes, "WinDLL", None)
    with pytest.raises(snapshot.NativePolicySnapshotError, match="acl_unavailable"):
        support._windows_dll("kernel32")


def test_changed_loader_or_process_rebuilds_definitions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: object(), raising=False)
    monkeypatch.setattr(support.os, "getpid", lambda: 101)
    first = support._windows_dll("kernel32")
    monkeypatch.setattr(support.os, "getpid", lambda: 102)
    second = support._windows_dll("kernel32")
    assert first is not second
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: object())
    assert support._windows_dll("kernel32") is not second


def test_loader_replacement_uses_identity_even_when_callables_compare_equal(monkeypatch: pytest.MonkeyPatch) -> None:
    class EqualLoader:
        def __eq__(self, _other: object) -> bool:
            return True

        def __call__(self, _name: str, *, use_last_error: bool) -> object:
            assert use_last_error
            return object()

    monkeypatch.setattr(ctypes, "WinDLL", EqualLoader(), raising=False)
    first = support._windows_dll("kernel32")
    monkeypatch.setattr(ctypes, "WinDLL", EqualLoader())
    assert support._windows_dll("kernel32") is not first


class _Function:
    def __init__(self, callback: Any) -> None:
        self.callback = callback
        self.assignments = 0

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"argtypes", "restype"}:
            self.assignments += 1
        object.__setattr__(self, name, value)

    def __call__(self, *args: Any) -> Any:
        return self.callback(*args)


def _kernel() -> SimpleNamespace:
    return SimpleNamespace(
        CreateFileW=_Function(lambda *_args: 71),
        CloseHandle=_Function(lambda _handle: 1),
        GetFileInformationByHandle=_Function(lambda *_args: 1),
        GetFileType=_Function(lambda _handle: snapshot._WINDOWS_FILE_TYPE_DISK),
    )


def test_open_setup_reuses_signatures_but_honors_replaced_facade_type() -> None:
    kernel = _kernel()
    first = windows_io._windows_configure_open_functions(snapshot, kernel)
    for _ in range(100):
        assert windows_io._windows_configure_open_functions(snapshot, kernel) is first
    assert sum(function.assignments for function in vars(kernel).values()) == 8
    replacement_type = support._build_windows_file_information_type()
    api = SimpleNamespace(_windows_file_information_type=lambda: replacement_type)
    replacement = windows_io._windows_configure_open_functions(api, kernel)
    assert replacement is not first and replacement.information_type is replacement_type
    assert sum(function.assignments for function in vars(kernel).values()) == 16
    assert windows_io._windows_configure_open_functions(api, _kernel()) is not replacement


def test_failed_signature_setup_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    original = windows_io._build_windows_open_functions
    calls = 0

    def build(kernel: Any, information_type: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TypeError("synthetic signature setup failure")
        return original(kernel, information_type)

    monkeypatch.setattr(windows_io, "_build_windows_open_functions", build)
    kernel = _kernel()
    with pytest.raises(TypeError, match="synthetic signature setup failure"):
        windows_io._windows_configure_open_functions(snapshot, kernel)
    assert windows_io._cached_windows_open_functions is None
    successful = windows_io._windows_configure_open_functions(snapshot, kernel)
    assert windows_io._windows_configure_open_functions(snapshot, kernel) is successful
    assert calls == 2


@pytest.mark.parametrize("fault", ["reparse", "not_disk", "stat_failed"])
def test_warm_definitions_do_not_reuse_handle_validation(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    kernel = _kernel()
    opened: list[int] = []
    closed: list[int] = []
    information_instances: list[Any] = []

    def create(*_args: Any) -> int:
        handle = 71 + len(opened)
        opened.append(handle)
        return handle

    def information(handle: int, pointer: Any) -> int:
        record = pointer._obj
        information_instances.append(record)
        record.dwFileAttributes = snapshot._WINDOWS_FILE_ATTRIBUTE_NORMAL
        if handle == 72 and fault == "reparse":
            record.dwFileAttributes |= snapshot._WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        return int(not (handle == 72 and fault == "stat_failed"))

    kernel.CreateFileW.callback = create
    kernel.GetFileInformationByHandle.callback = information
    kernel.CloseHandle.callback = lambda handle: closed.append(handle) or 1
    kernel.GetFileType.callback = lambda handle: (
        0 if handle == 72 and fault == "not_disk" else snapshot._WINDOWS_FILE_TYPE_DISK
    )
    monkeypatch.setattr(snapshot, "_windows_dll", lambda _name: kernel)
    first = windows_io._windows_open_handle(Path("C:/Guard/state.json"), directory=False)
    with pytest.raises(snapshot.NativePolicySnapshotError, match=r"path_(invalid|stat_failed)"):
        windows_io._windows_open_handle(Path("C:/Guard/state.json"), directory=False)
    assert opened == [71, 72] and closed == [72]
    assert information_instances[0] is not information_instances[1]
    snapshot._windows_close_handle(*first[:2])
    assert closed == [72, 71]


def test_warm_definitions_do_not_cache_owner_or_acl_acceptance(monkeypatch: pytest.MonkeyPatch) -> None:
    kernel = _kernel()
    owners: list[str] = []
    verified: list[str] = []
    reads: list[int] = []
    closes: list[int] = []

    def information(_handle: int, pointer: Any) -> int:
        pointer._obj.dwFileAttributes = snapshot._WINDOWS_FILE_ATTRIBUTE_NORMAL
        pointer._obj.nFileSizeLow = 1
        return 1

    def owner() -> str:
        current = f"synthetic-owner-{len(owners)}"
        owners.append(current)
        return current

    def verify(_handle: int, *, owner_sid: str, directory: bool) -> None:
        assert not directory
        verified.append(owner_sid)
        if len(verified) == 2:
            raise snapshot.NativePolicySnapshotError("native_policy_windows_dacl_invalid")

    def read(_handle: int, buffer: Any, _size: int, count: Any, _overlapped: Any) -> int:
        length = int(not reads)
        reads.append(length)
        if length:
            ctypes.memmove(buffer, b"x", length)
        count._obj.value = length
        return 1

    kernel.GetFileInformationByHandle.callback = information
    kernel.CloseHandle.callback = lambda handle: closes.append(handle) or 1
    kernel.ReadFile = _Function(read)
    monkeypatch.setattr(snapshot, "_windows_dll", lambda _name: kernel)
    monkeypatch.setattr(snapshot, "_windows_owner_sid", owner)
    monkeypatch.setattr(snapshot, "_windows_verify_private_dacl", verify)
    path = Path("C:/Guard/state.json")
    assert snapshot._windows_read_snapshot_bytes(path, maximum_bytes=16) == b"x"
    with pytest.raises(snapshot.NativePolicySnapshotError, match="dacl_invalid"):
        snapshot._windows_read_snapshot_bytes(path, maximum_bytes=16)
    assert owners == verified == ["synthetic-owner-0", "synthetic-owner-1"]
    assert reads == [1, 0] and closes == [71, 71]
