"""Real Windows ABI and mutable-state witnesses for cached FFI definitions."""

from __future__ import annotations

import ctypes
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as snapshot
from codex_plugin_scanner.guard import native_policy_snapshot_windows_support as support
from codex_plugin_scanner.guard.native_command_control_authority_io import read_private_state, write_private_state

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Actual Windows DLL, handle and DACL contract")


def test_shared_windows_library_preserves_thread_local_last_error() -> None:
    from ctypes import wintypes

    kernel = support._windows_dll("kernel32")
    kernel.SetLastError.argtypes = [wintypes.DWORD]
    kernel.SetLastError.restype = None
    kernel.GetLastError.argtypes = []
    kernel.GetLastError.restype = wintypes.DWORD
    barrier = threading.Barrier(8)

    def check(index: int) -> None:
        assert support._windows_dll("kernel32") is kernel
        code = 500 + index
        kernel.SetLastError(code)
        barrier.wait(timeout=15)
        assert ctypes.get_last_error() == code
        assert kernel.GetLastError() == code

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(check, range(8)))


def test_warm_windows_definitions_read_changed_authority_and_reject_new_size(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    name = "cache-witness.json"
    first = b'{"revision":1}'
    second = b'{"revision":2}'
    write_private_state(home, name, first, 4096)
    assert read_private_state(home, name, 4096) == first
    kernel = support._windows_dll("kernel32")
    information_type = support._windows_file_information_type()
    write_private_state(home, name, second, 4096)
    assert read_private_state(home, name, 4096) == second

    def read(_index: int) -> None:
        assert support._windows_dll("kernel32") is kernel
        assert support._windows_file_information_type() is information_type
        assert read_private_state(home, name, 4096) == second

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(read, range(8)))
    path = home / "native-runtime" / name
    path.write_bytes(b"x" * 4097)
    with pytest.raises(snapshot.NativePolicySnapshotError, match="cache_invalid"):
        read_private_state(home, name, 4096)
    write_private_state(home, name, second, 4096)
    assert read_private_state(home, name, 4096) == second
