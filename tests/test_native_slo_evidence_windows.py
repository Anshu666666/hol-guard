from __future__ import annotations

import os
import sys
import types
from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts import native_slo_evidence_public as public
from scripts import native_slo_evidence_windows as windows


def test_public_receipt_renames_the_still_open_exclusive_handle(monkeypatch, tmp_path):
    destination = tmp_path / "receipt.json"
    opened = {}
    events = []

    def create(path, access, sharing, security, disposition, flags, template):
        assert access == 0xC0010000 and sharing == 1 and disposition == 1
        assert flags & 0x00200000  # Never follow a reparse point.
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        opened[descriptor] = Path(path)
        events.append("created")
        return descriptor

    def rename(handle, path, parent_identity):
        os.lseek(handle, 0, os.SEEK_SET)
        assert os.read(handle, 4096) == b'{"status":"archive_failed"}'
        assert opened[handle].exists()
        assert not path.exists()
        events.append("rename-open-handle")
        opened[handle].rename(path)

    @contextmanager
    def ancestry(path):
        yield

    monkeypatch.setattr(public, "_windows_ancestry", ancestry)
    monkeypatch.setattr(public, "_windows_api", lambda: (None, create, os.close))
    monkeypatch.setattr(public, "_rename_public_handle", rename)
    monkeypatch.setattr(os, "O_BINARY", 0, raising=False)
    monkeypatch.setitem(sys.modules, "msvcrt", types.SimpleNamespace(open_osfhandle=lambda handle, flags: handle))
    public._windows_public_write(destination, b'{"status":"archive_failed"}')
    assert events == ["created", "rename-open-handle"]
    assert destination.read_bytes() == b'{"status":"archive_failed"}'
    with pytest.raises(OSError):
        os.fstat(next(iter(opened)))


def test_private_atomic_uses_handle_exclusive_rename_without_destination_repair(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard import native_policy_snapshot_windows_atomic as atomic
    from codex_plugin_scanner.guard import native_policy_snapshot_windows_support as support

    events = []

    @contextmanager
    def descriptor(private):
        yield None, "security", None, "owner"

    @contextmanager
    def ancestry(path):
        yield [("kernel", "parent-handle")]

    def opening(path, **options):
        assert options == {"directory": False, "create_new": True, "descriptor": "security", "rename_source": True}
        return "kernel", "source-handle", None

    api = types.SimpleNamespace(
        _windows_private_descriptor=descriptor,
        _windows_open_handle=opening,
        _windows_verify_private_dacl=lambda handle, **kwargs: events.append(("verify", handle)),
        _windows_close_handle=lambda kernel, handle: events.append(("close", handle)),
    )

    def rename(**options):
        assert options["source_handle"] == "source-handle"
        assert options["replace_existing"] is False
        assert options["parent_handle"] == "parent-handle"
        events.append(("rename", "source-handle"))

    monkeypatch.setattr(windows, "_api", lambda: api)
    monkeypatch.setattr(windows, "hold_directory", ancestry)
    monkeypatch.setattr(
        support, "_windows_write_chunks_and_flush", lambda kernel, handle, data: events.append(("write", handle))
    )
    monkeypatch.setattr(atomic, "_windows_rename_releasing_barrier", rename)
    monkeypatch.setattr(
        atomic,
        "_windows_prepare_replace_destination",
        lambda **kwargs: pytest.fail("existing destination must not be repaired"),
    )
    windows.atomic_private_file(tmp_path / "archive.hge", b"ciphertext")
    assert events == [
        ("verify", "source-handle"),
        ("write", "source-handle"),
        ("rename", "source-handle"),
        ("close", "source-handle"),
    ]


@pytest.mark.skipif(os.name != "nt", reason="requires actual Windows DACL/NT rename ABI")
def test_windows_private_empty_file_and_exclusive_public_receipt(tmp_path):
    from scripts.native_slo_evidence_files import atomic_exclusive, read_file, recover_files

    destination = tmp_path / "new-private-directory"
    recover_files(destination, [("empty.jsonl", b"")])
    assert read_file(destination / "empty.jsonl", 1, private=True) == b""
    output = tmp_path / "cipher.hge"
    atomic_exclusive(output, b"first")
    with pytest.raises((ValueError, OSError)):
        atomic_exclusive(output, b"second")
    assert output.read_bytes() == b"first"
    receipt = tmp_path / "public-receipt.json"
    public.publish_receipt(receipt, b'{"status":"no_observations"}')
    with pytest.raises((ValueError, OSError)):
        public.publish_receipt(receipt, b"replace")
    assert receipt.read_bytes() == b'{"status":"no_observations"}'
