from __future__ import annotations

import ctypes
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import windows_replaceable_file as reader


class _WindowsOs:
    name = "nt"
    O_BINARY = 0x8000
    O_NOINHERIT = 0x80

    def __getattr__(self, name):
        return getattr(os, name)


class _Api:
    def __init__(self):
        self.handle = 41
        self.attributes = 0
        self.information_success = True
        self.file_type = 1
        self.close_success = True
        self.operations = []

    def CreateFileW(self, *arguments):
        self.operations.append(("open", arguments))
        return self.handle

    def GetFileInformationByHandle(self, handle, pointer):
        self.operations.append(("information", handle))
        information = ctypes.cast(
            pointer, ctypes.POINTER(reader._WindowsByHandleFileInformation),
        ).contents
        information.dwFileAttributes = self.attributes
        return self.information_success

    def GetFileType(self, handle):
        self.operations.append(("type", handle))
        return self.file_type

    def CloseHandle(self, handle):
        self.operations.append(("close", handle))
        return self.close_success


@pytest.fixture
def native_open(monkeypatch):
    api = _Api()
    events = []
    transfers = []
    error = PermissionError(13, "synthetic native failure")
    setattr(error, "winerror", 32)
    monkeypatch.setattr(reader, "os", _WindowsOs())
    monkeypatch.setattr(reader, "sys", SimpleNamespace(audit=lambda *args: events.append(args)))
    monkeypatch.setattr(reader, "_file_api", lambda: api)
    monkeypatch.setattr(reader, "_windows_error", lambda: error)
    monkeypatch.setattr(reader.ctypes, "set_last_error", lambda code: None, raising=False)

    def transfer(handle):
        transfers.append(handle)
        return 73

    monkeypatch.setattr(reader, "_transfer_descriptor", transfer)
    return api, events, transfers, error


def test_read_access_full_sharing_existing_noninheritable_open(native_open):
    api, events, transfers, _error = native_open
    target = Path("synthetic-authority")
    descriptor = reader.open_replaceable_read_descriptor(target, os.O_RDONLY)
    assert descriptor == 73
    assert events == [("open", str(target), None, os.O_RDONLY | 0x80)]
    assert api.operations == [
        ("open", (str(target), 0x80000000, 7, None, 3, 0x00200000, None)),
        ("information", 41), ("type", 41),
    ]
    assert transfers == [41]


def test_text_callback_leaves_single_event_to_fileio(native_open):
    api, events, transfers, _error = native_open
    assert reader._text_opener("synthetic-authority", 0x8080) == 73
    assert events == []
    assert transfers == [41]
    assert ("close", 41) not in api.operations


@pytest.mark.parametrize(
    "flags",
    [os.O_WRONLY, os.O_RDWR, os.O_CREAT, os.O_TRUNC, os.O_APPEND, 0x40, 0x4000],
    ids=["write", "read_write", "create", "truncate", "append", "delete_on_close", "text_mode"],
)
def test_unsafe_flags_fail_before_audit_or_open(native_open, flags):
    api, events, transfers, _error = native_open
    with pytest.raises(ValueError, match="must_be_read_only"):
        reader.open_replaceable_read_descriptor("synthetic-authority", flags)
    assert api.operations == events == transfers == []


@pytest.mark.parametrize("name", ["a\0b", "x" * 32768], ids=["nul", "windows_path_limit"])
def test_invalid_path_never_reaches_native_open(native_open, name):
    api, events, transfers, _error = native_open
    with pytest.raises(ValueError):
        reader.open_replaceable_read_descriptor(name, os.O_RDONLY)
    assert api.operations == events == transfers == []


def test_audit_refusal_propagates_same_object_without_open(native_open, monkeypatch):
    api, _events, transfers, _error = native_open
    refusal = RuntimeError("synthetic audit refusal")

    def refuse(*_arguments):
        raise refusal

    monkeypatch.setattr(reader, "sys", SimpleNamespace(audit=refuse))
    with pytest.raises(RuntimeError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is refusal
    assert api.operations == transfers == []


@pytest.mark.parametrize("handle", [None, ctypes.c_void_p(-1).value])
def test_original_open_error_is_not_wrapped_or_closed(native_open, handle):
    api, _events, transfers, error = native_open
    api.handle = handle
    with pytest.raises(PermissionError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is error
    assert getattr(error, "winerror") == 32
    assert len(api.operations) == 1
    assert transfers == []


def test_information_error_is_preserved_and_owned_handle_closed(native_open):
    api, _events, transfers, error = native_open
    api.information_success = False
    with pytest.raises(PermissionError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is error
    assert api.operations[-1] == ("close", 41)
    assert transfers == []


@pytest.mark.parametrize("attributes", [0x10, 0x400, 0x410], ids=["directory", "reparse", "both"])
def test_actual_handle_metadata_rejects_nonregular(native_open, attributes):
    api, _events, transfers, _error = native_open
    api.attributes = attributes
    with pytest.raises(OSError, match="not_regular"):
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert api.operations[-1] == ("close", 41)
    assert transfers == []


@pytest.mark.parametrize("file_type", [2, 3], ids=["character", "pipe"])
def test_nondisk_handle_is_not_transferred(native_open, file_type):
    api, _events, transfers, _error = native_open
    api.file_type = file_type
    with pytest.raises(OSError, match="not_disk"):
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert api.operations[-1] == ("close", 41)
    assert transfers == []


def test_file_type_error_retains_actual_error_and_clears_stale_code(native_open, monkeypatch):
    api, _events, transfers, error = native_open
    cleared = []
    monkeypatch.setattr(reader.ctypes, "set_last_error", cleared.append)
    api.file_type = 0
    with pytest.raises(PermissionError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert cleared == [0]
    assert caught.value is error
    assert api.operations[-1] == ("close", 41)
    assert transfers == []


def test_unknown_file_type_without_os_error_remains_rejected(native_open):
    api, _events, transfers, error = native_open
    api.file_type = 0
    setattr(error, "winerror", 0)
    with pytest.raises(OSError, match="not_disk"):
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert api.operations[-1] == ("close", 41)
    assert transfers == []


def test_descriptor_transfer_failure_keeps_original_error_and_closes(native_open, monkeypatch):
    api, _events, _transfers, _error = native_open
    failure = OSError("synthetic transfer failure")

    def transfer(_handle):
        raise failure

    monkeypatch.setattr(reader, "_transfer_descriptor", transfer)
    with pytest.raises(OSError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is failure
    assert api.operations.count(("close", 41)) == 1


def test_secondary_close_failure_does_not_replace_original_error(native_open):
    api, _events, transfers, error = native_open
    api.information_success = False
    api.close_success = False
    with pytest.raises(PermissionError) as caught:
        reader.open_replaceable_read_descriptor("synthetic-authority", os.O_RDONLY)
    assert caught.value is error
    assert error.__notes__ == ["windows_replaceable_read_close_failed"]
    assert api.operations.count(("close", 41)) == 1
    assert transfers == []


def test_text_wrapper_preserves_utf8_newlines_and_closes(tmp_path, monkeypatch):
    target = tmp_path / "synthetic-authority"
    target.write_bytes("first\r\nsecond\né".encode("utf-8"))
    descriptors = []

    def opener(path, flags):
        descriptor = os.open(path, flags)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(reader, "_text_opener", opener)
    assert reader.read_replaceable_text(target) == "first\nsecond\né"
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_text_decode_failure_still_closes_descriptor(tmp_path, monkeypatch):
    target = tmp_path / "synthetic-authority"
    target.write_bytes(b"\xff")
    descriptors = []

    def opener(path, flags):
        descriptor = os.open(path, flags)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(reader, "_text_opener", opener)
    with pytest.raises(UnicodeDecodeError):
        reader.read_replaceable_text(target)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
