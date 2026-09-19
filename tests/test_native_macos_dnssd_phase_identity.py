"""Real file replacement and bounded Mach-O admission controls, without executing a binary."""

from __future__ import annotations

import hashlib
import os
import struct

import pytest

from scripts.ci import native_macos_dnssd_phase_identity as identity


def image(filetype=6, cpu=16777228):
    return struct.pack("<IiiIIIII", 0xFEEDFACF, cpu, 0, filetype, 1, 24, 0, 0) + struct.pack(
        "<II16s", 0x1B, 24, b"\x01" * 16
    )


@pytest.mark.parametrize("filetype", (2, 6))
@pytest.mark.parametrize("cpu", (16777228, 16777223))
def test_one_regular_file_binds_complete_bytes_and_actual_macho_type(tmp_path, filetype, cpu):
    data = image(filetype, cpu) + b"complete binary body"
    path = tmp_path / "binary"
    path.write_bytes(data)
    observed = identity.binary_identity(path, filetype)
    assert observed == {
        "filetype": filetype, "cpu_type": cpu, "cpu_subtype": 0, "uuid": "01" * 16,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


@pytest.mark.parametrize("actual,expected", [(2, 6), (6, 2), (6, True), (6, 3)])
def test_executable_dylib_and_invalid_requested_types_are_distinct(actual, expected):
    with pytest.raises(ValueError):
        identity.parse_identity(image(actual), expected)


@pytest.mark.parametrize("offset,value", [
    (0, 0), (4, 7), (12, 2), (16, 0), (16, 1025), (16, 2), (20, 16),
    (32, 0xC), (36, 0), (36, 12), (36, 16), (36, 32),
])
def test_malformed_headers_and_load_commands_are_refused(offset, value):
    data = bytearray(image())
    struct.pack_into("<I", data, offset, value)
    with pytest.raises(ValueError):
        identity.parse_identity(bytes(data), 6)


def test_short_oversized_and_duplicate_uuid_inputs_are_refused():
    duplicate = bytearray(image())
    struct.pack_into("<II", duplicate, 16, 2, 48)
    duplicate += image()[32:]
    for data in (b"", image()[:31], bytes(duplicate), image() + b"x" * identity.COMMAND_LIMIT):
        with pytest.raises(ValueError):
            identity.parse_identity(data, 6)


def test_symlink_directory_and_size_limit_are_refused_without_loading(tmp_path, monkeypatch):
    path = tmp_path / "binary"
    path.write_bytes(image())
    link = tmp_path / "link"
    link.symlink_to(path)
    for candidate in (link, tmp_path):
        with pytest.raises((OSError, ValueError)):
            identity.binary_identity(candidate, 6)
    monkeypatch.setattr(identity, "MAXIMUM", len(image()) - 1)
    with pytest.raises(ValueError, match="size"):
        identity.binary_identity(path, 6)


@pytest.mark.parametrize("mutation", ("replacement", "content_restore"))
def test_actual_file_change_during_held_descriptor_read_is_refused(tmp_path, monkeypatch, mutation):
    path = tmp_path / "binary"
    original = image() + b"same final body"
    path.write_bytes(original)
    before = path.stat()
    actual_fstat = identity.os.fstat
    calls = 0

    def changing(descriptor):
        nonlocal calls
        calls += 1
        if calls == 2:
            if mutation == "replacement":
                replacement = tmp_path / "replacement"
                replacement.write_bytes(original)
                replacement.replace(path)
            else:
                with path.open("r+b") as stream:
                    stream.seek(-1, 2)
                    stream.write(b"!")
                    stream.flush()
                    stream.seek(-1, 2)
                    stream.write(original[-1:])
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                assert path.read_bytes() == original and path.stat().st_mtime_ns == before.st_mtime_ns
                assert path.stat().st_ctime_ns != before.st_ctime_ns
        return actual_fstat(descriptor)

    monkeypatch.setattr(identity.os, "fstat", changing)
    with pytest.raises(ValueError, match="changed"):
        identity.binary_identity(path, 6)
