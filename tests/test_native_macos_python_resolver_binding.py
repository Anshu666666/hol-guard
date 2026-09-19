"""Actual file replacement must not join one dylib's UUID to another digest."""

from __future__ import annotations

import hashlib
import os
import struct
from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts.ci import native_macos_python_resolver_path as collector


def test_bridge_read_swap_cannot_bind_middle_uuid_to_restored_file(tmp_path, monkeypatch):
    path = tmp_path / "bridge.dylib"
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 16777228, 0, 6, 1, 24, 0, 0)
    command = struct.pack("<II", 0x1B, 24)
    first = header + command + b"a" * 16 + b"fixed executable section"
    middle = header + command + b"b" * 16 + b"fixed executable section"
    path.write_bytes(first)
    first_stat = path.stat()
    expected = hashlib.sha256(first).hexdigest()
    assert collector.bridge_identity(path) == {
        "sha256": expected,
        "uuid": (b"a" * 16).hex(),
        "cpu_type": 16777228,
        "cpu_subtype": 0,
    }
    original_open, observed = Path.open, []

    @contextmanager
    def swapped_open(source, mode="r", *args, **kwargs):
        with original_open(source, mode, *args, **kwargs) as stream:
            if source != path or mode != "rb":
                yield stream
                return

            class Reader:
                def fileno(self):
                    return stream.fileno()

                def read(self, size=-1):
                    if size == 32 and not observed:
                        path.write_bytes(middle)
                        observed.append("swapped")
                    data = stream.read(size)
                    if size == 24 and observed == ["swapped"]:
                        observed.append(data)
                        path.write_bytes(first)
                        os.utime(path, ns=(first_stat.st_atime_ns, first_stat.st_mtime_ns + 1_000_000_000))
                    return data

            yield Reader()

    monkeypatch.setattr(Path, "open", swapped_open)
    with pytest.raises(ValueError, match="bridge changed"):
        collector.bridge_identity(path)
    assert observed == ["swapped", command + b"b" * 16]
    assert path.read_bytes() == first and hashlib.sha256(path.read_bytes()).hexdigest() == expected
    assert "tests/test_native_macos_python_resolver_binding.py" in collector.original.SOURCES
