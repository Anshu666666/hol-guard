"""Bind one regular Mach-O file's complete bytes, file type, CPU and UUID."""

from __future__ import annotations

import hashlib
import os
import stat
import struct
from pathlib import Path
from typing import Any

MAXIMUM = 256 * 1024 * 1024
COMMAND_LIMIT = 1024 * 1024
CPU_TYPES = {"arm64": 16777228, "x86_64": 16777223}


def parse_identity(data: bytes, filetype: int) -> dict[str, Any]:
    if type(filetype) is not int or filetype not in (2, 6) or not 32 <= len(data) <= COMMAND_LIMIT + 32:
        raise ValueError("Mach-O input")
    magic, cpu, subtype, actual_type, count, size, _flags, _reserved = struct.unpack("<IiiIIIII", data[:32])
    if (
        magic != 0xFEEDFACF or cpu not in CPU_TYPES.values() or actual_type != filetype
        or not 0 < count <= 1024 or size != len(data) - 32
    ):
        raise ValueError("Mach-O header")
    cursor, uuid = 32, None
    for _ in range(count):
        if len(data) - cursor < 8:
            raise ValueError("Mach-O command")
        kind, length = struct.unpack("<II", data[cursor : cursor + 8])
        if length < 8 or length % 8 or length > len(data) - cursor:
            raise ValueError("Mach-O command size")
        if kind == 0x1B:
            if length != 24 or uuid is not None:
                raise ValueError("Mach-O UUID")
            uuid = data[cursor + 8 : cursor + 24].hex()
        cursor += length
    if cursor != len(data) or uuid is None:
        raise ValueError("Mach-O UUID absent")
    return {"filetype": filetype, "cpu_type": cpu, "cpu_subtype": subtype, "uuid": uuid}


def _fields(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def binary_identity(path: Path, filetype: int) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAXIMUM:
            raise ValueError("binary size or type")
        header = stream.read(32)
        if len(header) != 32:
            raise ValueError("binary header")
        size = struct.unpack("<I", header[20:24])[0]
        if size > COMMAND_LIMIT or size > before.st_size - 32:
            raise ValueError("binary commands")
        commands = stream.read(size)
        identity = parse_identity(header + commands, filetype)
        digest = hashlib.sha256(header + commands)
        remaining = before.st_size - len(header) - len(commands)
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("binary truncated")
            digest.update(chunk)
            remaining -= len(chunk)
        if stream.read(1):
            raise ValueError("binary grew")
        after = os.fstat(stream.fileno())
        if _fields(before) != _fields(after) or _fields(after) != _fields(path.stat(follow_symlinks=False)):
            raise ValueError("binary changed")
    return identity | {"sha256": digest.hexdigest()}
