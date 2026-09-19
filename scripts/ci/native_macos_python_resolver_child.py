"""Fixed Python/libc comparison child; its owner supplies the five-second bound."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import socket
import sys
from pathlib import Path
from typing import Any

MODES = ("socket_addr", "socket_name", "c_addr", "c_name")
LOCAL_NAMES = frozenset(
    ("localhost", "localhost.", "127.0.0.1", "hol-guard-qualification.localhost", "hol-guard-qualification.localhost.")
)


def file_sha(path: Path, maximum: int = 256 * 1024 * 1024) -> str:
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not 0 < before.st_size <= maximum:
            raise ValueError("identity size")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                raise ValueError("identity truncated")
            remaining -= len(block)
            digest.update(block)
        after = os.fstat(stream.fileno())

        def fields(item: os.stat_result) -> tuple[int, ...]:
            return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns

        if stream.read(1) or fields(before) != fields(after) or fields(after) != fields(path.stat()):
            raise ValueError("identity changed")
        return digest.hexdigest()


def runtime_identity() -> dict[str, str]:
    import _ctypes
    import _socket

    return {
        "python_sha256": file_sha(Path(sys.executable)),
        "socket_sha256": file_sha(Path(_socket.__file__)),
        "ctypes_sha256": file_sha(Path(_ctypes.__file__)),
        "child_source_sha256": file_sha(Path(__file__)),
    }


def emit(kind: str, **fields: Any) -> None:
    print(json.dumps({"kind": kind, **fields}, sort_keys=True), flush=True)


def socket_call(mode: str) -> int:
    error_kind, error_code, loopback = "none", 0, False
    try:
        if mode == "socket_addr":
            name = socket.gethostbyaddr("127.0.0.1")[0]
        else:
            name = socket.getnameinfo(("127.0.0.1", 0), socket.NI_NAMEREQD | socket.NI_NUMERICSERV)[0]
        loopback = name.lower() in LOCAL_NAMES
    except (OSError, UnicodeError) as error:
        error_kind = type(error).__name__
        if error_kind not in {
            "herror",
            "gaierror",
            "OSError",
            "UnicodeError",
            "UnicodeDecodeError",
            "UnicodeEncodeError",
        }:
            error_kind = "OSError" if isinstance(error, OSError) else "UnicodeError"
        number = getattr(error, "errno", None)
        error_code = number if type(number) is int and -(2**31) <= number < 2**31 else 0
    emit("socket_result", error_kind=error_kind, error_code=error_code, loopback_label=loopback)
    return 0 if error_kind == "none" else 2


def bridge_image(library: Any, phase: str) -> None:
    buffers = [ctypes.create_string_buffer(33) for _ in range(3)]
    if library.hol_guard_resolver_bridge_identity(*buffers, 33) != 0:
        raise ValueError("bridge identity")
    values = {}
    for label, buffer in zip(("bridge_uuid", "libinfo_uuid", "dnssd_uuid"), buffers, strict=True):
        value = buffer.raw
        if re.fullmatch(rb"[0-9a-f]{32}\x00", value) is None:
            raise ValueError("bridge identity format")
        values[label] = value[:32].decode("ascii")
    # Python writes/flushing use the descriptor, leaving C's stdout untouched
    # until the original probe configures its FILE stream in main().
    emit("bridge_image", phase=phase, **values)


def execute(mode: str, bridge: Path, expected_sha: str) -> int:
    if mode not in MODES:
        return 64
    stage = "runtime_binding"
    try:
        before = runtime_identity()
        emit("python_identity", mode=mode, pid=os.getpid(), **before)
        library = None
        if mode.startswith("c_"):
            stage = "before_load"
            emit("phase", phase=stage)
            if file_sha(bridge) != expected_sha:
                raise ValueError("bridge changed")
            library = ctypes.CDLL(str(bridge))
            stage = "after_load"
            emit("phase", phase=stage)
            library.hol_guard_resolver_call.argtypes = [ctypes.c_uint]
            library.hol_guard_resolver_call.restype = ctypes.c_int
            library.hol_guard_resolver_bridge_identity.argtypes = [
                ctypes.POINTER(ctypes.c_char),
                ctypes.POINTER(ctypes.c_char),
                ctypes.POINTER(ctypes.c_char),
                ctypes.c_uint,
            ]
            library.hol_guard_resolver_bridge_identity.restype = ctypes.c_int
            bridge_image(library, "before")
        stage = "call_enter"
        emit("phase", phase=stage)
        code = library.hol_guard_resolver_call(int(mode == "c_name")) if library else socket_call(mode)
        stage = "call_return"
        emit("phase", phase=stage)
        if library:
            bridge_image(library, "after")
        stage = "final_binding"
        after = runtime_identity()
        bridge_after = file_sha(bridge) if library else ""
        if after != before or (library and bridge_after != expected_sha):
            raise ValueError("execution identity changed")
        emit("python_complete", return_code=code, bridge_sha256=bridge_after, **after)
        return code
    except (OSError, ValueError, AttributeError) as error:
        category = "OSError" if isinstance(error, OSError) else type(error).__name__
        emit("failure", stage=stage, error_type=category)
        return 3


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, required=True)
    parser.add_argument("--bridge", type=Path, required=True)
    parser.add_argument("--bridge-sha256", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{64}", args.bridge_sha256) is None:
        return 64
    return execute(args.mode, args.bridge, args.bridge_sha256)


if __name__ == "__main__":
    raise SystemExit(main())
