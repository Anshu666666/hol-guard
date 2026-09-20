"""Finite source-only Windows journal byte-lock experiment; never a corpus driver."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import stat
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
JOURNAL_SHA256 = "ae6482f105278138f419ae2b33771cc3a91a8bcd8b3552a0bc082b5e9e424988"
OPERATIONS = ("open", "fstat", "ftruncate", "lseek", "acquire", "unlock", "close")


def error_record(error: BaseException) -> dict[str, object]:
    names: dict[type[BaseException], str] = {
        OSError: "os_error",
        PermissionError: "permission",
        FileNotFoundError: "not_found",
        RuntimeError: "runtime",
    }
    values: dict[str, object] = {"kind": names.get(type(error), "unregistered"), "errno": None, "winerror": None}
    if type(error) in (OSError, PermissionError, FileNotFoundError):
        for name in ("errno", "winerror"):
            value = getattr(error, name, None)
            if type(value) is int and -(2**31) <= value < 2**32:
                values[name] = value
    return values


class Forward:
    """Forward original calls once; retain no arguments or error messages."""

    def __init__(self, original: ModuleType, emit: Callable[[dict[str, object]], None], *, crt: bool = False) -> None:
        self.original = original
        self.emit = emit
        self.crt = crt
        self.calls: dict[str, int] = dict.fromkeys(OPERATIONS, 0)
        self.descriptors: list[int] = []
        self.failures: list[dict[str, object]] = []

    def __getattr__(self, name: str) -> Any:
        original = getattr(self.original, name)
        if name not in ("open", "fstat", "ftruncate", "lseek", "close", "locking"):
            return original

        def call(*args: Any, **kwargs: Any) -> Any:
            operation = name
            if name == "locking":
                operation = "unlock" if args[1] == self.original.LK_UNLCK else "acquire"
            self.calls[operation] += 1
            if operation in ("ftruncate", "acquire"):
                self.emit({"event": operation + "_begin"})
            try:
                result = original(*args, **kwargs)
            except BaseException as error:
                self.failures.append({"operation": operation, **error_record(error)})
                raise
            if operation == "open":
                self.descriptors.append(result)
            return result

        return call


@contextmanager
def primitive(journal: Any, path: Path, nonblocking: bool) -> Iterator[None]:
    """Original open/guards/offset/range, without truncation: a primitive control."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = journal.os.open(lock_path, flags, 0o600)
    locked = False
    try:
        metadata = journal.os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError("evidence journal lock is not a private regular file")
        journal._apply_private_file_mode(descriptor)
        journal.os.lseek(descriptor, 0, os.SEEK_SET)
        mode = journal.msvcrt.LK_NBLCK if nonblocking else journal.msvcrt.LK_LOCK
        journal.msvcrt.locking(descriptor, mode, 1)
        locked = True
        yield
    finally:
        if locked:
            journal.os.lseek(descriptor, 0, os.SEEK_SET)
            journal.msvcrt.locking(descriptor, journal.msvcrt.LK_UNLCK, 1)
        journal.os.close(descriptor)


def observe(
    journal: Any, path: Path, role: str, emit: Callable[[dict[str, object]], None], release: Callable[[], str]
) -> dict[str, object]:
    original_os, original_crt = journal.os, journal.msvcrt
    os_proxy, crt_proxy = Forward(original_os, emit), Forward(original_crt, emit, crt=True)
    journal.os, journal.msvcrt = os_proxy, crt_proxy
    report: dict[str, object] = {"role": role, "entered": False, "error": None}
    try:
        selected = (
            primitive(journal, path, role == "nonblocking")
            if role in ("blocking", "nonblocking")
            else journal._journal_lock(path)
        )
        try:
            with selected:
                report["entered"] = True
                if role == "holder":
                    emit({"event": "held"})
                    if release() != "release\n":
                        raise RuntimeError("control_release_protocol")
        except BaseException as error:
            report["error"] = error_record(error)
    finally:
        journal.os, journal.msvcrt = original_os, original_crt
        closed: list[bool] = []
        emergency: list[bool] = []
        for descriptor in os_proxy.descriptors:
            try:
                original_os.fstat(descriptor)
            except OSError as error:
                closed.append(error.errno == errno.EBADF)
            else:
                closed.append(False)
                try:
                    original_os.close(descriptor)
                    emergency.append(True)
                except OSError:
                    emergency.append(False)
        report.update(
            {
                "calls": {name: os_proxy.calls[name] + crt_proxy.calls[name] for name in OPERATIONS},
                "failures": os_proxy.failures + crt_proxy.failures,
                "opened_descriptors": len(os_proxy.descriptors),
                "original_descriptors_closed": closed,
                "emergency_close_results": emergency,
                "callbacks_restored": journal.os is original_os and journal.msvcrt is original_crt,
            }
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("holder", "original", "blocking", "nonblocking"), required=True)
    parser.add_argument("--path", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt":
        raise RuntimeError("windows_required")
    sys.path[:0] = [str(ROOT), str(ROOT / "src")]
    from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal

    source = Path(str(journal.__file__))
    normalized = source.read_bytes().replace(b"\r\n", b"\n")
    if not source.resolve().is_relative_to(ROOT / "src") or hashlib.sha256(normalized).hexdigest() != JOURNAL_SHA256:
        raise RuntimeError("journal_source_mismatch")
    if journal.fcntl is not None or journal.msvcrt is None:
        raise RuntimeError("windows_lock_branch_required")

    def emit(value: dict[str, object]) -> None:
        print(json.dumps(value, sort_keys=True), flush=True)

    report = observe(journal, args.path, args.role, emit, sys.stdin.readline)
    report["source_sha256"] = JOURNAL_SHA256
    emit({"event": "result", "report": report})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
