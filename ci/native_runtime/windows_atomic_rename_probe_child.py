"""Bounded child for the separate Windows Ex22 rename API probe."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
from pathlib import Path
from typing import Any, cast


class _NativeCalls:
    def __init__(self, api: Any):
        self.api = api
        self.handles: set[int] = set()
        self.opens = 0
        self.closes = 0
        self.rename_calls = 0
        self.rename_returned = False
        self.first_failed_operation: str | None = None

    def __getattr__(self, name: str) -> Any:
        methods = {
            "CreateFileW": self.create_file,
            "SetFileInformationByHandle": self.rename,
            "CloseHandle": self.close_handle,
        }
        if name in methods:
            return methods[name]
        return getattr(self.api, name)

    def create_file(self, *arguments: Any) -> Any:
        self.opens += 1
        handle = self.api.CreateFileW(*arguments)
        if handle in (None, ctypes.c_void_p(-1).value):
            self.failed("source_open" if arguments[1] & 0x10000 else "parent_open")
        else:
            self.handles.add(int(handle))
        return handle

    def rename(self, *arguments: Any) -> Any:
        self.rename_calls += 1
        result = self.api.SetFileInformationByHandle(*arguments)
        if not result:
            self.failed("rename")
        else:
            self.rename_returned = True
        return result

    def close_handle(self, handle: int) -> Any:
        self.closes += 1
        result = self.api.CloseHandle(handle)
        if result:
            self.handles.discard(int(handle))
        else:
            self.failed("close")
        return result

    def failed(self, operation: str) -> None:
        if self.first_failed_operation is None:
            self.first_failed_operation = operation

    def report(self) -> dict[str, object]:
        return {
            "opens": self.opens,
            "closes": self.closes,
            "rename_calls": self.rename_calls,
            "rename_returned": self.rename_returned,
            "owned_handles_remaining": len(self.handles),
            "first_failed_operation": self.first_failed_operation,
        }


class _RenameOs:
    def __init__(self, original: Any, probe: Any):
        self.original = original
        self.probe = probe
        self.expected = None
        self.snapshot_taken = False
        self.snapshot_failure: BaseException | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)

    def close(self, descriptor: int) -> None:
        # Observation failure is re-raised unchanged at the next replace seam,
        # after the original close and its descriptor = -1 state transition.
        # This avoids causing the writer's finally to close the same fd twice.
        try:
            self.expected = self.probe.snapshot_descriptor(descriptor)
            self.snapshot_taken = True
        except BaseException as error:
            self.snapshot_failure = error
        self.original.close(descriptor)

    def replace(self, source: Path, destination: Path) -> None:
        if self.snapshot_failure is not None:
            raise self.snapshot_failure
        if self.expected is None:
            raise RuntimeError("probe_original_writer_snapshot_missing")
        self.probe.replace_once(Path(source), Path(destination), self.expected)


def _writer(args: Any, original_child: Any, probe: Any, native: _NativeCalls) -> int:
    from codex_plugin_scanner.guard.daemon import manager

    original_os = manager.os
    observer = _RenameOs(original_os, probe)
    original_print = getattr(original_child, "print", print)

    def report_print(value: str, **keywords: Any) -> None:
        report = json.loads(value)
        report["probe"] = native.report()
        report["probe"]["writer_snapshot_taken"] = observer.snapshot_taken
        original_print(json.dumps(report, sort_keys=True), **keywords)

    manager.os = cast(Any, observer)
    original_child.print = report_print
    try:
        return original_child._writer(args)
    finally:
        manager.os = original_os
        original_child.print = original_print


def _audit(args: Any, original_child: Any, probe: Any, native: _NativeCalls) -> int:
    source = args.target.with_name(".rename-audit-source")
    descriptor = os.open(source, os.O_RDONLY)
    try:
        expected = probe.snapshot_descriptor(descriptor)
    finally:
        os.close(descriptor)
    refusal = RuntimeError("synthetic rename audit refusal")
    events: list[dict[str, object]] = []
    observed = None

    def audit(event: str, arguments: tuple[object, ...]) -> None:
        if event != "os.rename":
            return
        events.append(
            {
                "source_same": arguments[0] == str(source),
                "destination_same": arguments[1] == str(args.target),
                "source_dir_fd": arguments[2],
                "destination_dir_fd": arguments[3],
                "opens_before_event": native.opens,
                "renames_before_event": native.rename_calls,
            }
        )
        if args.refuse:
            raise refusal

    sys.addaudithook(audit)
    try:
        if args.candidate:
            probe.replace_once(source, args.target, expected)
        else:
            os.replace(source, args.target)
    except BaseException as error:
        observed = error
    print(
        json.dumps(
            {
                "schema": 1,
                "operation": "rename_audit",
                "events": events,
                "refusal_same_object": observed is refusal,
                "error": original_child._code(observed),
                "probe": native.report(),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--operation", choices=("writer", "rename_audit"), required=True)
    parser.add_argument("--hold-crt-source", action="store_true")
    parser.add_argument("--candidate", action="store_true")
    parser.add_argument("--refuse", action="store_true")
    args = parser.parse_args()
    if os.name != "nt" or sys.flags.isolated != 1:
        raise RuntimeError("probe_requires_isolated_windows_python")
    source = args.source_root.resolve(strict=True)
    sys.path[:0] = [str(source / "src"), str(source)]
    from ci.native_runtime import windows_atomic_rename_probe as probe
    from ci.native_runtime import windows_replaceable_reader_child as original_child

    native = _NativeCalls(probe._api())
    probe._api = lambda: native
    try:
        if args.operation == "writer":
            return _writer(args, original_child, probe, native)
        return _audit(args, original_child, probe, native)
    except BaseException as error:
        print(
            json.dumps(
                {
                    "schema": 1,
                    "operation": "failure",
                    "requested_operation": args.operation,
                    "error": original_child._code(error),
                    "probe": native.report(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
