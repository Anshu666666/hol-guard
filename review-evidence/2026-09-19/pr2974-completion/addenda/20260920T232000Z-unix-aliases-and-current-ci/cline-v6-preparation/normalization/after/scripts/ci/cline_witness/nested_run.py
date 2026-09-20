"""Fixed outcome of the original generated worker's nested subprocess call."""

from __future__ import annotations

import atexit
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import FrameType
from typing import Any, cast

SCHEMA = "hol-guard.cline-original-nested-run.v1"
FAULTS = frozenset({"capture_failed", "call_shape", "multiple_calls", "return_shape", "errno_shape", "restore_failed"})
OUTCOMES = frozenset(
    {"not_offered", "in_progress", "returned", "timeout", "os_error", "subprocess_error", "other_exception"}
)
OS_ERRORS = (
    OSError,
    FileNotFoundError,
    PermissionError,
    FileExistsError,
    IsADirectoryError,
    NotADirectoryError,
    InterruptedError,
    BlockingIOError,
    ChildProcessError,
    ProcessLookupError,
    TimeoutError,
    BrokenPipeError,
    ConnectionAbortedError,
    ConnectionRefusedError,
    ConnectionResetError,
)


class NestedRun:
    """Patch only this admitted worker process; forward every original call."""

    def __init__(
        self, config: dict[str, Any], writer: Callable[[Path, object], None], process_factory: Callable[..., Any]
    ) -> None:
        self.config = config
        self.writer = writer
        self.original = subprocess.run
        self.hook = self.call
        self.calls = 0
        self.saturated = False
        self.outcome = "not_offered"
        self.returncode: int | None = None
        self.errno: int | None = None
        self.faults: list[str] = []
        self.closed = False
        self.restored = False
        self.installed = False
        self.process = process_factory(config)

    def fault(self, name: str) -> None:
        try:
            if name in FAULTS and name not in self.faults:
                self.faults.append(name)
        except BaseException:
            return

    def selected(self, frame: FrameType) -> bool:
        site = self.config["nested_callsite"]
        return (
            frame.f_code.co_filename == site["file"]
            and frame.f_code.co_qualname == "main"
            and frame.f_code.co_firstlineno == site["first_line"]
            and frame.f_lineno == site["call_line"]
            and frame.f_globals.get("__name__") == "__main__"
        )

    def before(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        self.calls = min(2, self.calls + 1)
        if self.calls != 1:
            self.saturated = True
            self.fault("multiple_calls")
        self.outcome = "in_progress"
        self.returncode = self.errno = None
        argv = args[0] if len(args) == 1 else None
        valid = (
            type(argv) is list
            and all(type(item) is str for item in argv)
            and argv == self.config["argv"][1]
            and set(kwargs) == {"input", "capture_output", "text", "timeout", "check"}
            and type(kwargs["input"]) is str
            and kwargs["capture_output"] is True
            and kwargs["text"] is True
            and type(kwargs["timeout"]) is int
            and kwargs["timeout"] == 9
            and kwargs["check"] is False
        )
        if not valid:
            self.fault("call_shape")

    def returned(self, result: object) -> None:
        self.outcome = "returned"
        if (
            type(result) is subprocess.CompletedProcess
            and type(result.returncode) is int
            and -(2**31) <= result.returncode < 2**31
        ):
            self.returncode = result.returncode
        else:
            self.fault("return_shape")

    def raised(self, error: BaseException) -> None:
        if type(error) is subprocess.TimeoutExpired:
            self.outcome = "timeout"
        elif any(type(error) is candidate for candidate in OS_ERRORS):
            self.outcome = "os_error"
            number = cast(OSError, error).errno
            if number is None or (type(number) is int and -(2**31) <= number < 2**31):
                self.errno = number
            else:
                self.fault("errno_shape")
        elif type(error) is subprocess.SubprocessError or type(error) is subprocess.CalledProcessError:
            self.outcome = "subprocess_error"
        else:
            self.outcome = "other_exception"

    def call(self, *args: Any, **kwargs: Any) -> Any:
        selected = False
        try:
            selected = self.selected(sys._getframe(1))
        except BaseException:
            self.fault("capture_failed")
        if not selected:
            return self.original(*args, **kwargs)
        try:
            self.before(args, kwargs)
            self.process.begin()
        except BaseException:
            self.fault("capture_failed")
        try:
            result = self.original(*args, **kwargs)
        except BaseException as error:
            try:
                self.raised(error)
                self.process.capture_output(error, raised=True)
            except BaseException:
                self.fault("capture_failed")
            raise
        finally:
            try:
                self.process.end()
            except BaseException:
                self.fault("capture_failed")
        try:
            self.returned(result)
            self.process.capture_output(result, raised=False)
        except BaseException:
            self.fault("capture_failed")
        return result

    def start(self) -> None:
        atexit.register(self.finish)
        self.process.start()
        subprocess.run = self.hook
        self.installed = True

    def finish(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            if subprocess.run is self.hook:
                subprocess.run = self.original
            self.restored = subprocess.run is self.original
            if not self.restored:
                self.fault("restore_failed")
            self.process.restore()
            report = {
                "schema": SCHEMA,
                "configuration_sha256": self.config["configuration_sha256"],
                "pid": os.getpid(),
                "parent_pid": os.getppid(),
                "selected_calls": self.calls,
                "count_saturated": self.saturated,
                "outcome": self.outcome,
                "returncode": self.returncode,
                "errno": self.errno,
                "faults": list(self.faults),
                "run_installed": self.installed,
                "run_restored": self.restored,
                "observation_complete": self.installed
                and not self.faults
                and self.restored
                and self.outcome != "in_progress",
                "original_timeout_seconds": 9,
                "original_call_changed": False,
                "raw_arguments_or_output_exported": False,
                "performance_qualified": False,
                "process_observation": self.process.document(),
            }
            self.writer(Path(self.config["output"]) / "nested-run.json", report)
        except BaseException:
            # Missing report remains an admission failure, never a new worker outcome.
            return


def install(
    config: dict[str, Any], writer: Callable[[Path, object], None], process_factory: Callable[..., Any]
) -> None:
    NestedRun(config, writer, process_factory).start()


def validate(report: object, worker: dict[str, Any], digest: str) -> None:
    """A zero-offer observation is valid evidence, never native route credit."""
    fields = {
        "schema",
        "configuration_sha256",
        "pid",
        "parent_pid",
        "selected_calls",
        "count_saturated",
        "outcome",
        "returncode",
        "errno",
        "faults",
        "run_installed",
        "run_restored",
        "observation_complete",
        "original_timeout_seconds",
        "original_call_changed",
        "raw_arguments_or_output_exported",
        "performance_qualified",
        "process_observation",
    }
    if type(report) is not dict or set(report) != fields:
        raise ValueError("cline_nested_schema")
    if (
        report["schema"] != SCHEMA
        or report["configuration_sha256"] != digest
        or type(report["pid"]) is not int
        or report["pid"] != worker["pid"]
        or type(report["parent_pid"]) is not int
        or report["parent_pid"] != worker["parent_pid"]
        or type(report["selected_calls"]) is not int
        or report["selected_calls"] not in (0, 1)
        or report["count_saturated"] is not False
        or type(report["outcome"]) is not str
        or report["outcome"] not in OUTCOMES - {"in_progress"}
        or report["faults"] != []
        or report["run_installed"] is not True
        or report["run_restored"] is not True
        or report["observation_complete"] is not True
        or type(report["original_timeout_seconds"]) is not int
        or report["original_timeout_seconds"] != 9
        or report["original_call_changed"] is not False
        or report["raw_arguments_or_output_exported"] is not False
        or report["performance_qualified"] is not False
    ):
        raise ValueError("cline_nested_binding")
    if (report["selected_calls"] == 0) != (report["outcome"] == "not_offered"):
        raise ValueError("cline_nested_offer_outcome")
    if report["outcome"] == "returned":
        if type(report["returncode"]) is not int or not -(2**31) <= report["returncode"] < 2**31:
            raise ValueError("cline_nested_returncode")
    elif report["returncode"] is not None:
        raise ValueError("cline_nested_unreturned_code")
    if report["errno"] is not None and (
        report["outcome"] != "os_error" or type(report["errno"]) is not int or not -(2**31) <= report["errno"] < 2**31
    ):
        raise ValueError("cline_nested_errno")
