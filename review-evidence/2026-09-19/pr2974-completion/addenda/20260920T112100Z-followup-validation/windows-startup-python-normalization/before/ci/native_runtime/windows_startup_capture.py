"""Capture the exact original startup subprocess once, preserving pytest behavior."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ci.native_runtime.windows_startup_record import parse_stderr

SELECTOR = (
    "ci/native_runtime/test_native_hook_client_transport.py::"
    "test_native_hook_client_rejects_duplicate_edge_keys_without_fallback"
)
PAYLOAD = b'{"schema":"guard-hook-envelope.v2","schema":"other"}'
MAX_OUTPUT_BYTES = 8192


def _body(value: Any) -> dict[str, Any]:
    if type(value) is not bytes:
        return {"present": False, "complete": False, "bytes": None,
                "sha256": None, "prefix_sha256": None, "base64": None}
    bounded = value[:MAX_OUTPUT_BYTES]
    return {"present": True, "complete": len(value) <= MAX_OUTPUT_BYTES,
            "bytes": len(value),
            "sha256": hashlib.sha256(bounded).hexdigest() if len(value) <= MAX_OUTPUT_BYTES else None,
            "prefix_sha256": hashlib.sha256(bounded).hexdigest(),
            "base64": base64.b64encode(bounded).decode("ascii")}


class Capture:
    def __init__(self, original: Callable[..., Any], runtime: str) -> None:
        self.original = original
        self.runtime = runtime
        self.target_calls = 0
        self.exact_calls = 0
        self.other_calls = 0
        self.lost = False
        self.returned: dict[str, Any] | None = None
        self.phases: dict[str, str] = {}
        self.stop_calls = 0
        self.stop_result: dict[str, Any] | None = None

    def _candidate(self, args: tuple[Any, ...]) -> bool:
        if len(args) != 1 or type(args[0]) not in (tuple, list):
            return False
        argv = args[0]
        return len(argv) >= 2 and argv[1] == "hook-client"

    def _exact(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> bool:
        argv = args[0]
        return (
            type(argv) is tuple
            and len(argv) == 4
            and all(type(value) is str for value in argv)
            and argv[0] == self.runtime
            and argv[1:3] == ("hook-client", "--stdin")
            and Path(argv[3]).name == "native-runtime"
            and set(kwargs) == {"input", "check", "capture_output", "timeout"}
            and type(kwargs["input"]) is bytes and kwargs["input"] == PAYLOAD
            and kwargs["check"] is False and kwargs["capture_output"] is True
            and type(kwargs["timeout"]) is int and kwargs["timeout"] == 3
        )

    def _returned(self, result: Any) -> None:
        if type(result) is not subprocess.CompletedProcess:
            self.lost = True
            self.returned = {"kind": "unsupported_result"}
            return
        detail: dict[str, Any] = {
            "kind": "completed_process", "returncode": result.returncode,
            "stdout": _body(result.stdout), "stderr": _body(result.stderr),
        }
        try:
            parsed = parse_stderr(result.stderr, result.returncode)
            original = parsed.pop("original_stderr")
            detail["observation"] = parsed
            detail["original_stderr"] = _body(original)
        except Exception:
            detail["observation"] = {"status": "invalid", "record": None}
        self.returned = detail

    def _other(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        stop = (
            len(args) == 1 and type(args[0]) is tuple and len(args[0]) == 4
            and args[0][0] == self.runtime and args[0][1:3] == ("resident-stop", "--state-dir")
            and set(kwargs) == {"check", "capture_output", "timeout"}
            and kwargs["check"] is False and kwargs["capture_output"] is True
            and type(kwargs["timeout"]) is int and kwargs["timeout"] == 2
        )
        if stop:
            self.stop_calls = min(self.stop_calls + 1, 65535)
        try:
            result = self.original(*args, **kwargs)
        except BaseException:
            if stop:
                self.stop_result = {"kind": "original_exception"}
            raise
        if stop:
            try:
                if type(result) is subprocess.CompletedProcess and self.stop_calls == 1:
                    self.stop_result = {
                        "kind": "completed_process", "returncode": result.returncode,
                        "stdout": _body(result.stdout), "stderr": _body(result.stderr),
                    }
                else:
                    self.lost = True
            except Exception:
                self.lost = True
        return result

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        # No native/probe call is added. All original arguments and the original
        # returned object or raised exception are forwarded without replacement.
        if not self._candidate(args):
            self.other_calls = min(self.other_calls + 1, 65535)
            return self._other(args, kwargs)
        if self.target_calls >= 65535:
            self.lost = True
        self.target_calls = min(self.target_calls + 1, 65535)
        exact = self._exact(args, kwargs)
        if exact:
            self.exact_calls = min(self.exact_calls + 1, 65535)
        else:
            self.lost = True
        try:
            result = self.original(*args, **kwargs)
        except BaseException as error:
            try:
                if isinstance(error, subprocess.TimeoutExpired):
                    kind = "timeout"
                elif isinstance(error, OSError):
                    kind = "os_error"
                elif isinstance(error, KeyboardInterrupt):
                    kind = "interrupt"
                else:
                    kind = "other_exception"
                if self.target_calls == 1:
                    self.returned = {"kind": kind}
                else:
                    self.lost = True
            except Exception:
                self.lost = True
            raise
        try:
            if self.target_calls == 1:
                self._returned(result)
            else:
                self.lost = True
        except Exception:
            self.lost = True
        return result

    def phase(self, nodeid: str, when: str, outcome: str) -> None:
        if nodeid != SELECTOR or when not in ("setup", "call", "teardown"):
            self.lost = True
            return
        if outcome not in ("passed", "failed", "skipped") or when in self.phases:
            self.lost = True
            return
        self.phases[when] = outcome

    def result(self, pytest_exit: int) -> dict[str, Any]:
        returned = self.returned
        return {
            "schema": "pr2974-windows-startup-capture.v1",
            "selector": SELECTOR, "original_pytest_exit": pytest_exit,
            "payload_bytes": len(PAYLOAD),
            "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
            "target_calls": self.target_calls, "exact_calls": self.exact_calls,
            "other_calls": self.other_calls, "capture_lost": self.lost,
            "phases": dict(self.phases), "returned": returned,
            "original_stop_calls": self.stop_calls, "original_stop_result": self.stop_result,
            "child_observed": False, "complete_descendant_cleanup": False,
            "headline_timing_eligible": False, "qualification_complete": False,
        }


class CapturePlugin:
    def __init__(self, runtime: str, output: Path) -> None:
        self.capture = Capture(subprocess.run, runtime)
        self.output = output
        self.original = subprocess.run
        subprocess.run = self.capture.invoke

    def pytest_runtest_logreport(self, report: Any) -> None:
        self.capture.phase(report.nodeid, report.when, report.outcome)

    def pytest_sessionfinish(self, session: Any, exitstatus: int) -> None:
        del session
        subprocess.run = self.original
        try:
            with self.output.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(self.capture.result(int(exitstatus)), handle, sort_keys=True)
                handle.write("\n")
        except Exception:
            # The original pytest result is preserved. The driver rejects a
            # missing capture file; export failure cannot manufacture success.
            return

    def pytest_unconfigure(self, config: Any) -> None:
        del config
        subprocess.run = self.original


def pytest_configure(config: Any) -> None:
    runtime = os.environ["HOL_GUARD_NATIVE_BINARY"]
    output = Path(os.environ["HOL_GUARD_WINDOWS_STARTUP_CAPTURE"])
    config.pluginmanager.register(CapturePlugin(runtime, output), "windows-startup-capture")
