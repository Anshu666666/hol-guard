"""Run one unchanged HTTP compatibility regression with closed diagnostic output."""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SELECTOR = (
    "tests/test_guard_surface_server.py::TestGuardSurfaceServer::"
    "test_guard_daemon_pi_hook_endpoint_returns_blocked_runtime_review_payload"
)


@contextmanager
def _private_output():
    """Discard captured process output after emitting only explicit metadata."""
    sys.stdout.flush()
    sys.stderr.flush()
    original = (os.dup(1), os.dup(2))
    try:
        with tempfile.TemporaryFile(mode="w+b") as output:
            os.dup2(output.fileno(), 1)
            os.dup2(output.fileno(), 2)
            try:
                yield
            finally:
                sys.stdout.flush()
                sys.stderr.flush()
                os.dup2(original[0], 1)
                os.dup2(original[1], 2)
    finally:
        os.close(original[0])
        os.close(original[1])


def _exception(error: BaseException) -> dict[str, object]:
    frames = []
    for frame in traceback.extract_tb(error.__traceback__):
        try:
            path = str(Path(frame.filename).resolve().relative_to(ROOT))
        except ValueError:
            continue
        frames.append({"path": path, "line": frame.lineno, "function": frame.name})
    return {"class": type(error).__name__, "repositoryFrames": frames}


class Probe:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.counts: Counter[str] = Counter()
        self.elapsed: dict[str, float] = {}
        self.exceptions: list[dict[str, object]] = []
        self.phases: list[dict[str, object]] = []

    def _count(self, name: str) -> None:
        with self.lock:
            self.counts[name] += 1

    def _record_error(self, stage: str, error: BaseException) -> None:
        with self.lock:
            if len(self.exceptions) < 32:
                self.exceptions.append({"stage": stage, **_exception(error)})

    def _wrap(self, monkeypatch: pytest.MonkeyPatch, owner: type, name: str) -> None:
        descriptor = inspect.getattr_static(owner, name)
        original = getattr(owner, name)

        @functools.wraps(original)
        def observed(*args, **kwargs):
            self._count(name + ":entered")
            started = time.monotonic()
            if name == "handle_error" and sys.exc_info()[1] is not None:
                self._record_error(name, sys.exc_info()[1])
            try:
                result = original(*args, **kwargs)
                if name == "_guard_admit_request":
                    self._count(name + (":accepted" if result else ":rejected"))
                if name == "_load_request_body":
                    self._count(name + (":valid" if result[1] is None else ":invalid"))
                if name == "_write_json":
                    status = kwargs.get("status", 200)
                    if isinstance(status, int) and 100 <= status <= 599:
                        self._count("http-status:" + str(status))
                return result
            except BaseException as error:
                self._record_error(name, error)
                raise
            finally:
                with self.lock:
                    self.elapsed[name] = self.elapsed.get(name, 0.0) + time.monotonic() - started

        monkeypatch.setattr(owner, name, staticmethod(observed) if isinstance(descriptor, staticmethod) else observed)

    @pytest.fixture(autouse=True)
    def instrument_transport(self, monkeypatch: pytest.MonkeyPatch):
        from codex_plugin_scanner.guard.daemon import server

        for name in (
            "handle_error",
            "_guard_admit_request",
            "_register_unclassified_connection",
            "_process_request_worker",
            "_discard_request",
            "_close_unclassified_socket",
        ):
            self._wrap(monkeypatch, server._GuardDaemonHTTPServer, name)
        for name in (
            "_load_request_body",
            "_handle_runtime_hook",
            "_handle_runtime_hook_compatibility_cli",
            "_write_json",
        ):
            self._wrap(monkeypatch, server._GuardDaemonHandler, name)
        yield

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        outcome = yield
        report = outcome.get_result()
        result = {"phase": report.when, "outcome": report.outcome}
        if call.excinfo is not None:
            result["exception"] = _exception(call.excinfo.value)
        self.phases.append(result)


def _source_binding() -> dict[str, object]:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    rows = subprocess.check_output(["git", "ls-tree", "-r", "HEAD"], cwd=ROOT, text=True).splitlines()
    expected = {row.split("\t")[1]: row.split("\t")[0].split()[2] for row in rows}
    matched = {}
    unknown = []
    mismatches = []
    for name, module in tuple(sys.modules.items()):
        if not (name == "codex_plugin_scanner" or name.startswith(("codex_plugin_scanner.", "tests."))):
            continue
        source = getattr(module, "__file__", None)
        if not isinstance(source, str) or not source.endswith(".py"):
            continue
        path = Path(source).resolve()
        try:
            relative = str(path.relative_to(ROOT))
        except ValueError:
            unknown.append(name)
            continue
        data = path.read_bytes()
        digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        matched[relative] = digest
        if expected.get(relative) != digest:
            mismatches.append(relative)
    return {
        "head": head,
        "loadedSourceCount": len(matched),
        "loadedBlobs": matched,
        "unmappedModules": sorted(set(unknown)),
        "mismatchedPaths": sorted(set(mismatches)),
    }


def main() -> int:
    try:
        with _private_output():
            os.umask(0o077)
            probe = Probe()
            started = time.monotonic()
            code = int(pytest.main(["-q", "--tb=no", "-p", "no:cacheprovider", SELECTOR], plugins=[probe]))
            binding = _source_binding()
            result = {
                "selector": SELECTOR,
                "interpreter": sys.version.split()[0],
                "pytestExit": code,
                "elapsedSeconds": round(time.monotonic() - started, 3),
                "sourceBinding": binding,
                "testPhases": probe.phases,
                "transportCounts": dict(probe.counts),
                "transportSeconds": {name: round(value, 6) for name, value in probe.elapsed.items()},
                "transportExceptions": probe.exceptions,
                "rawOutputPublished": False,
                "budgetsChanged": False,
                "retriesAdded": False,
            }
            code = code or int(bool(binding["unmappedModules"] or binding["mismatchedPaths"]))
    except BaseException as error:
        try:
            diagnostic_error = _exception(error)
        except BaseException:
            diagnostic_error = {"class": "DiagnosticMetadataError", "repositoryFrames": []}
        result = {"diagnosticStatus": "error", "error": diagnostic_error, "rawOutputPublished": False}
        code = 2
    try:
        print(json.dumps(result, sort_keys=True))
    except BaseException:
        return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
