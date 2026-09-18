"""Diagnose one unchanged corpus test without publishing captured child output."""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SELECTOR = (
    "tests/test_guard_command_corpus.py::test_full_guard_evaluation_matches_exact_non_widening_known_gap_baseline"
)
RUNNER = ROOT / "tests" / "guard_command_corpus_runner.py"
ERROR_CLASSES = frozenset(
    {
        "TimeoutExpired",
        "CalledProcessError",
        "ModuleNotFoundError",
        "ImportError",
        "TypeError",
        "ValueError",
        "AttributeError",
        "AssertionError",
        "RuntimeError",
        "MemoryError",
        "OSError",
        "FileNotFoundError",
        "PermissionError",
        "BrokenProcessPool",
    }
)


@contextmanager
def _private_output():
    sys.stdout.flush()
    sys.stderr.flush()
    saved = (os.dup(1), os.dup(2))
    try:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as captured:
            os.dup2(captured.fileno(), 1)
            os.dup2(captured.fileno(), 2)
            try:
                with redirect_stdout(captured), redirect_stderr(captured):
                    yield
            finally:
                captured.flush()
                os.dup2(saved[0], 1)
                os.dup2(saved[1], 2)
    finally:
        os.close(saved[0])
        os.close(saved[1])


def _captured_metadata(value: str | bytes | None) -> dict[str, object]:
    data = value.encode("utf-8", "replace") if isinstance(value, str) else value or b""
    text = data.decode("utf-8", "replace")
    classes = []
    for line in text.splitlines():
        match = re.match(r"^(?:[a-zA-Z_][a-zA-Z0-9_]*\.)*([A-Za-z_][A-Za-z0-9_]*):", line)
        if match and match.group(1) in ERROR_CLASSES:
            classes.append(match.group(1))
    frames = []
    for match in re.finditer(r'^  File "([^"\n]+)", line ([0-9]+), in ', text, re.MULTILINE):
        frames.append({"pathSha256": hashlib.sha256(match.group(1).encode()).hexdigest(), "line": int(match.group(2))})
    return {
        "byteCount": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "exceptionClasses": classes[-16:],
        "frames": frames[-32:],
    }


def _exception(error: BaseException) -> dict[str, object]:
    name = type(error).__name__
    result: dict[str, object] = {"class": name if name in ERROR_CLASSES else "OtherException"}
    if isinstance(error, subprocess.CalledProcessError):
        result.update(returnCode=error.returncode, stderr=_captured_metadata(error.stderr))
    if isinstance(error, subprocess.TimeoutExpired):
        result.update(timeoutSeconds=error.timeout, stderr=_captured_metadata(error.stderr))
    return result


def _tree_binding() -> dict[str, object]:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    rows = subprocess.check_output(["git", "ls-tree", "-rz", "HEAD"], cwd=ROOT).split(b"\0")
    expected = {}
    mismatches = []
    for row in rows:
        if not row:
            continue
        metadata, path_bytes = row.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        if kind != "blob":
            raise RuntimeError("unsupported tracked entry")
        relative = path_bytes.decode()
        path = ROOT / relative
        data = os.readlink(path).encode() if mode == "120000" else path.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        expected[relative] = blob
        if actual != blob:
            mismatches.append(hashlib.sha256(path_bytes).hexdigest())
    loaded = {}
    unknown = []
    for name, module in tuple(sys.modules.items()):
        if not (name == "codex_plugin_scanner" or name.startswith(("codex_plugin_scanner.", "tests."))):
            continue
        source = getattr(module, "__file__", None)
        if not isinstance(source, str) or not source.endswith(".py"):
            continue
        try:
            relative = str(Path(source).resolve().relative_to(ROOT))
        except ValueError:
            unknown.append(hashlib.sha256(name.encode()).hexdigest())
            continue
        data = Path(source).read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        loaded[hashlib.sha256(relative.encode()).hexdigest()] = actual
        if expected.get(relative) != actual:
            mismatches.append(hashlib.sha256(relative.encode()).hexdigest())
    return {
        "head": head,
        "trackedBlobs": len(expected),
        "loadedParentSourceCount": len(loaded),
        "loadedParentSourceBlobs": loaded,
        "mismatchedPathHashes": sorted(set(mismatches)),
        "unknownModuleHashes": sorted(set(unknown)),
        "childLoadedSourceAudit": False,
    }


class Probe:
    def __init__(self) -> None:
        self.phases = []
        self.children = []

    @pytest.fixture(autouse=True)
    def observe_coordinator(self, monkeypatch):
        original = subprocess.run

        @functools.wraps(original)
        def observed(*args, **kwargs):
            command = args[0] if args else kwargs.get("args")
            selected = isinstance(command, (tuple, list)) and list(command) == [sys.executable, str(RUNNER)]
            if not selected:
                return original(*args, **kwargs)
            started = time.monotonic()
            outcome = {"timeoutSeconds": kwargs.get("timeout"), "check": kwargs.get("check")}
            try:
                result = original(*args, **kwargs)
                outcome["returnCode"] = result.returncode
                outcome["stdout"] = _captured_metadata(result.stdout)
                return result
            except BaseException as error:
                outcome["error"] = _exception(error)
                raise
            finally:
                outcome["elapsedSeconds"] = round(time.monotonic() - started, 6)
                self.children.append(outcome)

        monkeypatch.setattr(subprocess, "run", observed)
        yield

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        outcome = yield
        report = outcome.get_result()
        result = {"phase": report.when, "outcome": report.outcome}
        if call.excinfo is not None:
            result["exception"] = _exception(call.excinfo.value)
        self.phases.append(result)


def main() -> int:
    try:
        with _private_output():
            os.umask(0o077)
            before = _tree_binding()
            if before["mismatchedPathHashes"] or before["unknownModuleHashes"]:
                raise RuntimeError("source mismatch")
            probe = Probe()
            started = time.monotonic()
            code = int(pytest.main(["-q", "--tb=no", "-p", "no:cacheprovider", SELECTOR], plugins=[probe]))
            after = _tree_binding()
            invalid = (
                after["head"] != before["head"]
                or after["trackedBlobs"] != before["trackedBlobs"]
                or after["mismatchedPathHashes"]
                or after["unknownModuleHashes"]
                or len(probe.children) != 1
            )
            result = {
                "selector": SELECTOR,
                "interpreter": sys.version.split()[0],
                "pytestExit": code,
                "elapsedSeconds": round(time.monotonic() - started, 3),
                "before": before,
                "after": after,
                "testPhases": probe.phases,
                "coordinator": probe.children,
                "rawOutputPublished": False,
                "testBudgetsChanged": False,
                "testRetriesAdded": False,
                "scope": "One instrumented unchanged test; full-shard failure is not cleared by this diagnostic.",
            }
            code = code or int(bool(invalid))
    except BaseException as error:
        try:
            detail = _exception(error)
        except BaseException:
            detail = {"class": "DiagnosticMetadataError"}
        result = {"diagnosticStatus": "error", "exception": detail, "rawOutputPublished": False}
        code = 2
    try:
        print(json.dumps(result, sort_keys=True))
    except BaseException:
        return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
