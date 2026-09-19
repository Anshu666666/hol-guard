"""Finite terminal evidence for one unchanged command-corpus invocation."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from types import CodeType, TracebackType
from typing import Any

RUNNER_BLOB = "bd0721c3bd3c63ad5b02f68c5000f4f49a23bf5b"
MARKER = "HGP_CORPUS_TERMINAL_V1="
OPT_IN = "HOL_GUARD_CORPUS_TERMINAL_PROOF"
FUNCTIONS = (
    "_install_evaluator_packages",
    "_worker_report",
    "_decode_worker",
    "_run_worker",
    "_iter_reports",
    "_coordinator_report",
    "peak_rss_mib",
)
KINDS = frozenset(
    {
        "AssertionError",
        "CalledProcessError",
        "FileNotFoundError",
        "ImportError",
        "KeyError",
        "MemoryError",
        "ModuleNotFoundError",
        "OSError",
        "OverflowError",
        "PermissionError",
        "RecursionError",
        "RuntimeError",
        "TimeoutError",
        "TimeoutExpired",
        "TypeError",
        "ValueError",
        "other",
    }
)
PHASES = frozenset(
    {
        "package-import",
        "worker-import",
        "worker-ranks",
        "worker-streams",
        "worker-evaluation",
        "worker-comparison",
        "worker-report",
        "worker-decode",
        "worker-subprocess",
        "coordinator-workers",
        "coordinator-report",
        "rss",
        "unknown",
    }
)
FIELDS = frozenset(
    {"schema", "producer", "kind", "phase", "exit", "worker", "mismatchGroups", "mismatchCases", "child"}
)


def _number(value: object, minimum: int, maximum: int) -> int | None:
    return value if type(value) is int and minimum <= value <= maximum else None


def _kind(error: BaseException) -> str:
    name = type(error).__name__
    return name if type(error).__module__ in {"builtins", "subprocess"} and name in KINDS else "other"


def _valid(value: object, depth: int = 0) -> bool:
    if type(value) is not dict or set(value) != FIELDS or depth > 2:
        return False
    if value["schema"] != 1 or value["producer"] != RUNNER_BLOB:
        return False
    if value["kind"] not in KINDS or value["phase"] not in PHASES:
        return False
    for key, low, high in (
        ("exit", -255, 255),
        ("worker", 0, 3),
        ("mismatchGroups", 0, 64),
        ("mismatchCases", 0, 1000000),
    ):
        item = value[key]
        if item is not None and _number(item, low, high) is None:
            return False
    return value["child"] is None or _valid(value["child"], depth + 1)


def read_marker(raw: object) -> dict[str, Any] | None:
    if type(raw) is not str or len(raw) > 65536:
        return None
    lines = [line[len(MARKER) :] for line in raw.splitlines() if line.startswith(MARKER)]
    if len(lines) != 1 or len(lines[0]) > 2048:
        return None
    try:
        value = json.loads(lines[0])
        return value if _valid(value) else None
    except (TypeError, ValueError, RecursionError):
        return None


def _phase(name: str, line: int) -> str:
    if name == "_worker_report":
        if line <= 98:
            return "worker-import"
        if line <= 103:
            return "worker-ranks"
        if line <= 118:
            return "worker-streams"
        if line == 119:
            return "worker-evaluation"
        if line <= 124:
            return "worker-comparison"
        return "worker-report"
    return {
        "_install_evaluator_packages": "package-import",
        "_decode_worker": "worker-decode",
        "_run_worker": "worker-subprocess",
        "_iter_reports": "coordinator-workers",
        "_coordinator_report": "coordinator-report",
        "peak_rss_mib": "rss",
    }.get(name, "unknown")


def project_failure(error: BaseException, terminal: TracebackType | None, namespace: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": 1,
        "producer": RUNNER_BLOB,
        "kind": _kind(error),
        "phase": "unknown",
        "exit": None,
        "worker": None,
        "mismatchGroups": None,
        "mismatchCases": None,
        "child": None,
    }
    codes = {
        value.__code__: name
        for name in FUNCTIONS
        if callable(value := namespace.get(name)) and type(getattr(value, "__code__", None)) is CodeType
    }
    for _ in range(64):
        if terminal is None:
            break
        frame = terminal.tb_frame
        name = codes.get(frame.f_code)
        if name is not None and frame.f_globals is namespace:
            result["phase"] = _phase(name, terminal.tb_lineno)
            local = frame.f_locals
            worker = _number(local.get("worker_index"), 0, 3)
            if worker is not None:
                result["worker"] = worker
            groups = local.get("groups")
            if type(groups) in (dict, defaultdict):
                values = list(groups.values()) if len(groups) <= 64 else []
                if len(groups) <= 64 and all(type(item) is list for item in values):
                    count = sum(len(item) for item in values)
                    if count <= 1000000:
                        result["mismatchGroups"] = len(groups)
                        result["mismatchCases"] = count
        terminal = terminal.tb_next
    if type(error) is subprocess.CalledProcessError:
        result["exit"] = _number(error.returncode, -255, 255)
        result["child"] = read_marker(error.stderr)
    return result


def install_terminal_hook(namespace: dict[str, Any]) -> bool:
    """Install only for the pinned runner; run no observer during its workload."""
    if os.environ.get(OPT_IN) != "1" or namespace.get("__name__") != "__main__":
        return False
    try:
        path = Path(__file__).with_name("guard_command_corpus_runner.py")
        if Path(sys.argv[0]).resolve() != path.resolve():
            return False
        raw = path.read_bytes()
        framed = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        if hashlib.sha1(framed).hexdigest() != RUNNER_BLOB:
            return False
    except (OSError, ValueError, RuntimeError):
        return False
    original = sys.excepthook

    def terminal_hook(kind: type[BaseException], error: BaseException, traceback: TracebackType | None) -> None:
        try:
            value = project_failure(error, traceback, namespace)
            if _valid(value):
                sys.stderr.write(MARKER + json.dumps(value, sort_keys=True) + "\n")
                sys.stderr.flush()
        except BaseException:
            pass
        finally:
            original(kind, error, traceback)

    sys.excepthook = terminal_hook
    return True
