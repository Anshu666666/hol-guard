"""Observe the unchanged existing test's subprocess returns without altering them."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text())
OUTPUT = Path(os.environ["BUDGET_CAPTURE"])
SOURCE = Path(os.environ["BUDGET_SOURCE"]).resolve()
SETTINGS = ("PYTHONHASHSEED", "TZ", "LC_ALL", "GUARD_PYTEST_UNDER_COVERAGE",
            "HOL_GUARD_NATIVE", "HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE",
            "HOL_GUARD_NATIVE_DIAGNOSTIC", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE")
RESULTS: list[dict[str, object]] = []
NODES: list[str] = []
REPORTS: list[dict[str, object]] = []


def save() -> None:
    payload = {"source_sha": os.environ["BUDGET_SOURCE_SHA"], "nodeids": NODES,
               "subprocess_results": RESULTS, "pytest_reports": REPORTS,
               "qualification_complete": False}
    target = OUTPUT.with_name(OUTPUT.name + ".new")
    target.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
    target.replace(OUTPUT)


def pytest_collection_finish(session: pytest.Session) -> None:
    NODES.extend(item.nodeid for item in session.items)
    save()
    if NODES != [CONFIG["selector"]]:
        raise pytest.UsageError("Unexpected paired diagnostic collection")


class SubprocessView:
    def __init__(self, original: object) -> None:
        self.original = original

    def __getattr__(self, name: str) -> object:
        return getattr(self.original, name)

    def run(self, *args: object, **kwargs: object) -> object:
        expected = [sys.executable, str(SOURCE / "tests/guard_command_decision_diff.py"), "--metrics"]
        assert args and list(args[0]) == expected
        assert kwargs["check"] is True and kwargs["capture_output"] is True
        assert kwargs["timeout"] == CONFIG["child_timeout_seconds"] == 75
        assert len(RESULTS) < 2, "Refuse extra metric invocation"
        env = kwargs["env"]
        row = {"index": len(RESULTS), "command": expected, "timeout_seconds": kwargs["timeout"],
               "selected_environment": {name: env.get(name) for name in SETTINGS},
               "status": "started", "returned": False}
        RESULTS.append(row)
        save()
        started = time.monotonic()
        try:
            result = self.original.run(*args, **kwargs)
            row.update(returned=True, returncode=result.returncode, status="returned")
            for name in ("stdout", "stderr"):
                data = getattr(result, name)
                if isinstance(data, str):
                    data = data.encode()
                path = OUTPUT.with_name(OUTPUT.stem + "-" + str(row["index"]) + "." + name)
                path.write_bytes(data)
                row[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                             "file": path.name}
            row["metrics"] = json.loads(result.stdout)
            return result
        except BaseException as error:
            row.update(status="raised", exception_type=type(error).__name__)
            if isinstance(error, (subprocess.TimeoutExpired, subprocess.CalledProcessError)):
                row["timeout_seconds"] = getattr(error, "timeout", row["timeout_seconds"])
                row["returncode"] = getattr(error, "returncode", None)
                for name in ("stdout", "stderr"):
                    data = getattr(error, name, None)
                    if data is not None:
                        if isinstance(data, str):
                            data = data.encode()
                        path = OUTPUT.with_name(OUTPUT.stem + "-" + str(row["index"]) + "." + name)
                        path.write_bytes(data)
                        row[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                                     "file": path.name}
            raise
        finally:
            row["external_wall_seconds"] = time.monotonic() - started
            save()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: pytest.Item):
    assert item.nodeid == CONFIG["selector"]
    original = item.module.subprocess
    item.module.subprocess = SubprocessView(original)
    try:
        yield
    finally:
        item.module.subprocess = original
        save()


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    REPORTS.append({"nodeid": report.nodeid, "when": report.when, "outcome": report.outcome,
                    "duration_seconds": report.duration})
    save()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    save()
