"""Keep the original corpus outcome and expose only a finite terminal marker."""

from __future__ import annotations

import json
import subprocess
from contextlib import suppress
from pathlib import Path

import pytest

from tests.guard_corpus_failure_diagnostic import read_marker

NODE = "tests/test_guard_command_corpus.py::test_full_guard_evaluation_matches_exact_non_widening_known_gap_baseline"
RESULT = Path(".corpus-terminal-result.json")
_summary: dict[str, object] = {"schema": 1, "observed": False, "passed": False, "failure": None}


def pytest_collection_finish(session):
    if [item.nodeid for item in session.items] != [NODE]:
        raise pytest.UsageError("corpus diagnostic requires exactly the original node")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if item.nodeid != NODE or call.when != "call":
        return
    _summary["observed"] = True
    _summary["passed"] = report.passed
    failure = None
    if call.excinfo is not None and type(call.excinfo.value) is subprocess.CalledProcessError:
        failure = read_marker(call.excinfo.value.stderr)
    _summary["failure"] = failure
    report.sections.append(("finite corpus terminal evidence", json.dumps(_summary, sort_keys=True)))


def pytest_sessionfinish(session, exitstatus):
    _summary["pytestExit"] = int(exitstatus)
    with suppress(OSError):
        RESULT.write_text(json.dumps(_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
