"""Observe complete selected modules and separate harness controls using actual pytest items."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_text())
ROOT = Path(os.environ["VALIDATION_SOURCE"]).resolve(strict=True)
REPORT = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
TEST_TMP = Path(os.environ["VALIDATION_TEST_TMP"]).resolve(strict=True)
GROUP = sys.argv[1]
SPEC = CONFIG["finite_groups"][GROUP]
SNAPSHOT = REPORT / (GROUP + "-snapshot.json")
JUNIT = REPORT / (GROUP + "-junit.xml")
PATHS = {
    str((HERE if row["harness"] else ROOT) / row["path"]): row
    for row in SPEC["files"]
}
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
os.chdir(ROOT)

import pytest

state = {"schema": "pr2974-ci-repair-finite.v1", "group": GROUP, "root": str(ROOT),
         "source_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"],
         "mutable_report_staging": True, "collection": [], "collect_reports": [],
         "body_reports": [], "source_files": {}, "terminal": False, "exit_code": None,
         "qualification_complete": False}


def save():
    temporary = SNAPSHOT.with_name(SNAPSHOT.name + ".new")
    temporary.write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    temporary.replace(SNAPSHOT)


def source_record(function):
    function = inspect.unwrap(function)
    code = getattr(function, "__code__", None)
    if code is None:
        return {"module": getattr(function, "__module__", None),
                "qualname": getattr(function, "__qualname__", None), "python_code": False}
    path = Path(code.co_filename).resolve(strict=True)
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    row = {"path": str(path), "sha256": digest, "bytes": len(raw)}
    previous = state["source_files"].setdefault(str(path), row)
    assert previous == row, "Observed source changed"
    retained = REPORT / "observed-source" / (digest + path.suffix)
    retained.parent.mkdir(parents=True, exist_ok=True)
    if retained.exists():
        assert retained.read_bytes() == raw
    else:
        retained.write_bytes(raw)
    return {**row, "module": function.__module__, "qualname": function.__qualname__,
            "first_line": code.co_firstlineno, "retained_path": str(retained.relative_to(REPORT))}


class Observer:
    def pytest_collectreport(self, report):
        state["collect_reports"].append({
            "nodeid": report.nodeid, "outcome": report.outcome,
            "longrepr": str(report.longrepr) if report.longrepr else None})
        save()

    def pytest_collection_modifyitems(self, session, config, items):
        seen = {path: set() for path in PATHS}
        for item in items:
            source = source_record(item.obj)
            path = source["path"]
            assert path in PATHS, path
            spec = PATHS[path]
            assert source["sha256"] == spec["sha256"], path
            original_name = item.originalname or item.name
            assert original_name in spec["functions"], original_name
            seen[path].add(original_name)
            fixtures = {}
            info = item._fixtureinfo
            for name in info.names_closure:
                fixtures[name] = [
                    {"scope": definition.scope, "baseid": definition.baseid,
                     "argnames": list(definition.argnames), "params_repr": repr(definition.params),
                     "source": source_record(definition.func)}
                    for definition in info.name2fixturedefs.get(name, ())]
            state["collection"].append({
                "nodeid": item.nodeid, "source": source, "original_name": original_name,
                "fixturenames": list(item.fixturenames), "fixtures": fixtures,
                "callspec": {name: repr(value) for name, value in getattr(item, "callspec", {}).params.items()}
                if getattr(item, "callspec", None) else None,
                "marks": [{"name": mark.name, "args_repr": repr(mark.args),
                           "kwargs_repr": repr(mark.kwargs)} for mark in item.iter_markers()]})
        assert items and len({item.nodeid for item in items}) == len(items)
        for path, names in seen.items():
            assert names == set(PATHS[path]["functions"]), (path, names)
        if SPEC.get("exact_case_count") is not None:
            assert len(items) == SPEC["exact_case_count"]
        state["collection_complete"] = True
        save()

    def pytest_runtest_setup(self, item):
        assert state.get("collection_complete") is True

    def pytest_runtest_logreport(self, report):
        state["body_reports"].append({
            "nodeid": report.nodeid, "phase": report.when, "outcome": report.outcome,
            "wasxfail": getattr(report, "wasxfail", None), "duration": report.duration,
            "longrepr": str(report.longrepr) if report.longrepr else None,
            "sections": list(report.sections)})
        save()



if __name__ == "__main__":
    save()
    try:
        args = ["-q", "-m", "", "-p", "no:cacheprovider", "--rootdir", str(ROOT),
                "--basetemp", str(TEST_TMP / (GROUP + "-temp")),
                "--junitxml", str(JUNIT), *PATHS]
        state["pytest_argv"] = args
        state["exit_code"] = int(pytest.main(args, plugins=[Observer()]))
    finally:
        state["terminal"] = True
        origin_errors = []
        for name, module in list(sys.modules.items()):
            if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.") or name == "tests" or name.startswith("tests."):
                filename = getattr(module, "__file__", None)
                if filename:
                    path = Path(filename).resolve(strict=True)
                    if not path.is_relative_to(ROOT):
                        origin_errors.append({"module": name, "path": str(path)})
        state["origin_errors"] = origin_errors
        state["observed_source_files_unchanged"] = all(
            hashlib.sha256(Path(path).read_bytes()).hexdigest() == row["sha256"]
            for path, row in state["source_files"].items())
        cases = ET.parse(JUNIT).getroot().findall(".//testcase") if JUNIT.is_file() else []
        counts = {"tests": len(cases), "failed": sum(case.find("failure") is not None for case in cases),
                  "errored": sum(case.find("error") is not None for case in cases),
                  "skipped": sum(case.find("skipped") is not None for case in cases)}
        counts["passed"] = counts["tests"] - counts["failed"] - counts["errored"] - counts["skipped"]
        state["counts"] = counts
        grouped = {row["nodeid"]: [] for row in state["collection"]}
        for row in state["body_reports"]:
            assert row["nodeid"] in grouped
            grouped[row["nodeid"]].append(row)
        state["all_setup_call_teardown_passed"] = bool(grouped) and all(
            [row["phase"] for row in rows] == ["setup", "call", "teardown"]
            and all(row["outcome"] == "passed" and row["wasxfail"] is None for row in rows)
            for rows in grouped.values())
        state["passed"] = (
            state["exit_code"] == 0 and state.get("collection_complete") is True
            and not origin_errors and state["observed_source_files_unchanged"]
            and counts["tests"] == len(state["collection"]) and not counts["failed"] and not counts["errored"]
            and all(row["wasxfail"] is None for row in state["body_reports"])
            and (not SPEC["require_every_case_passed"] or state["all_setup_call_teardown_passed"]))
        save()
    assert state["passed"], "Finite cohort failed; retain actual collection, body records and JUnit"
    raise SystemExit(state["exit_code"])
