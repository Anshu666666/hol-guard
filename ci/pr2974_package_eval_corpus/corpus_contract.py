"""Run the six unchanged corpus contracts and retain their real pytest reports."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import pwd
import stat
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_text())
ROOT = Path(os.environ["VALIDATION_SOURCE"]).resolve(strict=True)
REPORT = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
TEMP = Path(os.environ["VALIDATION_TEST_TMP"]).resolve(strict=True) / "corpus-contract-temp"
TEST = "tests/test_guard_command_decision_diff.py"
EXPECTED = [TEST + "::" + name for name in CONFIG["corpus_test_functions"]]
SNAPSHOT = REPORT / "corpus-contract-snapshot.json"
JUNIT = REPORT / "corpus-contract-junit.xml"
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
os.chdir(ROOT)

import pytest

state = {"schema": "pr2974-package-corpus-contracts.v1", "root": str(ROOT),
         "source_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"],
         "mutable_report_staging": True, "expected_nodes": EXPECTED, "collection": [],
         "collect_reports": [], "body_reports": [], "source_files": {},
         "terminal": False, "exit_code": None, "qualification_complete": False}


def save() -> None:
    temporary = SNAPSHOT.with_name(SNAPSHOT.name + ".new")
    temporary.write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    temporary.replace(SNAPSHOT)


def source_record(function) -> dict:
    function = inspect.unwrap(function)
    code = getattr(function, "__code__", None)
    if code is None:
        return {"module": getattr(function, "__module__", None),
                "qualname": getattr(function, "__qualname__", None), "python_code": False}
    path = Path(code.co_filename).resolve(strict=True)
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    record = {"path": str(path), "bytes": len(raw), "sha256": digest}
    previous = state["source_files"].setdefault(str(path), record)
    assert previous == record, "Observed source changed"
    destination = REPORT / "observed-source" / (digest + path.suffix)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        assert destination.read_bytes() == raw
    else:
        destination.write_bytes(raw)
    return {**record, "module": function.__module__, "qualname": function.__qualname__,
            "first_line": code.co_firstlineno, "signature": str(inspect.signature(function)),
            "retained_path": str(destination.relative_to(REPORT))}


class Observer:
    def pytest_collectreport(self, report):
        state["collect_reports"].append({"nodeid": report.nodeid, "outcome": report.outcome,
                                        "longrepr": str(report.longrepr) if report.longrepr else None})
        save()

    def pytest_collection_modifyitems(self, session, config, items):
        nodes = [item.nodeid for item in items]
        assert nodes == EXPECTED, nodes
        for item in items:
            source = source_record(item.obj)
            assert source["path"] == str(ROOT / TEST)
            assert source["sha256"] == CONFIG["source_inputs"][TEST]
            assert not getattr(item, "callspec", None), "Original six contracts have no case parameters"
            fixtures = {}
            info = item._fixtureinfo
            for name in info.names_closure:
                fixtures[name] = []
                for definition in info.name2fixturedefs.get(name, ()):
                    fixtures[name].append({
                        "scope": definition.scope, "baseid": definition.baseid,
                        "argnames": list(definition.argnames),
                        "params_repr": repr(definition.params),
                        "source": source_record(definition.func)})
            state["collection"].append({
                "nodeid": item.nodeid, "source": source, "fixturenames": list(item.fixturenames),
                "fixtures": fixtures,
                "marks": [{"name": mark.name, "args_repr": repr(mark.args), "kwargs_repr": repr(mark.kwargs)}
                          for mark in item.iter_markers()]})
        state["collection_complete"] = True
        save()

    def pytest_runtest_setup(self, item):
        assert state.get("collection_complete") is True
        assert [row["nodeid"] for row in state["collection"]] == EXPECTED

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
        test_tmp = Path(os.environ["VALIDATION_TEST_TMP"]).resolve(strict=True)
        real_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        environment_home = Path.home().resolve(strict=True)
        info = test_tmp.lstat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
        assert stat.S_IMODE(info.st_mode) == 0o700 and test_tmp.parent == Path("/tmp").resolve(strict=True)
        assert test_tmp == Path(os.environ["TMPDIR"]).resolve(strict=True)
        assert not test_tmp.is_relative_to(real_home) and not test_tmp.is_relative_to(environment_home)
        assert TEMP.resolve().is_relative_to(test_tmp)
        state["test_temp_root"] = {
            "path": str(test_tmp), "real_home": str(real_home), "environment_home": str(environment_home),
            "uid": info.st_uid, "mode": oct(stat.S_IMODE(info.st_mode)), "outside_home": True,
        }
        args = ["-q", "-m", "", "-p", "no:cacheprovider", "--basetemp", str(TEMP),
                "--junitxml", str(JUNIT), TEST]
        state["pytest_argv"] = args
        exit_code = int(pytest.main(args, plugins=[Observer()]))
        state["exit_code"] = exit_code
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
        state["passed"] = (state["exit_code"] == 0 and state.get("collection_complete") is True
                           and not origin_errors and state["observed_source_files_unchanged"])
        save()
    assert state["passed"], "Corpus contract execution failed; retain original pytest output and snapshot"
    raise SystemExit(state["exit_code"])
