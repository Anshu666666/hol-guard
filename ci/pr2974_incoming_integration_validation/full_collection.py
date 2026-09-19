"""Retain one complete invariant-checked collection without executing fixtures."""

from __future__ import annotations

import dataclasses
import inspect
import json
import os
from pathlib import Path
import sys
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import CONFIG, REPORT, SOURCE, write_json
import collect_controls as observed


def main() -> int:
    output = REPORT / "full-collection.json"
    state = {
        "schema": "pr2974-full-current-collection.v1",
        "source_sha": CONFIG["source_sha"],
        "source_tree": CONFIG["source_tree"],
        "nodeids": [],
        "collection_reports": [],
        "collection_errors": [],
        "fixture_or_body_reports": [],
        "deselected_nodeids": [],
        "completed_collection": False,
        "invariant_gate_enabled": False,
        "source_unchanged": False,
        "passed": False,
        "qualification_complete": False,
    }
    write_json(output, state)
    observed.STATE.update(config=CONFIG, source=SOURCE)
    code = 99

    def save():
        encoded = json.dumps(state, sort_keys=True, indent=2).encode()
        assert len(encoded) <= 16 * 1024 * 1024, "Full collection retention bound exceeded"
        write_json(output, state)

    class Capture:
        def pytest_collectreport(self, report):
            row = {"nodeid": report.nodeid, "outcome": report.outcome}
            state["collection_reports"].append(row)
            if report.failed:
                state["collection_errors"].append({**row, "longrepr": str(report.longrepr)})
            assert len(state["collection_reports"]) <= 60000
            with (REPORT / "full-collection-reports.jsonl").open("a") as stream:
                stream.write(json.dumps({**row, "longrepr": str(report.longrepr) if report.failed or report.skipped else None}) + "\n")
            if report.failed:
                save()

        def pytest_deselected(self, items):
            state["deselected_nodeids"].extend(item.nodeid for item in items)
            save()

        def pytest_collection_finish(self, session):
            state["nodeids"] = [item.nodeid for item in session.items]
            state["collection_failed_count"] = session.testsfailed
            state["collected_count"] = len(session.items)
            assert 0 < len(session.items) <= 60000
            assert len(state["nodeids"]) == len(set(state["nodeids"]))
            assert session.config.rootpath.resolve() == SOURCE
            assert session.config.inipath.resolve() == SOURCE / "pyproject.toml"
            assert session.config.option.collectonly is True
            assert session.config.option.markexpr == ""
            assert session.config.option.noconftest is False and session.config.option.confcutdir is None
            assert not session.config.pluginmanager.hasplugin("cacheprovider")
            assert session.config.pluginmanager.hasplugin("terminalreporter")
            assert session.config.pluginmanager.hasplugin("tests.bundle_first_cloud")
            state["invariant_gate_enabled"] = session.config.getoption("--validate-test-invariants") is True
            assert state["invariant_gate_enabled"]
            from tests.guard_test_invariants import TEST_INVARIANTS

            state["protected_invariants"] = [dataclasses.asdict(item) for item in TEST_INVARIANTS]
            state["missing_invariants"] = [
                item.invariant_id for item in TEST_INVARIANTS
                if not any(node == item.selector or node.startswith(item.selector + "[")
                           for node in state["nodeids"])
            ]
            state["conftests"] = [
                observed.source_record(Path(module.__file__))
                for module in sorted(session.config.pluginmanager._conftest_plugins,
                                     key=lambda module: module.__file__)
            ]
            assert {"conftest.py", "tests/conftest.py"} <= {row["path"] for row in state["conftests"]}
            providers = {}
            autouse = set()
            for item in session.items:
                assert item.nodeid.startswith("tests/") and "::" in item.nodeid
                autouse.update(session._fixturemanager._getautousenames(item))
                for name in item.fixturenames:
                    for fixture in item._fixtureinfo.name2fixturedefs.get(name, ()):
                        function = inspect.unwrap(fixture.func)
                        code_object = getattr(function, "__code__", None)
                        assert code_object is not None
                        source = observed.source_record(Path(code_object.co_filename))
                        key = source["origin"] + "/" + source["path"] + "::" + function.__qualname__
                        providers[key] = {**source, "qualname": function.__qualname__,
                                          "scope": fixture.scope, "argnames": list(fixture.argnames)}
            state["fixture_provider_origins"] = providers
            state["autouse_names"] = sorted(autouse)
            assert "_spawn_package_shim_sqlite_lock_holder" in autouse
            assert not state["missing_invariants"]
            state["sys_path_after_collection"] = list(sys.path)
            state["completed_collection"] = True
            save()

        def pytest_runtest_protocol(self, item, nextitem):
            raise AssertionError("Full collection must not execute a test protocol")

        def pytest_fixture_setup(self, fixturedef, request):
            raise AssertionError("Full collection must not execute a fixture")

        def pytest_runtest_logreport(self, report):
            state["fixture_or_body_reports"].append(
                {"nodeid": report.nodeid, "when": report.when, "outcome": report.outcome}
            )
            save()

    try:
        assert sys.flags.isolated and sys.dont_write_bytecode and __debug__
        assert sys.version.split()[0] == CONFIG["python_version"]
        assert Path(sys.executable).resolve() == Path(os.environ["VALIDATION_PYTHON"]).resolve()
        assert os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
        assert os.environ.get("PYTEST_ADDOPTS", "") == ""
        assert Path.cwd().resolve() == SOURCE
        state["source_inputs_before"] = observed.source_admission()
        assert not any(name == "pytest" or name.split(".", 1)[0] in {"codex_plugin_scanner", "scripts", "tests", "ci"}
                       for name in sys.modules)
        sys.path[:0] = [str(SOURCE / "src"), str(SOURCE)]
        import pytest

        assert pytest.__version__ == CONFIG["installed_versions"]["pytest"]
        pytest.hookimpl(tryfirst=True)(Capture.pytest_runtest_protocol)
        pytest.hookimpl(tryfirst=True)(Capture.pytest_fixture_setup)
        arguments = [
            "tests", "--collect-only", "--validate-test-invariants", "-q", "-ra",
            "-m", "", "-p", "no:cacheprovider",
            "--basetemp", str(Path(os.environ["VALIDATION_TEST_TMP"]) / "full-current-collection"),
            "--junitxml", str(REPORT / "full-collection.xml"),
        ]
        state["pytest_argv"] = arguments
        save()
        code = int(pytest.main(arguments, plugins=[Capture()]))
    except BaseException as error:
        state["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
    finally:
        try:
            state["source_inputs_after"] = observed.source_admission()
            state["source_unchanged"] = state["source_inputs_after"] == state["source_inputs_before"]
            state["source_module_origins"] = observed.module_origins()
        except BaseException as error:
            state["final_observation_error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
        state["pytest_exit_code"] = code
        state["passed"] = bool(
            code == 0 and state["completed_collection"] and state["invariant_gate_enabled"]
            and state["source_unchanged"] and not state["collection_errors"]
            and not state["fixture_or_body_reports"] and not state.get("error")
            and not state.get("final_observation_error")
        )
        save()
    return 0 if state["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
