"""Retain one complete invariant-checked collection without executing fixtures."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
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
from full_collection_evidence import CollectionEvidence

PYTEST_TERMINAL_SHA256 = "e2fe406f930e795d09026746e8209a9a7142ac704fc0a0200af9e4f74d2104d0"


def main() -> int:
    output = REPORT / "full-collection.json"
    reports_path = REPORT / "full-collection-reports.jsonl"
    state = {
        "schema": "pr2974-full-current-collection.v2",
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "collection_report_count": 0, "collection_error_count": 0,
        "fixture_or_body_report_count": 0, "deselected_count": 0,
        "completed_collection": False, "invariant_gate_enabled": False,
        "source_unchanged": False, "retention_complete": False,
        "passed": False, "qualification_complete": False,
    }
    write_json(output, state)
    observed.STATE.update(config=CONFIG, source=SOURCE)
    evidence = None
    nodeids, deselected, fixture_reports = [], [], []
    providers, provider_paths = {}, {}
    report_bytes = 0
    report_hasher = hashlib.sha256()
    report_outcomes = {}
    code = 99

    def save():
        if evidence is not None:
            state["retention_progress"] = evidence.snapshot()
        encoded = json.dumps(state, sort_keys=True, indent=2).encode()
        assert len(encoded) <= 16 * 1024 * 1024, "Full collection status bound exceeded"
        write_json(output, state)

    def source_record(path):
        path = path.resolve(strict=True)
        row = observed.source_record(path)
        key = row["origin"] + "/" + row["path"]
        if key in provider_paths:
            assert provider_paths[key]["record"] == row
        else:
            provider_paths[key] = {"path": path, "record": row}
        return row

    def provider_bodies():
        for key, item in provider_paths.items():
            row, path = item["record"], item["path"]
            assert observed.source_record(path) == row
            raw = path.read_bytes()
            assert len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"]
            try:
                content, encoding = raw.decode("utf-8"), "utf-8"
            except UnicodeDecodeError:
                content, encoding = base64.b64encode(raw).decode("ascii"), "base64"
            yield {"key": key, **row, "encoding": encoding, "content": content}

    class Capture:
        def pytest_collectreport(self, report):
            nonlocal report_bytes
            state["collection_report_count"] += 1
            state["collection_error_count"] += int(report.failed)
            assert state["collection_report_count"] <= 60000
            row = {"nodeid": report.nodeid, "outcome": report.outcome,
                   "longrepr": str(report.longrepr) if report.failed or report.skipped else None}
            raw = (json.dumps(row, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True) + "\n").encode("ascii")
            assert report_bytes + len(raw) <= 32 * 1024 * 1024, "Collection report bound exceeded"
            with reports_path.open("ab") as stream:
                assert stream.write(raw) == len(raw)
            report_bytes += len(raw)
            report_hasher.update(raw)
            report_outcomes[report.outcome] = report_outcomes.get(report.outcome, 0) + 1
            if report.failed:
                save()

        def pytest_deselected(self, items):
            deselected.extend(item.nodeid for item in items)
            state["deselected_count"] = len(deselected)
            assert len(deselected) <= 60000
            save()

        def pytest_collection_finish(self, session):
            nodeids.extend(item.nodeid for item in session.items)
            state["collection_failed_count"] = session.testsfailed
            state["collected_count"] = len(nodeids)
            assert evidence is not None
            state["nodeids"] = evidence.write_records("nodeids", nodeids, len(nodeids))
            assert 0 < len(nodeids) <= 60000 and len(nodeids) == len(set(nodeids))
            assert session.config.rootpath.resolve() == SOURCE
            assert session.config.inipath.resolve() == SOURCE / "pyproject.toml"
            assert session.config.option.collectonly is True
            assert session.config.option.markexpr == ""
            assert session.config.option.noconftest is False and session.config.option.confcutdir is None
            assert not session.config.pluginmanager.hasplugin("cacheprovider")
            terminal = session.config.pluginmanager.getplugin("terminalreporter")
            assert terminal is not None
            assert session.config.get_verbosity("test_cases") == -2
            terminal_source = source_record(Path(inspect.getfile(type(terminal))))
            assert terminal_source["origin"] == "owned_dependency"
            assert terminal_source["sha256"] == PYTEST_TERMINAL_SHA256
            state["terminal_reporter_origin"] = terminal_source
            assert session.config.pluginmanager.hasplugin("tests.bundle_first_cloud")
            state["invariant_gate_enabled"] = session.config.getoption("--validate-test-invariants") is True
            assert state["invariant_gate_enabled"]
            from tests.guard_test_invariants import TEST_INVARIANTS

            state["protected_invariants"] = [dataclasses.asdict(item) for item in TEST_INVARIANTS]
            state["missing_invariants"] = [
                item.invariant_id for item in TEST_INVARIANTS
                if not any(node == item.selector or node.startswith(item.selector + "[") for node in nodeids)
            ]
            state["conftests"] = [
                source_record(Path(module.__file__))
                for module in sorted(session.config.pluginmanager._conftest_plugins,
                                     key=lambda module: module.__file__)
            ]
            assert {"conftest.py", "tests/conftest.py"} <= {row["path"] for row in state["conftests"]}
            autouse = set()
            for item in session.items:
                assert item.nodeid.startswith("tests/") and "::" in item.nodeid
                autouse.update(session._fixturemanager._getautousenames(item))
                for name in item.fixturenames:
                    for fixture in item._fixtureinfo.name2fixturedefs.get(name, ()):
                        function = inspect.unwrap(fixture.func)
                        code_object = getattr(function, "__code__", None)
                        assert code_object is not None
                        source = source_record(Path(code_object.co_filename))
                        key = source["origin"] + "/" + source["path"] + "::" + function.__qualname__
                        providers[key] = {**source, "qualname": function.__qualname__,
                                          "scope": fixture.scope, "argnames": list(fixture.argnames)}
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
            fixture_reports.append({"nodeid": report.nodeid, "when": report.when, "outcome": report.outcome})
            state["fixture_or_body_report_count"] = len(fixture_reports)
            assert len(fixture_reports) <= 60000
            save()

    try:
        evidence = CollectionEvidence(REPORT, CONFIG["source_sha"], CONFIG["source_tree"])
        with reports_path.open("xb"):
            pass
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
            "tests", "--collect-only", "--validate-test-invariants", "-qq", "-ra",
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
        module_origins = {}
        try:
            state["source_inputs_after"] = observed.source_admission()
            state["source_unchanged"] = state["source_inputs_after"] == state["source_inputs_before"]
            module_origins = observed.module_origins()
        except BaseException as error:
            state["final_observation_error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
        state["retention_errors"] = []
        if evidence is not None:
            groups = [
                ("deselected_nodeids", deselected, len(deselected)),
                ("fixture_or_body_reports", fixture_reports, len(fixture_reports)),
                ("fixture_provider_origins", ({"key": key, **row} for key, row in providers.items()), len(providers)),
                ("provider_sources", provider_bodies(), len(provider_paths)),
                ("source_module_origins", ({"module": name, **row} for name, row in module_origins.items()),
                 len(module_origins)),
            ]
            if "nodeids" not in evidence.streams:
                groups.insert(0, ("nodeids", nodeids, len(nodeids)))
            for name, rows, count in groups:
                try:
                    state[name] = evidence.write_records(name, rows, count)
                except BaseException:
                    state["retention_errors"].append({"stream": name, "traceback": traceback.format_exc()})
            try:
                state["retention_index"] = evidence.finish()
                state["retention_complete"] = state["retention_index"]["complete"]
                raw = reports_path.read_bytes()
                assert len(raw) == report_bytes <= 32 * 1024 * 1024
                assert raw.count(b"\n") == state["collection_report_count"]
                assert hashlib.sha256(raw).hexdigest() == report_hasher.hexdigest()
                outcomes = {}
                for line in raw.splitlines():
                    report = json.loads(line)
                    outcomes[report["outcome"]] = outcomes.get(report["outcome"], 0) + 1
                assert outcomes == report_outcomes
                assert outcomes.get("failed", 0) == state["collection_error_count"]
                state["collection_reports"] = {
                    "path": reports_path.name, "bytes": len(raw),
                    "sha256": report_hasher.hexdigest(), "records": state["collection_report_count"],
                    "outcomes": outcomes,
                }
            except BaseException:
                state["retention_complete"] = False
                state["retention_errors"].append({"stream": "index_or_reports", "traceback": traceback.format_exc()})
        state["pytest_exit_code"] = code
        state["passed"] = bool(
            code == 0 and state["completed_collection"] and state["invariant_gate_enabled"]
            and state["source_unchanged"] and state["retention_complete"]
            and state["collection_error_count"] == 0 and state["fixture_or_body_report_count"] == 0
            and not state["retention_errors"] and not state.get("error") and not state.get("final_observation_error")
        )
        save()
    return 0 if state["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
