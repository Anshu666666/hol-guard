"""Observe exact collection; allow candidate execution only after matching its prior snapshot."""

from __future__ import annotations

import argparse
import ast
import builtins
import hashlib
import importlib
import inspect
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_definition_contract import callable_source, source_file
from source_repair_bridge import CONTRACT_SHA256, verify_source as verify_repaired_source

INPUT_COMMIT = "ad40ceec7c9eb3ee50cffff827db8f54c7522fb1"
BASELINE_COMMIT = "44353b20262f1ca56b56204f4c764b047710454f"
CANDIDATE_COMMIT = "1578e609636cf0460b23dfbe083759097a635be0"
CANDIDATE_TREE = "4a7ea105c53d0eb68ed8a037e3e38288b32ff407"
RECONSTRUCTION_SHA256 = "c0573d781b5e95c4e085287a8f172d35b56e05706a3e2f488c480eca416f0256"
HELPER_SHA256 = "273a0f96c5f5474bde91c58240596e8f9607135f8ee39330f1fd29e051413adb"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    data = Path(path).read_bytes()
    return data, json.loads(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--reconstruction-receipt", required=True)
    parser.add_argument("--repaired-candidate-root", required=True)
    parser.add_argument("--side", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--lane", choices=("protect", "codex"), required=True)
    parser.add_argument("--cases", choices=("existing", "candidate-only"), required=True)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--junit")
    parser.add_argument("--prior-snapshot")
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--basetemp", required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve(strict=True)
    output = Path(args.snapshot).resolve()
    assert not output.is_relative_to(root)
    assert not Path(args.basetemp).resolve().is_relative_to(root)
    assert not Path(__file__).resolve().is_relative_to(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "schema": "pr2974-protect-codex-collection-observation-v1",
        "root": str(root), "side": args.side, "lane": args.lane, "cases": args.cases,
        "mode": "candidate_execution" if args.run else "collection_only",
        "started": time.time(), "terminal": False, "collection_complete": False,
        "comparison": [], "raw_origins": [], "source_files": {}, "approved_export_origins": {},
        "verified_checkout_file_global_origins": {},
        "module_origins": {}, "collect_reports": [], "body_reports": [], "refused_execution": [],
        "errors": [], "exit_code": None, "test_path_normalization": None,
        "test_execution_credit": False, "qualification_complete": False,
    }

    def save():
        temporary = output.with_name(output.name + ".new")
        temporary.write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
        temporary.replace(output)

    def git(*command):
        return subprocess.check_output(["git", *command], cwd=root, stderr=subprocess.PIPE, timeout=60)

    def record_source(source):
        path = source.path
        key = str(path)
        if path.is_relative_to(root):
            relative = path.relative_to(root).as_posix()
            expected = git("show", state["source_commit"] + ":" + relative)
            assert source.raw == expected, ("Source bytes differ from immutable commit", relative)
            key = relative
        row = {"path": str(path), "sha256": source.sha256, "bytes": len(source.raw)}
        old = state["source_files"].get(key)
        assert old is None or old == row, key
        state["source_files"][key] = row
        return key

    save()
    try:
        assert sys.flags.isolated == 1 and sys.dont_write_bytecode is True, "Use the owned Python with -I -B"
        manifest_bytes, manifest = read_json(args.manifest)
        state["manifest_sha256"] = sha(manifest_bytes)
        assert manifest["baseline_commit"] == BASELINE_COMMIT
        assert manifest["unformatted_candidate_commit"] == INPUT_COMMIT
        candidate = manifest["candidate_commit"]
        assert candidate == CANDIDATE_COMMIT, "Refuse an absent or unreviewed corrected candidate"
        assert manifest["candidate_tree"] == CANDIDATE_TREE
        assert manifest["candidate_parent"] == BASELINE_COMMIT
        repaired_root = Path(args.repaired_candidate_root).resolve(strict=True)
        assert repaired_root == root if args.side == "candidate" else repaired_root != root
        assert not Path(__file__).resolve().is_relative_to(repaired_root)
        assert manifest["source_repair_contract_sha256"] == CONTRACT_SHA256
        repair_module = Path(__file__).resolve().with_name("source_repair_bridge.py")
        assert sha(repair_module.read_bytes()) == manifest["source_repair_bridge_sha256"]
        historical_files, repair_report = verify_repaired_source(
            repaired_root, Path(__file__).resolve().with_name("source-repair-contract.json"),
            Path(args.reconstruction_receipt),
        )
        assert repair_report["candidate_commit"] == candidate and repair_report["candidate_tree"] == CANDIDATE_TREE
        state["source_repair"] = repair_report
        reconstruction_bytes, reconstruction = read_json(args.reconstruction_receipt)
        assert sha(reconstruction_bytes) == manifest["reconstruction_receipt_sha256"] == RECONSTRUCTION_SHA256
        assert reconstruction["source_commit"] == INPUT_COMMIT
        assert reconstruction["independently_verified_post_format_tree"] == repair_report["reconstructed_historical_tree"]
        assert reconstruction["input_tree"] == "2780b299c076a736208efa70ae864d618a856648"
        assert reconstruction["actual_run_conclusion"] == "success"
        assert reconstruction["all_actual_job_steps_succeeded"] is True
        assert reconstruction["all_nonformat_paths_and_modes_unchanged"] is True
        assert reconstruction["all_33_payload_sha256_and_git_blobs_independently_verified"] is True
        assert reconstruction["full_tracked_files"] == 4574 and reconstruction["complete_payload_file_count"] == 33
        outcome = reconstruction["actual_driver_outcome"]
        assert outcome["passed"] is True and outcome["source_unchanged"] is True and outcome["error"] is None
        assert outcome["source_sha"] == INPUT_COMMIT
        assert all(row["passed"] is True and row["returncode"] == 0 and not row["timed_out"]
                   for row in outcome["steps"])
        assert reconstruction["output_files"] == manifest["formatted_output_files"]
        state["source_bridge"] = {
            "reconstruction_receipt_sha256": sha(reconstruction_bytes), "input_commit": INPUT_COMMIT,
            "candidate_commit": candidate, "candidate_tree": CANDIDATE_TREE,
            "historical_formatted_commit": repair_report["historical_formatted_commit"],
            "historical_formatted_tree": repair_report["reconstructed_historical_tree"],
            "current_source_bound_through_reviewed_repair_inverse": True,
            "raw_formatter_harvest_file_extracted": False,
            "actual_driver_outcome": outcome, "actual_run_id": reconstruction["run_id"],
        }
        final_files = manifest["candidate_source_files"] | manifest["candidate_only_test_source"]
        assert set(manifest["candidate_source_files"]) == set(manifest["input_source_files"])
        assert set(manifest["candidate_only_test_source"]) == set(manifest["candidate_only_unformatted_test_source"])
        for path, metadata in final_files.items():
            assert reconstruction["output_files"][path]["sha256"] == historical_files[path]["sha256"], path
            assert sha((repaired_root / path).read_bytes()) == metadata["sha256"], path
        bridges = reconstruction["actual_32_ast_literal_token_comment_bridges"]
        assert len(bridges) == 32 and len({row["path"] for row in bridges}) == 32
        bridge_rows = {row["path"]: row for row in bridges}
        for row in bridges:
            output_record = reconstruction["output_files"][row["path"]]
            assert row["before_sha256"] == output_record["input_sha256"]
            assert row["after_sha256"] == output_record["sha256"]
            assert all(row[key] is True for key in (
                "passed", "full_ast_equal_including_type_comments_and_type_ignore_line_fields",
                "canonical_tokens_equal", "comments_and_statement_token_anchors_equal", "within_500_physical_lines",
            )), row["path"]
        for path, metadata in final_files.items():
            row = bridge_rows[path]
            original = (manifest["input_source_files"] | manifest["candidate_only_unformatted_test_source"])[path]
            assert row["before_sha256"] == original["sha256"] and row["after_sha256"] == historical_files[path]["sha256"], path
        expected_commit = BASELINE_COMMIT if args.side == "baseline" else candidate
        state["source_commit"] = expected_commit
        assert git("rev-parse", "HEAD").decode().strip() == expected_commit
        state["source_tree"] = git("rev-parse", "HEAD^{tree}").decode().strip()
        if args.side == "candidate":
            assert state["source_tree"] == manifest["candidate_tree"]
            parents = [line[7:] for line in git("cat-file", "-p", candidate).decode().split("\n\n", 1)[0].splitlines()
                       if line.startswith("parent ")]
            assert parents == [BASELINE_COMMIT], parents
            state["candidate_parents"] = parents
        assert not git("status", "--porcelain", "--untracked-files=no").strip()
        helper = Path(__file__).resolve().with_name("source_definition_contract.py")
        assert sha(helper.read_bytes()) == HELPER_SHA256
        state["helper_sha256"] = HELPER_SHA256
        state["observer_sha256"] = sha(Path(__file__).resolve().read_bytes())
        prior = None
        if args.run:
            assert args.side == "candidate" and args.junit and args.prior_snapshot
            assert not Path(args.junit).resolve().is_relative_to(root)
            prior_bytes, prior = read_json(args.prior_snapshot)
            assert prior["passed"] is True and prior["terminal"] is True and prior["exit_code"] == 0
            assert prior["mode"] == "collection_only" and prior["side"] == "candidate"
            assert prior["lane"] == args.lane and prior["cases"] == args.cases
            assert prior["source_commit"] == candidate and prior["source_tree"] == CANDIDATE_TREE
            assert prior["manifest_sha256"] == state["manifest_sha256"]
            assert prior["helper_sha256"] == HELPER_SHA256
            assert prior["observer_sha256"] == state["observer_sha256"]
            assert prior["observed_source_files_unchanged"] is True
            assert prior["source_repair"] == state["source_repair"]
            assert not prior["body_reports"] and not prior["refused_execution"] and not prior["errors"]
            state["prior_collection_sha256"] = sha(prior_bytes)
        else:
            assert args.junit is None and args.prior_snapshot is None
        for path, metadata in manifest["unchanged_test_source_hashes"].items():
            assert sha(git("show", BASELINE_COMMIT + ":" + path)) == metadata["sha256"], path
            assert sha(git("show", expected_commit + ":" + path)) == metadata["sha256"], path
        for path, metadata in (final_files if args.side == "candidate" else manifest["baseline_source_files"]).items():
            assert sha((root / path).read_bytes()) == metadata["sha256"], path
        lane = manifest["lanes"][args.lane]
        if args.cases == "candidate-only":
            assert args.side == "candidate" and args.lane == "protect"
            selectors = lane["candidate_only_selectors"]
        else:
            selectors = lane["existing_selectors"]
        expected_count = sum(row["expected_cases"] for row in selectors)
        assert expected_count == (10 if args.cases == "candidate-only" else lane["expected_existing_cases"])
        tests = [row["selector"] for row in selectors]
        assert tests and len(tests) == len(set(tests))
        selected_paths = {selector.split("::", 1)[0] for selector in tests}
        for path in selected_paths:
            record_source(source_file(str(root / path)))
        state["selectors"] = selectors
        state["expected_cases"] = expected_count
        state["python"] = {"version": sys.version, "executable": sys.executable,
                           "sha256": sha(Path(sys.executable).resolve().read_bytes())}
        os.chdir(root)
        sys.dont_write_bytecode = True
        sys.path[:0] = [str(root), str(root / "src"), str(root / "tests/support")]
        import pytest

        state["pytest_version"] = pytest.__version__
        approved = {}
        export_objects = {}

        def raw_function(function):
            source, raw, definition = callable_source(function)
            path = record_source(source)
            return raw, {
                "module": raw.__module__, "qualname": raw.__qualname__,
                "source_path": path, "source_sha256": source.sha256,
                "code_filename": raw.__code__.co_filename, "code_qualname": raw.__code__.co_qualname,
                "code_firstlineno": raw.__code__.co_firstlineno,
                "decorator_start": definition["decorator_start"], "defline": definition["defline"],
                "ast": ast.dump(definition["node"], include_attributes=False),
                "tokens": source.tokens_for(definition["node"]), "signature": str(inspect.signature(raw)),
            }

        for entry in manifest["approved_export_map"]:
            key = entry["facade_module"] + "." + entry["facade_attribute"]
            assert key not in approved
            owner = importlib.import_module(entry["facade_module"])
            parts = entry["facade_attribute"].split(".")
            for part in parts[:-1]:
                owner = getattr(owner, part)
            descriptor = inspect.getattr_static(owner, parts[-1])
            assert isinstance(descriptor, staticmethod) is entry["static_descriptor"], key
            value = getattr(owner, parts[-1])
            raw, evidence = raw_function(value)
            expected_module = entry["facade_module"] if args.side == "baseline" else entry["candidate_module"]
            expected_qualname = entry["original_qualname"] if args.side == "baseline" else entry["candidate_qualname"]
            expected_path = entry["original_source"] if args.side == "baseline" else entry["candidate_source"]
            assert (evidence["module"], evidence["qualname"], evidence["source_path"]) == (
                expected_module, expected_qualname, expected_path), key
            if args.side == "candidate":
                provider = importlib.import_module(entry["candidate_module"])
                provider_value = provider
                for part in entry["candidate_qualname"].split("."):
                    provider_value = getattr(provider_value, part)
                assert value is provider_value, key
            assert id(raw) not in export_objects, ("Repeated approved callable identity", key)
            export_objects[id(raw)] = key
            approved[key] = entry
            state["approved_export_origins"][key] = evidence | {
                "facade_object_identity_verified": True, "static_descriptor": entry["static_descriptor"],
                "explicit_receiver_annotation": entry["explicit_receiver_annotation"],
            }
        assert len(approved) == 93

        def function_evidence(function):
            raw, evidence = raw_function(function)
            if id(raw) in export_objects:
                return {"approved_live_facade_export": export_objects[id(raw)]}
            return {"function": raw.__module__ + "." + raw.__qualname__, "ast": evidence["ast"],
                    "signature": evidence["signature"]}

        def module_evidence(module):
            filename = getattr(module, "__file__", None)
            if filename:
                path = Path(filename).resolve(strict=True)
                data = path.read_bytes()
                if path.is_relative_to(root):
                    assert data == git("show", expected_commit + ":" + path.relative_to(root).as_posix())
                state["module_origins"][module.__name__] = {"path": str(path), "sha256": sha(data)}
            return {"module": module.__name__}

        def stable(value):
            if value is None or type(value) in (bool, int, float, str):
                return value
            if isinstance(value, bytes):
                return {"bytes_hex": value.hex()}
            if isinstance(value, Path):
                return {"path": str(value)}
            if isinstance(value, (list, tuple)):
                return {"type": type(value).__name__, "items": [stable(item) for item in value]}
            if isinstance(value, (set, frozenset)):
                rows = [stable(item) for item in value]
                return {"type": type(value).__name__, "items": sorted(rows, key=lambda item: json.dumps(item, sort_keys=True))}
            if isinstance(value, dict):
                return {"mapping": sorted([[stable(key), stable(item)] for key, item in value.items()],
                                          key=lambda item: json.dumps(item[0], sort_keys=True))}
            if inspect.ismodule(value):
                return module_evidence(value)
            if inspect.isfunction(value) or inspect.ismethod(value):
                return function_evidence(value)
            if inspect.isclass(value) or inspect.isbuiltin(value):
                return {"object": value.__module__ + "." + value.__qualname__}
            raise TypeError("Unreviewed collection value: " + type(value).__module__ + "." + type(value).__qualname__)

        def global_evidence(function):
            source, raw, definition = callable_source(function)
            record_source(source)
            imported = {}
            for node in source.tree.body:
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.asname or alias.name.split(".")[0]
                        assert name not in imported
                        imported[name] = ("import", alias.name, alias.asname)
                elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
                    assert node.level == 0
                    for alias in node.names:
                        assert alias.name != "*"
                        name = alias.asname or alias.name
                        assert name not in imported
                        imported[name] = ("from", node.module, alias.name)
            result = {}
            for name in source.globals_for(definition):
                if name not in raw.__globals__:
                    assert hasattr(builtins, name), name
                    result[name] = {"builtin": name}
                    continue
                value = raw.__globals__[name]
                binding = imported.get(name)
                if name == "__file__":
                    relative = "tests/test_guard_codex_install.py"
                    module_name = "tests.test_guard_codex_install"
                    function_name = "test_guard_install_codex_rewrites_workspace_config_with_proxy_entries"
                    expected_hash = "c33b4d09346881fa8fc88c070c6e7f6edf8fa2216fd47401f168651cde96b8e5"
                    expected_path = (root / relative).resolve(strict=True)
                    assert args.lane == "codex" and binding is None
                    assert raw.__module__ == module_name and raw.__qualname__ == function_name
                    assert definition["qualname"] == function_name and source.path == expected_path
                    assert source.sha256 == manifest["unchanged_test_source_hashes"][relative]["sha256"] == expected_hash
                    owner = sys.modules[module_name]
                    assert raw.__globals__ is vars(owner)
                    assert type(value) is str and value == str(expected_path) == owner.__file__
                    assert raw.__code__.co_filename == value
                    identity = {"relative_path": relative, "source_sha256": source.sha256, "module": module_name}
                    key = module_name + "." + function_name + ".__file__"
                    evidence = identity | {"actual_global_value": value, "actual_code_filename": raw.__code__.co_filename}
                    previous = state["verified_checkout_file_global_origins"].get(key)
                    assert previous is None or previous == evidence
                    state["verified_checkout_file_global_origins"][key] = evidence
                    result[name] = {"verified_checkout_source_file": identity}
                    continue
                if binding is not None:
                    kind, module, member = binding
                    provider = importlib.import_module(module if kind == "from" or member else module.split(".")[0])
                    expected = getattr(provider, member) if kind == "from" else provider
                    assert value is expected, ("Imported object changed", name, binding)
                    result[name] = {"import_binding": list(binding), "value": stable(value)}
                else:
                    result[name] = stable(value)
            return result

        def refuse(phase, nodeid=""):
            if args.run:
                assert state.get("execution_collection_matches_prior") is True, "Execution collection is not admitted"
                return
            state["refused_execution"].append({"phase": phase, "nodeid": nodeid})
            save()
            raise RuntimeError("Collection-only observer refuses " + phase)

        class Snapshot:
            @pytest.hookimpl(tryfirst=True)
            def pytest_runtest_protocol(self, item, nextitem):
                refuse("runtest protocol", item.nodeid)

            @pytest.hookimpl(tryfirst=True)
            def pytest_runtest_setup(self, item):
                refuse("test setup", item.nodeid)

            @pytest.hookimpl(tryfirst=True)
            def pytest_fixture_setup(self, fixturedef, request):
                refuse("fixture setup: " + fixturedef.argname, request.node.nodeid)

            @pytest.hookimpl(tryfirst=True)
            def pytest_runtest_call(self, item):
                refuse("test body", item.nodeid)

            @pytest.hookimpl(tryfirst=True)
            def pytest_pyfunc_call(self, pyfuncitem):
                refuse("Python test call", pyfuncitem.nodeid)

            @pytest.hookimpl(tryfirst=True)
            def pytest_runtest_teardown(self, item, nextitem):
                refuse("test teardown", item.nodeid)

            def pytest_internalerror(self, excrepr, excinfo):
                state["errors"].append({"type": "pytest_internalerror", "message": str(excrepr)})
                save()

            def pytest_keyboard_interrupt(self, excinfo):
                state["errors"].append({"type": "keyboard_interrupt", "message": str(excinfo)})
                save()

            def pytest_collectreport(self, report):
                state["collect_reports"].append({
                    "nodeid": report.nodeid, "outcome": report.outcome,
                    "longrepr": str(report.longrepr) if report.failed or report.skipped else None,
                })

            def pytest_runtest_logreport(self, report):
                state["body_reports"].append({
                    "nodeid": report.nodeid, "phase": report.when, "outcome": report.outcome,
                    "duration": report.duration, "wasxfail": getattr(report, "wasxfail", None),
                    "longrepr": str(report.longrepr) if report.failed or report.skipped else None,
                })
                save()

            @pytest.hookimpl(trylast=True)
            def pytest_collection_finish(self, session):
                rows, origins, counts, raw_nodes = [], [], {selector: 0 for selector in tests}, []
                state["comparison"], state["raw_origins"] = rows, origins
                manager = session._fixturemanager
                for item in session.items:
                    source, raw, definition = callable_source(item.obj)
                    path = record_source(source)
                    assert path in selected_paths
                    qualifier = definition["qualname"]
                    assert qualifier.rsplit(".", 1)[-1].startswith("test_")
                    prefix = path + "::" + qualifier.replace(".", "::")
                    assert item.nodeid == prefix or item.nodeid.startswith(prefix + "["), item.nodeid
                    matches = [selector for selector in tests if selector == path or
                               item.nodeid == selector or item.nodeid.startswith(selector + "[")]
                    assert len(matches) == 1, (item.nodeid, matches)
                    counts[matches[0]] += 1
                    raw_nodes.append(item.nodeid)
                    info = item._fixtureinfo
                    autouse = list(manager._getautousenames(item))
                    fixtures = {}
                    for name, definitions in sorted(info.name2fixturedefs.items()):
                        fixtures[name] = [{
                            "scope": fixture.scope, "baseid": fixture.baseid, "argname": fixture.argname,
                            "argnames": list(fixture.argnames), "params": stable(fixture.params),
                            "ids": stable(fixture.ids), "autouse_for_item": name in autouse,
                            "callable": function_evidence(fixture.func),
                        } for fixture in definitions]
                    callspec = getattr(item, "callspec", None)
                    rows.append({
                        "nodeid": item.nodeid, "test": function_evidence(item.obj),
                        "signature": str(inspect.signature(raw)), "fixtures": fixtures,
                        "fixture_names": list(item.fixturenames), "fixture_initialnames": list(info.initialnames),
                        "autouse_names": autouse,
                        "autouse_bindings": [{"nodeid": node.nodeid,
                                              "names": list(manager._nodeid_autousenames.get(node.nodeid, ()))}
                                             for node in item.listchain()],
                        "markers": [{"name": mark.name, "args": stable(mark.args), "kwargs": stable(mark.kwargs)}
                                    for mark in item.iter_markers()],
                        "callspec": None if callspec is None else {
                            "params": stable(callspec.params), "indices": callspec.indices, "id": callspec.id,
                            "argument_scopes": {name: scope.value for name, scope in callspec._arg2scope.items()}},
                        "globals": global_evidence(item.obj),
                    })
                    origins.append({
                        "nodeid": item.nodeid, "source_path": path, "code_filename": raw.__code__.co_filename,
                        "source_sha256": source.sha256, "module": raw.__module__, "qualname": qualifier,
                        "code_firstlineno": raw.__code__.co_firstlineno,
                        "decorator_start": definition["decorator_start"], "defline": definition["defline"],
                        "class_module": None if item.cls is None else item.cls.__module__,
                        "class_id_within_process": None if item.cls is None else id(item.cls),
                        "class_mro": [] if item.cls is None else [
                            cls.__module__ + "." + cls.__qualname__ for cls in item.cls.__mro__],
                    })
                state["actual_cases"] = len(rows)
                state["actual_selector_counts"] = counts
                state["raw_nodes_unique"] = len(raw_nodes) == len(set(raw_nodes))
                state["collection_complete"] = True
                save()
                assert len(rows) == expected_count and state["raw_nodes_unique"]
                assert counts == {row["selector"]: row["expected_cases"] for row in selectors}, counts
                assert not state["body_reports"] and not state["refused_execution"]
                if prior is not None:
                    assert rows == prior["comparison"], "Execution-time collection differs from prior candidate snapshot"
                    assert counts == prior["actual_selector_counts"]
                    state["execution_collection_matches_prior"] = True
                    save()

            def pytest_sessionfinish(self, session, exitstatus):
                state["exit_code"] = int(exitstatus)
                state["session_testsfailed"] = session.testsfailed
                state["session_testscollected"] = session.testscollected
                save()

        invocation = ["-q", "-m", "", "-p", "no:cacheprovider", "--basetemp", args.basetemp, *tests]
        invocation += ["--junitxml", args.junit] if args.run else ["--collect-only"]
        state["pytest_argv"] = invocation
        state["exit_code"] = int(pytest.main(invocation, plugins=[Snapshot()]))
        assert state["exit_code"] == 0 and state["collection_complete"]
        assert not state["refused_execution"] and not state["errors"]
        if args.run:
            assert state.get("execution_collection_matches_prior") is True
            by_node = {row["nodeid"]: [] for row in state["comparison"]}
            for row in state["body_reports"]:
                assert row["nodeid"] in by_node
                by_node[row["nodeid"]].append(row)
            assert all([row["phase"] for row in rows] == ["setup", "call", "teardown"]
                       and all(row["outcome"] == "passed" and row["wasxfail"] is None for row in rows)
                       for rows in by_node.values()), "A selected body failed, skipped, or did not complete"
        else:
            assert not state["body_reports"]
        assert all(row["outcome"] == "passed" for row in state["collect_reports"])
        state["product_modules"] = {}
        for name, module in list(sys.modules.items()):
            if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."):
                filename = getattr(module, "__file__", None)
                if filename:
                    path = Path(filename).resolve()
                    assert path.is_relative_to(root / "src"), (name, filename)
                    data = path.read_bytes()
                    assert data == git("show", expected_commit + ":" + path.relative_to(root).as_posix())
                    state["product_modules"][name] = {
                        "path": path.relative_to(root).as_posix(), "sha256": sha(data),
                    }
        assert git("rev-parse", "HEAD").decode().strip() == expected_commit
        assert not git("status", "--porcelain", "--untracked-files=no").strip()
        for row in state["source_files"].values():
            assert sha(Path(row["path"]).read_bytes()) == row["sha256"], row["path"]
        state["observed_source_files_unchanged"] = True
    except BaseException as exc:
        state["errors"].append({"type": type(exc).__name__, "message": str(exc)})
        state["exit_code"] = state["exit_code"] or 3
        raise
    finally:
        state["ended"] = time.time()
        state["terminal"] = True
        state["passed"] = (state["exit_code"] == 0 and state["collection_complete"]
                           and not state["errors"] and not state["refused_execution"]
                           and (args.run or not state["body_reports"])
                           and state.get("observed_source_files_unchanged") is True)
        state["test_execution_credit"] = bool(args.run and state["passed"])
        save()
    raise SystemExit(state["exit_code"])


if __name__ == "__main__":
    main()
