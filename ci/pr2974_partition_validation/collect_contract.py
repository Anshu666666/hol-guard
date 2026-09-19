"""Observe exact command/surface collection and execution with complete-file source binding."""
from __future__ import annotations

import argparse
import ast
import builtins
import hashlib
import importlib
import inspect
import json
import os
import platform
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_definition_contract import callable_source, outer_units, source_file
from surface_fixture_bridge import SurfaceFixtureBridge

SURFACE_SUFFIXES = (
    "", "_01_dashboard", "_02_settings", "_03_hook_requests", "_04_hook_temporary_workspaces",
    "_05_hook_capacity", "_06_hook_authority", "_07_cloud_identity", "_08_cloud_recovery",
    "_09_hook_responses_idle", "_10_surface_contracts", "_11_surface_operations",
    "_12_approval_browser", "_13_surface_clients", "_14_fast_hook_path",
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--baseline-source", required=True)
    parser.add_argument("--original-module", choices=(
        "tests.test_guard_command_extensions", "tests.test_guard_surface_server"), required=True)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--expected", type=int, required=True)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--junit")
    parser.add_argument("--prior-collection", type=Path)
    parser.add_argument("--basetemp", required=True)
    parser.add_argument("tests", nargs="+")
    args = parser.parse_args()
    root = Path(args.root).resolve(strict=True)
    output = Path(args.snapshot).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "comparison": [], "raw_origins": [], "collect_reports": [], "body_reports": [],
        "refused_execution": [], "collection_complete": False, "started": time.time(),
        "mode": "existing_cases" if args.run else "collection_only",
        "python": sys.version, "platform": platform.platform(), "root": str(root),
        "normalization_map": {}, "source_files": {}, "errors": [], "exit_code": None,
    }

    def save():
        output.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")

    save()
    try:
        os.chdir(root)
        sys.path[:0] = [str(root), str(root / "src"), str(root / "tests/support")]
        import pytest
        state["pytest_version"] = pytest.__version__
        original_path = args.original_module.replace(".", "/") + ".py"
        suffixes = ("", "_runtime", "_runtime_policy") if "command_extensions" in args.original_module else SURFACE_SUFFIXES
        verified_paths = [original_path[:-3] + suffix + ".py" for suffix in suffixes]
        allowed_modules = {path[:-3].replace("/", "."): args.original_module for path in verified_paths}
        assert args.tests == [original_path] or args.tests == verified_paths, "Use the exact original or ordered candidate list."
        baseline = source_file(str(Path(args.baseline_source).resolve(strict=True)))
        original_units = dict(outer_units(baseline.tree))
        fixture_bridge = (SurfaceFixtureBridge(root, baseline)
                          if args.original_module == "tests.test_guard_surface_server" and args.tests == verified_paths
                          else None)
        state["synthetic_fixture_bridge"] = None if fixture_bridge is None else fixture_bridge.evidence
        state["synthetic_fixture_runtime"] = {}
        if fixture_bridge is not None:
            helper_path = root / fixture_bridge.evidence["helper"]["path"]
            state["source_files"][str(helper_path)] = {
                "path": str(helper_path), "sha256": fixture_bridge.evidence["helper"]["sha256"],
                "bytes": fixture_bridge.evidence["helper"]["bytes"],
            }
        actual_definitions = {}
        original_imports = {}
        for node in baseline.tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    original_imports[alias.asname or alias.name.split(".")[0]] = ("import", alias.name, alias.asname)
            elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
                assert node.level == 0
                for alias in node.names:
                    assert alias.name != "*"
                    original_imports[alias.asname or alias.name] = ("from", node.module, alias.name)
        for path in args.tests:
            source = source_file(str(root / path))
            for name, node in outer_units(source.tree):
                compared = fixture_bridge.definition(path, name, node) if fixture_bridge else node
                assert name in original_units and ast.dump(compared, include_attributes=False) == ast.dump(
                    original_units[name], include_attributes=False), (path, name)
                assert name not in actual_definitions, ("Repeated qualified definition", name)
                actual_definitions[name] = path
        assert set(actual_definitions) == set(original_units)
        state["normalization_map"] = {
            path + "::" + name.replace(".", "::"): original_path + "::" + name.replace(".", "::")
            for name, path in actual_definitions.items()
            if name.rsplit(".", 1)[-1].startswith("test_")
        }
        state["baseline_source_sha256"] = baseline.sha256

        def normalized_module(name):
            return allowed_modules.get(name, name)

        def normalize_node(value):
            text = str(value)
            head, separator, tail = text.partition("::")
            if head in verified_paths:
                head = original_path
            return head + (separator + tail if separator else "")

        def normalized_path(value):
            text = str(value)
            if text.startswith(str(root) + os.sep):
                text = "<CHECKOUT>/" + str(Path(text).relative_to(root))
            return normalize_node(text)

        def function_evidence(function):
            source, raw, definition = callable_source(function)
            state["source_files"][str(source.path)] = {
                "path": str(source.path), "sha256": source.sha256, "bytes": len(source.raw),
            }
            module_name = raw.__module__
            compared_node = definition["node"]
            if fixture_bridge is not None and source.path.is_relative_to(root):
                compared_node = fixture_bridge.definition(source.path.relative_to(root).as_posix(),
                                                          definition["qualname"], compared_node)
            if module_name in allowed_modules:
                actual_path = source.path.relative_to(root).as_posix()
                assert any(actual_path == path and (definition["qualname"] == name or
                           definition["qualname"].startswith(name + ".<locals>."))
                           for name, path in actual_definitions.items()), definition["qualname"]
                module_name = args.original_module
            return {
                "function": module_name + "." + raw.__qualname__,
                "ast": ast.dump(compared_node, include_attributes=False),
            }

        def stable(value):
            if value is None or isinstance(value, (bool, int, float, str)):
                return value
            if isinstance(value, bytes):
                return {"bytes_hex": value.hex()}
            if isinstance(value, Path):
                return {"path": normalized_path(value)}
            if isinstance(value, (list, tuple)):
                return {"type": type(value).__name__, "items": [stable(item) for item in value]}
            if isinstance(value, (set, frozenset)):
                items = [stable(item) for item in value]
                return {"type": type(value).__name__, "items": sorted(items, key=lambda item: json.dumps(item, sort_keys=True))}
            if isinstance(value, dict):
                return {"mapping": sorted([[stable(k), stable(v)] for k, v in value.items()],
                                          key=lambda item: json.dumps(item[0], sort_keys=True))}
            if inspect.ismodule(value):
                return {"module": normalized_module(value.__name__)}
            if inspect.isfunction(value) or inspect.ismethod(value):
                return function_evidence(value)
            if inspect.isclass(value) or inspect.isbuiltin(value):
                return {"object": normalized_module(value.__module__) + "." + value.__qualname__}
            raise TypeError("Unreviewed collection value: " + type(value).__module__ + "." + type(value).__qualname__)

        def globals_evidence(function):
            source, raw, definition = callable_source(function)
            result = {}
            for name in source.globals_for(definition):
                if name not in raw.__globals__:
                    assert hasattr(builtins, name), name
                    result[name] = {"builtin": name}
                    continue
                value = raw.__globals__[name]
                binding = original_imports.get(name)
                if binding:
                    kind, module, member = binding
                    expected = (getattr(importlib.import_module(module), member) if kind == "from" else
                                importlib.import_module(module if member else module.split(".")[0]))
                    assert value is expected, "Imported-object identity changed: " + name
                    if (kind, module, member) == (
                        "from", "codex_plugin_scanner.guard.runtime.command_extensions",
                        "BUILT_IN_COMMAND_EXTENSION_REGISTRY",
                    ):
                        provider = importlib.import_module(module)
                        provider_path = Path(provider.__file__).resolve()
                        relative = "src/codex_plugin_scanner/guard/runtime/command_extensions.py"
                        assert provider_path == root / relative
                        provider_sha256 = hashlib.sha256(provider_path.read_bytes()).hexdigest()
                        assert provider_sha256 == "43a97fae6d8cbbc0897b8f01fcfaa5e38445d468023360a000349aac33aa5037"
                        assert type(value) is provider.CommandSafetyExtensionRegistry
                        assert type(value).__module__ == module
                        assert type(value).__qualname__ == "CommandSafetyExtensionRegistry"
                        result[name] = {
                            "verified_imported_constant": {"module": module, "member": member},
                            "provider_path": relative, "provider_sha256": provider_sha256,
                            "class": module + ".CommandSafetyExtensionRegistry",
                            "identity_matches_provider": True,
                        }
                        continue
                result[name] = stable(value)
            if fixture_bridge is not None and source.path.is_relative_to(root):
                actual_path = source.path.relative_to(root).as_posix()
                qualifier = definition["qualname"]
                if fixture_bridge.applies(actual_path, qualifier):
                    binding = fixture_bridge.runtime_binding(actual_path, qualifier, raw)
                    state["synthetic_fixture_runtime"][qualifier] = {
                        "binding": binding, "raw_globals": dict(result),
                        "raw_global_names": source.globals_for(definition),
                        "raw_function_ast": ast.dump(definition["node"], include_attributes=False),
                    }
                    assert fixture_bridge.name in result
                    del result[fixture_bridge.name]
            return result

        def refuse(phase, nodeid=""):
            if not args.run:
                state["refused_execution"].append({"phase": phase, "nodeid": nodeid})
                save()
                raise RuntimeError("Collection-only observer refuses " + phase)
            if not state.get("execution_collection_matches_prior"):
                state["refused_execution"].append({"phase": phase, "nodeid": nodeid})
                save()
                raise RuntimeError("Execution collection was not bound before " + phase)

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
                    "longrepr": str(report.longrepr) if report.failed else None,
                })

            def pytest_runtest_logreport(self, report):
                state["body_reports"].append({
                    "nodeid": report.nodeid, "phase": report.when, "outcome": report.outcome,
                    "duration": report.duration, "longrepr": str(report.longrepr) if report.failed or report.skipped else None,
                    "wasxfail": getattr(report, "wasxfail", None),
                })

            @pytest.hookimpl(trylast=True)
            def pytest_collection_finish(self, session):
                rows, origins, raw_nodes, normalized_nodes, lifetime_review = [], [], [], [], []
                state["comparison"], state["raw_origins"] = rows, origins
                manager = session._fixturemanager
                for item in session.items:
                    source, raw, definition = callable_source(item.obj)
                    qualifier = definition["qualname"]
                    actual_path = source.path.relative_to(root).as_posix()
                    assert actual_definitions.get(qualifier) == actual_path
                    assert qualifier.rsplit(".", 1)[-1].startswith("test_")
                    prefix = actual_path + "::" + qualifier.replace(".", "::")
                    expected_prefix = original_path + "::" + qualifier.replace(".", "::")
                    assert item.nodeid == prefix or item.nodeid.startswith(prefix + "["), item.nodeid
                    normalized = expected_prefix + item.nodeid[len(prefix):]
                    raw_nodes.append(item.nodeid)
                    normalized_nodes.append(normalized)
                    info = item._fixtureinfo
                    autouse = list(manager._getautousenames(item))
                    fixtures = {}
                    for name, definitions in sorted(info.name2fixturedefs.items()):
                        records = []
                        for fixture in definitions:
                            records.append({
                                "scope": fixture.scope, "baseid": normalize_node(fixture.baseid),
                                "argname": fixture.argname, "argnames": list(fixture.argnames),
                                "params": stable(fixture.params), "ids": stable(fixture.ids),
                                "autouse_for_item": name in autouse, "callable": function_evidence(fixture.func),
                            })
                            if name in item.fixturenames and fixture.scope in {"class", "module"}:
                                lifetime_review.append({"item": item.nodeid, "fixture": name, "scope": fixture.scope,
                                                        "baseid": fixture.baseid})
                        fixtures[name] = records
                    callspec = getattr(item, "callspec", None)
                    rows.append({
                        "nodeid": normalized, "test": function_evidence(item.obj),
                        "signature": str(inspect.signature(raw)), "fixtures": fixtures,
                        "fixture_names": list(item.fixturenames), "fixture_initialnames": list(info.initialnames),
                        "autouse_names": autouse,
                        "autouse_bindings": [{"nodeid": normalize_node(node.nodeid),
                                              "names": list(manager._nodeid_autousenames.get(node.nodeid, ()))}
                                             for node in item.listchain()],
                        "markers": [{"name": mark.name, "args": stable(mark.args), "kwargs": stable(mark.kwargs)}
                                    for mark in item.iter_markers()],
                        "callspec": None if callspec is None else {
                            "params": stable(callspec.params), "indices": callspec.indices, "id": callspec.id,
                            "argument_scopes": {name: scope.value for name, scope in callspec._arg2scope.items()}},
                        "globals": globals_evidence(item.obj),
                    })
                    origins.append({
                        "nodeid": item.nodeid, "code_file": str(source.path), "source_sha256": source.sha256,
                        "qualname": qualifier, "module": raw.__module__,
                        "raw_function_ast": ast.dump(definition["node"], include_attributes=False),
                        "raw_global_names": source.globals_for(definition),
                        "class_module": None if item.cls is None else item.cls.__module__,
                        "class_id_within_process": None if item.cls is None else id(item.cls),
                        "class_mro": [] if item.cls is None else [
                            cls.__module__ + "." + cls.__qualname__ for cls in item.cls.__mro__],
                    })
                if fixture_bridge is not None:
                    assert set(state["synthetic_fixture_runtime"]) == {name for _, name in fixture_bridge.units}
                state["comparison"], state["raw_origins"] = rows, origins
                state["used_class_module_fixtures_requiring_review"] = lifetime_review
                state["actual_cases"] = len(rows)
                state["raw_nodes_unique"] = len(raw_nodes) == len(set(raw_nodes))
                state["normalized_nodes_unique"] = len(normalized_nodes) == len(set(normalized_nodes))
                state["product_modules"] = {}
                for name, module in list(sys.modules.items()):
                    if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."):
                        filename = getattr(module, "__file__", None)
                        if filename:
                            resolved = Path(filename).resolve()
                            assert resolved.is_relative_to(root / "src"), (name, filename)
                            state["product_modules"][name] = str(resolved.relative_to(root))
                state["collection_complete"] = True
                save()
                assert len(rows) == args.expected
                assert state["raw_nodes_unique"] and state["normalized_nodes_unique"]
                assert not lifetime_review, "Used class/module fixture lifetimes require explicit partition review."
                if args.run:
                    assert args.prior_collection is not None
                    prior_raw = args.prior_collection.read_bytes()
                    prior = json.loads(prior_raw)
                    state["prior_collection_sha256"] = hashlib.sha256(prior_raw).hexdigest()
                    assert prior["mode"] == "collection_only" and prior["root"] == str(root)
                    assert prior["actual_cases"] == args.expected and not prior["body_reports"]
                    assert prior["terminal"] and prior["exit_code"] == 0 and prior["collection_complete"]
                    assert not prior["errors"] and not prior["refused_execution"]
                    assert prior["comparison"] == rows, "Execution collection changed before fixture setup"
                    state["execution_collection_matches_prior"] = True
                    save()

            def pytest_sessionfinish(self, session, exitstatus):
                state["exit_code"] = int(exitstatus)
                state["session_testsfailed"] = session.testsfailed
                state["session_testscollected"] = session.testscollected
                save()

        invocation = ["-q", "-m", "", "-p", "no:cacheprovider", "--basetemp", args.basetemp, *args.tests]
        if args.run:
            assert args.junit and args.prior_collection is not None
            invocation += ["--junitxml", args.junit]
        else:
            invocation += ["--collect-only"]
        state["pytest_argv"] = invocation
        state["exit_code"] = int(pytest.main(invocation, plugins=[Snapshot()]))
        state["final_product_modules"] = {}
        for name, module in list(sys.modules.items()):
            if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."):
                filename = getattr(module, "__file__", None)
                if filename:
                    path = Path(filename).resolve(strict=True)
                    assert path.is_relative_to(root / "src"), (name, filename)
                    state["final_product_modules"][name] = {
                        "path": path.relative_to(root).as_posix(),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
        for record in state["source_files"].values():
            assert hashlib.sha256(Path(record["path"]).read_bytes()).hexdigest() == record["sha256"]
        state["observed_source_files_unchanged"] = True
    except BaseException as exc:
        state["errors"].append({"type": type(exc).__name__, "message": str(exc)})
        if state["exit_code"] is None:
            state["exit_code"] = 3
        raise
    finally:
        state["ended"] = time.time()
        state["terminal"] = True
        save()
    raise SystemExit(state["exit_code"])


if __name__ == "__main__":
    main()
