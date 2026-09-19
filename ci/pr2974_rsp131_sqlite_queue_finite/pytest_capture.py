"""Retain the exact selected collection, phase outcomes and owned C build evidence."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import traceback

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_text())
SOURCE = Path(os.environ["VALIDATION_SOURCE"]).resolve(strict=True)
REPORT = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
BASE = Path(os.environ["VALIDATION_PYTEST_BASETEMP"]).resolve()
COHORT = os.environ["VALIDATION_COHORT"]
EXPECTED = next(row for row in CONFIG["cohorts"] if row["name"] == COHORT)
OUT = REPORT / COHORT
VENV = Path(sys.prefix).resolve(strict=True)
DEFINITIONS: dict[str, str] = {}
SOURCE_FILES = json.loads((REPORT / "source-before.json").read_bytes())["files"]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save(value: dict) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    temporary = OUT / "pytest-capture.json.new"
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")
    temporary.replace(OUT / "pytest-capture.json")


def value_record(value, depth=0):
    assert depth <= 16, "Collection value nesting exceeds the fixed bound"
    kind = type(value)
    if value is None or kind in (bool, int, str):
        assert kind is not str or len(value.encode()) <= 65536
        return {"type": kind.__name__, "value": value}
    if kind is float:
        return {"type": "float", "hex": value.hex() if math.isfinite(value) else str(value)}
    if kind in (tuple, list):
        assert len(value) <= 256
        return {"type": kind.__name__, "items": [value_record(item, depth + 1) for item in value]}
    if kind is dict:
        assert len(value) <= 256 and all(type(key) is str for key in value)
        return {"type": "dict", "items": [[key, value_record(item, depth + 1)] for key, item in value.items()]}
    # These exact built-in exception instances are parameters in the pinned queue clock control.
    if kind in (ValueError, KeyboardInterrupt):
        assert (kind is ValueError and value.args == ("private clock error",)) or (
            kind is KeyboardInterrupt and value.args == ()
        )
        return {"type": "builtins." + kind.__name__, "args": value_record(value.args, depth + 1)}
    raise ValueError("Unadmitted collection value type: " + kind.__module__ + "." + kind.__qualname__)


def function_record(function) -> dict:
    original = function
    function = inspect.unwrap(function)
    code = getattr(function, "__code__", None)
    assert code is not None, "Selected callable has no Python source code"
    path = Path(code.co_filename).resolve(strict=True)
    if path.is_relative_to(SOURCE):
        origin = "candidate"
        relative = path.relative_to(SOURCE).as_posix()
    else:
        assert path.is_relative_to(VENV), str(path)
        origin, relative = "owned_dependency", path.relative_to(VENV).as_posix()
    raw = path.read_bytes()
    if origin == "candidate":
        assert relative in SOURCE_FILES and digest(raw) == SOURCE_FILES[relative]["sha256"], relative
    parsed = ast.parse(raw.decode("utf-8"), filename=str(path), type_comments=True)
    matches = [node for node in ast.walk(parsed)
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name == code.co_name
               and min([node.lineno, *(entry.lineno for entry in node.decorator_list)]) == code.co_firstlineno]
    assert len(matches) == 1, (str(path), code.co_name, code.co_firstlineno)
    definition = matches[0]
    definition_ast = ast.dump(definition, include_attributes=False)
    definition_hash = digest(definition_ast.encode())
    assert len(definition_ast.encode()) <= 256 * 1024
    DEFINITIONS[definition_hash] = definition_ast
    assert len(DEFINITIONS) <= 512 and sum(len(value.encode()) for value in DEFINITIONS.values()) <= 8 * 1024 * 1024
    return {
        "module": function.__module__, "qualname": function.__qualname__,
        "wrapped_module": original.__module__, "wrapped_qualname": original.__qualname__,
        "origin": origin, "path": relative, "sha256": digest(raw),
        "first_line": code.co_firstlineno, "argument_names": list(code.co_varnames[:code.co_argcount]),
        "posonlyargcount": code.co_posonlyargcount, "kwonlyargcount": code.co_kwonlyargcount,
        "complete_definition_ast_sha256": definition_hash,
        "definition_end_line": definition.end_lineno,
    }


class Capture:
    def __init__(self):
        self.value = {
            "cohort": COHORT, "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "selectors": EXPECTED["selectors"], "expected_cases": EXPECTED["expected_cases"],
            "collection": [], "collection_admitted": False, "reports": [],
            "complete_definition_asts": DEFINITIONS,
            "pytest_exit_code": None, "error": None, "source_origins": {},
            "compiled_build_files": {}, "compiled_build_directories": [],
            "qualification_complete": False, "installed_qualification_credit": False,
            "native_qualification_credit": False,
        }
        save(self.value)

    def pytest_collection_finish(self, session):
        assert session.config.option.markexpr == "", "The original slow cases must not be deselected"
        assert session.config.rootpath.resolve() == SOURCE
        assert session.config.inipath.resolve() == SOURCE / "pyproject.toml"
        assert session.config.option.noconftest is False and session.config.option.collectonly is False
        assert session.config.option.confcutdir is None
        assert not session.config.pluginmanager.hasplugin("cacheprovider")
        assert session.config.pluginmanager.hasplugin("tests.bundle_first_cloud")
        rows = []
        for item in session.items:
            function = function_record(item.function)
            assert function["origin"] == "candidate"
            assert function["path"] == item.nodeid.split("::", 1)[0]
            fixtures = {}
            info = item._fixtureinfo
            for name in item.fixturenames:
                definitions = info.name2fixturedefs.get(name, ())
                fixtures[name] = [{
                    "source": function_record(definition.func), "scope": definition.scope,
                    "argnames": list(definition.argnames),
                    "params": value_record(definition.params),
                    "ids": value_record(definition.ids) if not callable(definition.ids) else {
                        "callable": function_record(definition.ids)
                    },
                } for definition in definitions]
            callspec = getattr(item, "callspec", None)
            parameter_scopes = {name: scope.value for name, scope in callspec._arg2scope.items()} if callspec else {}
            assert set(parameter_scopes) == set(callspec.params if callspec else {})
            assert all(scope in {"function", "class", "module", "package", "session"}
                       for scope in parameter_scopes.values())
            autouse = list(session._fixturemanager._getautousenames(item))
            if COHORT == "writer-queue":
                assert sorted(autouse) == sorted(CONFIG["queue_autouse_fixtures"]), autouse
            rows.append({
                "nodeid": item.nodeid, "function": function, "fixture_names": list(item.fixturenames),
                "fixtures": fixtures, "autouse_names": autouse, "param_id": callspec.id if callspec is not None else None,
                "parameters": value_record(callspec.params if callspec is not None else {}),
                "parameter_scopes": parameter_scopes,
                "marks": [{"name": mark.name, "args": value_record(mark.args),
                           "kwargs": value_record(mark.kwargs)} for mark in item.iter_markers()],
            })
        self.value["collection"] = rows
        save(self.value)
        nodes = [row["nodeid"] for row in rows]
        assert len(nodes) == len(set(nodes)) == EXPECTED["expected_cases"]
        covered = []
        for selection in EXPECTED["selection_counts"]:
            selector = selection["selector"]
            if selector.endswith(".py"):
                matches = [node for node in nodes if node.startswith(selector + "::")]
            else:
                matches = [node for node in nodes if node == selector or node.startswith(selector + "[")]
            assert len(matches) == selection["expected_cases"], (selector, len(matches))
            covered.extend(matches)
        assert len(covered) == len(set(covered)) == len(nodes) and set(covered) == set(nodes)
        contract = json.loads((REPORT / "source-contract.json").read_bytes())
        dependencies = json.loads((REPORT / "dependency-contract-before.json").read_bytes())
        assert contract["passed"] is dependencies["passed"] is True
        assert contract["source_sha"] == dependencies["source_sha"] == CONFIG["source_sha"]
        assert rows == contract["expected_followup_collections"][COHORT], "Current collection differs from admission"
        self.value["original_contract_current_source_comparison_passed"] = True
        self.value["collection_admitted"] = True
        save(self.value)

    def pytest_runtest_protocol(self, item, nextitem):
        assert self.value["collection_admitted"], "Refuse bodies before the exact collection is admitted"

    def pytest_runtest_setup(self, item):
        assert self.value["collection_admitted"]

    def pytest_fixture_setup(self, fixturedef, request):
        assert self.value["collection_admitted"]

    def pytest_runtest_call(self, item):
        assert self.value["collection_admitted"]

    def pytest_runtest_teardown(self, item, nextitem):
        assert self.value["collection_admitted"]

    def pytest_runtest_logreport(self, report):
        text = str(report.longrepr) if report.failed or report.skipped else None
        raw = text.encode() if text is not None else b""
        self.value["reports"].append({
            "nodeid": report.nodeid, "when": report.when, "outcome": report.outcome,
            "duration_seconds": report.duration, "wasxfail": getattr(report, "wasxfail", None),
            "longrepr": text if len(raw) <= 131072 else raw[:131072].decode(errors="replace"),
            "longrepr_bytes": len(raw), "longrepr_sha256": digest(raw),
            "longrepr_censored": len(raw) > 131072,
        })
        save(self.value)


def retain_builds(value: dict) -> None:
    if not BASE.is_dir():
        return
    directories = sorted(path for path in BASE.glob("rsp131-sqlite-vfs-build*")
                         if path.is_dir() and not path.is_symlink())
    assert len(directories) <= 1, "More than one original session C build"
    total = 0
    for directory in directories:
        assert directory.resolve().parent == BASE
        info = directory.lstat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
        entries = sorted(directory.iterdir())
        assert len(entries) <= 32
        value["compiled_build_directories"].append(directory.name)
        for path in entries:
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), str(path)
            assert info.st_size <= 16 * 1024 * 1024
            raw = path.read_bytes()
            total += len(raw)
            assert total <= 64 * 1024 * 1024
            relative = path.relative_to(BASE).as_posix()
            target = OUT / "compiled-build" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            assert target.read_bytes() == raw
            value["compiled_build_files"][relative] = {
                "sha256": digest(raw), "bytes": len(raw), "mode": oct(stat.S_IMODE(info.st_mode)),
            }


def main() -> int:
    assert sys.flags.isolated and sys.dont_write_bytecode and __debug__
    assert os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert os.environ.get("PYTEST_ADDOPTS", "") == ""
    assert BASE.parent == Path(os.environ["VALIDATION_TEST_TMP"]).resolve(strict=True) and not BASE.exists()
    expected_args = ["-q", "-ra", "-p", "no:cacheprovider", "-m", "", "--basetemp", str(BASE),
                     "--junitxml", str(OUT / "junit.xml"), *EXPECTED["selectors"]]
    assert sys.argv[1:] == expected_args
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SOURCE, timeout=30).decode().strip() == CONFIG["source_sha"]
    assert sys.version.split()[0] == CONFIG["python_version"]
    for filename in ("source-contract.json", "dependency-contract-before.json"):
        admitted = json.loads((REPORT / filename).read_bytes())
        assert admitted["passed"] is True and admitted["source_sha"] == CONFIG["source_sha"]
    assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                   for name in sys.modules)
    selected = set(EXPECTED["modules"])
    expected_map = json.loads((REPORT / "source-before.json").read_text())["files"]
    for path in selected:
        assert digest((SOURCE / path).read_bytes()) == expected_map[path]["sha256"], path
    sys.path[:0] = [str(SOURCE / "src"), str(SOURCE)]
    import pytest

    assert pytest.__version__ == CONFIG["installed_versions"]["pytest"]
    capture = Capture()
    code = 99
    try:
        code = int(pytest.main(sys.argv[1:], plugins=[capture]))
    except BaseException as error:
        capture.value["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
    finally:
        try:
            for name, module in sorted(sys.modules.copy().items()):
                filename = getattr(module, "__file__", None)
                if not filename:
                    continue
                path = Path(filename).resolve(strict=True)
                selected_name = (name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                                 or name == "scripts" or name.startswith("scripts.")
                                 or name == "tests" or name.startswith("tests."))
                if not selected_name and not path.is_relative_to(SOURCE):
                    continue
                assert path.is_relative_to(SOURCE), (name, str(path))
                relative = path.relative_to(SOURCE).as_posix()
                observed = digest(path.read_bytes())
                assert relative in expected_map and observed == expected_map[relative]["sha256"], name
                capture.value["source_origins"][name] = {"path": relative, "sha256": observed}
            retain_builds(capture.value)
        except BaseException as error:
            capture.value["evidence_error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
            code = code or 98
        capture.value["pytest_exit_code"] = code
        save(capture.value)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
