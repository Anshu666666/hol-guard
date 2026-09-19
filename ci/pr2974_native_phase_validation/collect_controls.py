"""Observe exact native diagnostic controls before setup, then retain every phase."""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
import math
import os
import pwd
import stat
import subprocess
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATE: dict = {}
DEFINITIONS: dict[str, str] = {}
PROVIDERS: dict[str, dict] = {}
PARSED: dict[str, ast.Module] = {}
AUTOUSE = [
    "_spawn_package_shim_sqlite_lock_holder",
    "_default_unit_tests_to_python_rollback",
    "_explicit_python_differential_oracle",
    "_reset_guard_sync_resolver_override",
    "_isolate_lifecycle_authority_home",
    "_isolate_trust_attestation_env",
    "_isolate_daemon_background_refresh_workers",
    "_policy_integrity_keyring_for_selected_tests",
]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def save() -> None:
    target = STATE["output"]
    encoded = json.dumps(STATE["capture"], sort_keys=True, indent=2, allow_nan=False) + "\n"
    assert len(encoded.encode()) <= 16 * 1024 * 1024, "Observation exceeds retention bound"
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".new")
    temporary.write_text(encoded, encoding="utf-8")
    temporary.replace(target)


def value_record(value, depth=0):
    assert depth <= 16
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
    raise ValueError("Unadmitted collection type: " + kind.__module__ + "." + kind.__qualname__)


def git(*arguments: str) -> bytes:
    return subprocess.check_output(["git", *arguments], cwd=STATE["source"], timeout=30)


def source_admission() -> dict:
    config, source = STATE["config"], STATE["source"]
    assert git("rev-parse", "HEAD").decode().strip() == config["source_sha"]
    assert git("rev-parse", "HEAD^{tree}").decode().strip() == config["source_tree"]
    assert not git("status", "--porcelain", "--untracked-files=no")
    tracked = {}
    for entry in git("ls-files", "--stage", "-z").decode().split("\0"):
        if not entry:
            continue
        metadata, relative = entry.split("\t", 1)
        mode, blob, stage = metadata.split()
        assert stage == "0" and relative not in tracked
        tracked[relative] = {"mode": mode, "git_blob": blob}
    STATE["tracked"] = tracked
    observed = {}
    for relative, expected in config["source_inputs"].items():
        raw = (source / relative).read_bytes()
        assert digest(raw) == expected, relative
        observed[relative] = digest(raw)
    return observed


def source_record(path: Path, retain: bool = False) -> dict:
    path = path.resolve(strict=True)
    source, venv = STATE["source"], Path(sys.prefix).resolve(strict=True)
    if path.is_relative_to(source):
        origin, relative = "candidate", path.relative_to(source).as_posix()
    else:
        assert path.is_relative_to(venv), str(path)
        origin, relative = "owned_dependency", path.relative_to(venv).as_posix()
    raw = path.read_bytes()
    assert len(raw) <= 2 * 1024 * 1024
    if origin == "candidate":
        pin = STATE["tracked"][relative]
        assert pin["mode"] in {"100644", "100755"}
        # Git's object identity is used only as an immutable source checksum.
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest()
        assert actual == pin["git_blob"], relative
    result = {"origin": origin, "path": relative, "sha256": digest(raw), "bytes": len(raw)}
    if retain:
        key = origin + "/" + relative
        PROVIDERS[key] = {**result, "content": raw.decode("utf-8")}
        assert len(PROVIDERS) <= 128
        assert sum(row["bytes"] for row in PROVIDERS.values()) <= 8 * 1024 * 1024
    return result


def definition_nodes(node: ast.AST, prefix: str = ""):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        qualified = prefix + node.name
        yield qualified, node
        prefix = qualified + ".<locals>."
    elif isinstance(node, ast.ClassDef):
        prefix += node.name + "."
    for child in ast.iter_child_nodes(node):
        yield from definition_nodes(child, prefix)


def function_record(function) -> dict:
    original = function
    function = inspect.unwrap(function)
    code = getattr(function, "__code__", None)
    assert code is not None
    path = Path(code.co_filename).resolve(strict=True)
    record = source_record(path, retain=True)
    source_text = PROVIDERS[record["origin"] + "/" + record["path"]]["content"]
    if record["sha256"] not in PARSED:
        PARSED[record["sha256"]] = ast.parse(source_text, filename=str(path), type_comments=True)
    parsed = PARSED[record["sha256"]]
    matches = [
        node for qualified, node in definition_nodes(parsed)
        if qualified == code.co_qualname and node.name == code.co_name
        and min([node.lineno, *(mark.lineno for mark in node.decorator_list)])
        <= code.co_firstlineno <= node.lineno
    ]
    assert len(matches) == 1, (record, code.co_qualname, code.co_firstlineno)
    node = matches[0]
    encoded = ast.dump(node, include_attributes=False)
    key = digest(encoded.encode())
    assert len(encoded.encode()) <= 256 * 1024
    DEFINITIONS[key] = encoded
    assert len(DEFINITIONS) <= 512 and sum(len(row.encode()) for row in DEFINITIONS.values()) <= 8 * 1024 * 1024
    return {
        **record, "module": function.__module__, "qualname": function.__qualname__,
        "code_qualname": code.co_qualname, "first_line": code.co_firstlineno,
        "wrapped_module": original.__module__, "wrapped_qualname": original.__qualname__,
        "argument_names": list(code.co_varnames[:code.co_argcount + code.co_kwonlyargcount]),
        "posonlyargcount": code.co_posonlyargcount, "kwonlyargcount": code.co_kwonlyargcount,
        "signature_ast": ast.dump(node.args, include_attributes=False),
        "definition_ast_sha256": key, "definition_end_line": node.end_lineno,
    }


def module_origins() -> dict:
    result = {}
    for name, module in sorted(sys.modules.copy().items()):
        filename = getattr(module, "__file__", None)
        scoped = name.split(".", 1)[0] in {"codex_plugin_scanner", "scripts", "tests", "ci"}
        if filename:
            path = Path(filename).resolve(strict=True)
            if not scoped and not path.is_relative_to(STATE["source"]):
                continue
            assert path.is_relative_to(STATE["source"]), (name, str(path))
            result[name] = source_record(path)
        elif scoped and hasattr(module, "__path__"):
            paths = [Path(value).resolve(strict=True) for value in module.__path__]
            assert all(path.is_relative_to(STATE["source"]) for path in paths), name
            result[name] = {"namespace_paths": [path.relative_to(STATE["source"]).as_posix() for path in paths]}
    return result


def binary_admission() -> dict:
    if STATE["cohort"] == "python":
        manifest = STATE["report"] / "native-binaries.json"
        raw = manifest.read_bytes() if manifest.is_file() else None
        assert raw is None or len(raw) <= 65536
        return {"scope": "native_binaries_not_required_or_qualified_for_python_controls",
                "build_manifest_present": raw is not None,
                "build_manifest_sha256": None if raw is None else digest(raw)}
    config = STATE["config"]
    report = json.loads((STATE["report"] / "native-binaries.json").read_text(encoding="utf-8"))
    assert set(report) == {"default", "diagnostic"}
    observed = {}
    for name, row in report.items():
        assert row["source_sha"] == config["source_sha"] and row["git_source_tree"] == config["source_tree"]
        assert row["features"] == ([] if name == "default" else ["diagnostic-phases"])
        assert row["toolchain"] == config["rust_toolchain"] and row["build_profile"] == "release"
        path = Path(row["path"])
        assert path.is_absolute() and not path.is_symlink() and path.resolve(strict=True) == path
        target = Path(row["cargo_target_directory"]).resolve(strict=True)
        assert target.is_relative_to(STATE["scratch"]) and path.is_relative_to(target)
        expected_env = "HOL_GUARD_NATIVE_PHASE_" + name.upper() + "_BINARY"
        assert os.environ[expected_env] == str(path)
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            assert 0 < before.st_size == row["bytes"] <= 128 * 1024 * 1024
            hasher, count = hashlib.sha256(), 0
            while chunk := os.read(descriptor, 65536):
                hasher.update(chunk)
                count += len(chunk)
                assert count <= row["bytes"]
            after = os.fstat(descriptor)
            identity = lambda info: [info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
            assert identity(before) == identity(after) == identity(path.stat())
            assert count == row["bytes"] and hasher.hexdigest() == row["sha256"]
            observed[name] = {**row, "identity_at_observation": identity(after)}
        finally:
            os.close(descriptor)
    assert observed["default"]["path"] != observed["diagnostic"]["path"]
    return observed


def properties(report) -> list:
    result = []
    for name, value in report.user_properties:
        assert type(name) is str and type(value) is str
        assert len(name.encode()) <= 1024 and len(value.encode()) <= 1024 * 1024
        result.append([name, value])
    assert len(result) <= 64
    return result


class Capture:
    def refuse(self) -> None:
        value = STATE["capture"]
        assert STATE["mode"] == "run", "Fixture and body execution refused during collection"
        assert value["collection_admitted"] and value["execution_collection_matches_prior"]

    def pytest_collection_finish(self, session):
        value, expected = STATE["capture"], STATE["expected"]
        assert session.config.option.markexpr == ""
        assert session.config.rootpath.resolve() == STATE["source"]
        assert session.config.inipath.resolve() == STATE["source"] / "pyproject.toml"
        assert session.config.option.collectonly == (STATE["mode"] == "collect")
        assert session.config.option.noconftest is False and session.config.option.confcutdir is None
        assert not session.config.pluginmanager.hasplugin("cacheprovider")
        python = STATE["cohort"] == "python"
        assert session.config.pluginmanager.hasplugin("tests.bundle_first_cloud") == python
        conftests = sorted(
            source_record(Path(module.__file__), retain=True)["path"]
            for module in session.config.pluginmanager._conftest_plugins
        )
        assert conftests == (["conftest.py", "tests/conftest.py"] if python else ["conftest.py"])
        rows = []
        for item in session.items:
            function = function_record(item.function)
            assert function["origin"] == "candidate" and function["path"] == item.nodeid.split("::", 1)[0]
            fixture_rows = {}
            for name in item.fixturenames:
                fixture_rows[name] = [{
                    "function": function_record(definition.func), "scope": definition.scope,
                    "argnames": list(definition.argnames), "params": value_record(definition.params),
                    "ids": {"callable": function_record(definition.ids)} if callable(definition.ids) else value_record(definition.ids),
                } for definition in item._fixtureinfo.name2fixturedefs.get(name, ())]
            callspec = getattr(item, "callspec", None)
            scopes = {key: scope.value for key, scope in callspec._arg2scope.items()} if callspec else {}
            assert set(scopes) == set(callspec.params if callspec else {})
            autouse = list(session._fixturemanager._getautousenames(item))
            assert sorted(autouse) == sorted(AUTOUSE if python else AUTOUSE[:1])
            rows.append({
                "nodeid": item.nodeid, "function": function, "fixtures": fixture_rows,
                "fixture_names": list(item.fixturenames), "autouse_names": autouse,
                "param_id": callspec.id if callspec else None,
                "parameters": value_record(callspec.params if callspec else {}), "parameter_scopes": scopes,
                "marks": [{"name": mark.name, "args": value_record(mark.args), "kwargs": value_record(mark.kwargs)}
                          for mark in item.iter_markers()],
                "junit": {"classname": function["path"][:-3].replace("/", "."), "name": item.name},
            })
        contract = {
            "source_sha": STATE["config"]["source_sha"], "source_tree": STATE["config"]["source_tree"],
            "cohort": STATE["cohort"], "selectors": expected["selectors"], "collection": rows,
            "definitions": dict(DEFINITIONS), "providers": dict(PROVIDERS), "conftests": conftests,
            "module_origins": module_origins(), "binaries": STATE["binaries"],
        }
        value["contract"] = contract
        save()
        nodes = [row["nodeid"] for row in rows]
        assert len(nodes) == len(set(nodes)) == expected["expected_cases"]
        covered = []
        for selection in expected["selection_counts"]:
            selector = selection["selector"]
            matches = [node for node in nodes if node.startswith(selector + "::")]
            assert len(matches) == selection["expected_cases"], (selector, len(matches))
            covered.extend(matches)
        assert covered == nodes and len(set(covered)) == len(nodes)
        assert not session.testsfailed
        if STATE["mode"] == "run":
            prior = STATE["prior"]
            assert prior["pytest_exit_code"] == 0 and prior["collection_admitted"]
            assert prior["mode"] == "collect" and not prior["reports"] and prior["error"] is None
            assert prior["evidence_error"] is None and prior["source_unchanged"] and prior["binary_unchanged"]
            assert contract == prior["contract"], "Execution collection differs from the successful prior snapshot"
            value["execution_collection_matches_prior"] = True
        value["collection_admitted"] = True
        save()

    def pytest_runtest_protocol(self, item, nextitem):
        self.refuse()

    def pytest_runtest_setup(self, item):
        self.refuse()

    def pytest_fixture_setup(self, fixturedef, request):
        self.refuse()

    def pytest_runtest_call(self, item):
        self.refuse()

    def pytest_runtest_teardown(self, item, nextitem):
        self.refuse()

    def pytest_runtest_logreport(self, report):
        raw = (str(report.longrepr) if report.failed or report.skipped else "").encode()
        assert len(raw) <= 16 * 1024 * 1024
        failure = None
        if raw:
            target = STATE["output"].with_suffix(".failures.txt")
            offset = target.stat().st_size if target.exists() else 0
            assert offset + len(raw) <= 16 * 1024 * 1024
            with target.open("ab") as stream:
                assert stream.write(raw) == len(raw)
            failure = {"file": target.name, "offset": offset, "bytes": len(raw)}
        STATE["capture"]["reports"].append({
            "nodeid": report.nodeid, "when": report.when, "outcome": report.outcome,
            "duration_seconds": report.duration, "wasxfail": getattr(report, "wasxfail", None),
            "longrepr_sha256": digest(raw), "longrepr_bytes": len(raw), "failure_file": failure,
            "user_properties": properties(report),
        })
        save()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cohort", choices=["python", "native"], required=True)
    parser.add_argument("--mode", choices=["collect", "run"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--basetemp", type=Path, required=True)
    parser.add_argument("--prior", type=Path)
    args = parser.parse_args()
    config = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
    source = Path(os.environ["VALIDATION_SOURCE"]).resolve(strict=True)
    report = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
    scratch = Path(os.environ["VALIDATION_SCRATCH"]).resolve(strict=True)
    output = args.output.resolve()
    assert output.is_relative_to(report) and not output.exists()
    expected = next(row for row in config["python_cohorts"] if row["name"] == args.cohort)
    STATE.update(config=config, source=source, report=report, scratch=scratch, output=output,
                 mode=args.mode, cohort=args.cohort, expected=expected)
    STATE["capture"] = {
        "schema": "hol-guard-native-controls-observation.v1", "mode": args.mode, "cohort": args.cohort,
        "source_sha": config["source_sha"], "source_tree": config["source_tree"], "contract": None,
        "collection_admitted": False, "execution_collection_matches_prior": False, "reports": [],
        "pytest_exit_code": None, "error": None, "evidence_error": None,
        "source_unchanged": False, "binary_unchanged": False, "qualification_complete": False,
    }
    save()
    code = 99
    try:
        assert sys.flags.isolated and sys.dont_write_bytecode and __debug__
        assert Path(sys.executable).resolve() == Path(os.environ["VALIDATION_PYTHON"]).resolve()
        assert sys.version.split()[0] == config["python_version"]
        assert os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1" and os.environ.get("PYTEST_ADDOPTS", "") == ""
        assert Path.cwd().resolve() == source and not report.is_relative_to(source)
        temporary = Path(os.environ["VALIDATION_TEST_TMP"]).resolve(strict=True)
        assert Path(os.environ["TMPDIR"]).resolve(strict=True) == temporary
        assert temporary.is_relative_to(Path("/tmp")) and stat.S_IMODE(temporary.stat().st_mode) == 0o700
        assert temporary.stat().st_uid == os.getuid()
        assert not temporary.is_relative_to(Path.home().resolve())
        assert not temporary.is_relative_to(Path(pwd.getpwuid(os.getuid()).pw_dir).resolve())
        base = args.basetemp.resolve()
        assert base.parent == temporary and not base.exists()
        assert bool(args.prior) == (args.mode == "run")
        if args.prior:
            assert args.prior.resolve(strict=True).is_relative_to(report)
            STATE["prior"] = json.loads(args.prior.read_text(encoding="utf-8"))
        STATE["source_inputs_before"] = source_admission()
        for path in expected["selectors"]:
            assert path.endswith(".py") and path in config["source_inputs"]
        STATE["binaries"] = binary_admission()
        assert not any(name == "pytest" or name.split(".", 1)[0] in {"codex_plugin_scanner", "scripts", "tests", "ci"}
                       for name in sys.modules)
        sys.path[:0] = [str(source / "src"), str(source)]
        import pytest

        assert pytest.__version__ == config["installed_versions"]["pytest"]
        for name in ("pytest_runtest_protocol", "pytest_runtest_setup", "pytest_fixture_setup",
                     "pytest_runtest_call", "pytest_runtest_teardown"):
            pytest.hookimpl(tryfirst=True)(getattr(Capture, name))
        arguments = ["-q", "-ra", "-p", "no:cacheprovider", "-m", "", "--basetemp", str(base),
                     "--junitxml", str(output.with_suffix(".xml"))]
        if args.mode == "collect":
            arguments.append("--collect-only")
        arguments.extend(expected["selectors"])
        STATE["capture"]["pytest_argv"] = arguments
        save()
        code = int(pytest.main(arguments, plugins=[Capture()]))
    except BaseException as error:
        STATE["capture"]["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
    finally:
        try:
            STATE["capture"]["source_inputs_after"] = source_admission()
            STATE["capture"]["source_unchanged"] = STATE["capture"]["source_inputs_after"] == STATE["source_inputs_before"]
            STATE["capture"]["source_origins_after"] = module_origins()
            STATE["capture"]["binaries_after"] = binary_admission()
            STATE["capture"]["binary_unchanged"] = STATE["capture"]["binaries_after"] == STATE["binaries"]
            assert STATE["capture"]["source_unchanged"] and STATE["capture"]["binary_unchanged"]
        except BaseException as error:
            STATE["capture"]["evidence_error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
            code = code or 98
        STATE["capture"]["pytest_exit_code"] = code
        save()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
