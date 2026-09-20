"""Run only the declared untimed phase controls and preserve exact source/results."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SOURCE_PARENT = "124472b8949805e0dd36052df6894b335d8b519d"
SOURCE_PARENT_TREE = "a0c139c4e02535545c5b0e602c240a38affde5fe"
PYTHON_PATHS = (
    "scripts/ci/priority_launcher_phase/__init__.py",
    "scripts/ci/priority_launcher_phase/capture.py",
    "scripts/ci/priority_launcher_phase/projection.py",
    "scripts/ci/priority_launcher_phase/parent.py",
    "scripts/ci/priority_launcher_phase/daemon.py",
    "scripts/ci/priority_launcher_phase/fixture.py",
    "scripts/ci/priority_launcher_phase/joins.py",
    "scripts/ci/priority_launcher_phase/bindings.py",
    "scripts/ci/priority_launcher_phase/run.py",
    "scripts/ci/priority_launcher_phase_daemon.py",
    "scripts/ci/priority_launcher_phase_diagnostic.py",
    "tests/test_priority_launcher_phase_capture.py",
    "tests/test_priority_launcher_phase_forwarding.py",
    "tests/test_priority_launcher_phase_joins.py",
    "scripts/ci/priority_launcher_phase/schema.py",
)
AUXILIARY_PATHS = (
    "scripts/ci/priority_launcher_phase/plan-v2.json",
    "scripts/ci/priority_launcher_phase/PLAN-CLARIFICATION-v3.json",
    "scripts/ci/priority_launcher_phase/source-bindings.json",
)
TESTS = (
    "tests/test_priority_launcher_phase_capture.py",
    "tests/test_priority_launcher_phase_forwarding.py",
    "tests/test_priority_launcher_phase_joins.py",
)
MAX_OUTPUT = 8 * 1024 * 1024


def _write(path: Path, value: object) -> None:
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    if len(encoded) > MAX_OUTPUT:
        raise ValueError("phase_control_record_bound")
    with path.open("xb") as stream:
        stream.write(encoded)


def _git(root: Path, *args: str) -> str:
    value = subprocess.check_output(("git", "-C", str(root), *args), timeout=15)
    if len(value) > MAX_OUTPUT:
        raise ValueError("phase_control_git_bound")
    return value.decode().strip()


def _bindings(args: argparse.Namespace) -> dict[str, object]:
    expected_sha, expected_tree = os.environ["SOURCE_SHA"], os.environ["SOURCE_TREE"]
    result: dict[str, object] = {"schema": "priority-phase-controls-binding.v1", "qualification": False}
    for name, root, sha in (("source", args.source, expected_sha), ("driver", args.driver, os.environ["GITHUB_SHA"])):
        actual_sha = _git(root, "rev-parse", "HEAD")
        tree = _git(root, "rev-parse", "HEAD^{tree}")
        parents = _git(root, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:]
        expected_parent = SOURCE_PARENT if name == "source" else expected_sha
        if (
            actual_sha != sha
            or parents != [expected_parent]
            or _git(root, "status", "--porcelain", "--untracked-files=no")
        ):
            raise ValueError("phase_control_checkout_binding")
        if name == "source" and tree != expected_tree:
            raise ValueError("phase_control_tree_binding")
        result[name] = {"sha": actual_sha, "tree": tree, "parents": parents, "tracked_clean": True}
    driver_changed = _git(args.driver, "diff", "--name-only", "HEAD^", "HEAD").splitlines()
    if set(driver_changed) != {
        ".github/workflows/priority-launcher-phase-controls.yml",
        "scripts/ci/priority_launcher_phase_controls.py",
    }:
        raise ValueError("phase_control_driver_scope")
    changed = _git(args.source, "diff", "--name-only", "HEAD^", "HEAD").splitlines()
    if set(changed) != set(PYTHON_PATHS) | set(AUXILIARY_PATHS):
        raise ValueError("phase_control_source_scope")
    inputs: dict[str, object] = {}
    for name in (*PYTHON_PATHS, *AUXILIARY_PATHS):
        data = (args.source / name).read_bytes()
        if len(data) > 128 * 1024:
            raise ValueError("phase_control_source_file_bound")
        inputs[name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "git_blob": _git(args.source, "rev-parse", "HEAD:" + name),
        }
    manifest = json.loads((args.source / AUXILIARY_PATHS[-1]).read_text())
    if manifest["source_sha"] != SOURCE_PARENT or manifest["source_tree"] != SOURCE_PARENT_TREE:
        raise ValueError("phase_control_product_binding")
    for row in manifest["files"]:
        data = (args.source / row["path"]).read_bytes()
        if (
            hashlib.sha256(data).hexdigest() != row["sha256"]
            or _git(args.source, "rev-parse", "HEAD:" + row["path"]) != row["git_blob"]
        ):
            raise ValueError("phase_control_product_bytes")
    result["inputs"] = inputs
    result["product_source_binding_sha256"] = hashlib.sha256(
        (args.source / AUXILIARY_PATHS[-1]).read_bytes()
    ).hexdigest()
    return result


def _declared_count(root: Path) -> int:
    count = 0
    for name in TESTS:
        tree = ast.parse((root / name).read_text())
        for function in tree.body:
            if not isinstance(function, ast.FunctionDef) or not function.name.startswith("test_"):
                continue
            cases = 1
            for decorator in function.decorator_list:
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "parametrize"
                ):
                    if len(decorator.args) < 2 or not isinstance(decorator.args[1], (ast.List, ast.Tuple)):
                        raise ValueError("phase_control_dynamic_parameter_count")
                    cases *= len(decorator.args[1].elts)
            count += cases
    return count


def _command(args: argparse.Namespace, name: str, command: list[str], *, timeout: int = 180) -> int:
    timed_out = False
    try:
        result = subprocess.run(command, cwd=args.source, capture_output=True, timeout=timeout, check=False)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code = None
        stdout = error.stdout if isinstance(error.stdout, bytes) else b""
        stderr = error.stderr if isinstance(error.stderr, bytes) else b""
        timed_out = True
    streams = {}
    for suffix, data in (("stdout", stdout), ("stderr", stderr)):
        with (args.output / (name + "." + suffix)).open("xb") as stream:
            stream.write(data[:MAX_OUTPUT])
        streams[suffix] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "retained_bytes": min(len(data), MAX_OUTPUT),
            "overflow": len(data) > MAX_OUTPUT,
        }
    complete = not timed_out and not any(row["overflow"] for row in streams.values())
    _write(
        args.output / (name + "-result.json"),
        {
            "argv": command,
            "returncode": code,
            "timed_out": timed_out,
            "streams": streams,
            "capture_complete": complete,
            "timeout_scope": (
                "subprocess.run kills and reaps its direct child; inherited-pipe descendants can extend draining. "
                "No process-tree cleanup or overall wall bound is inferred."
            ),
        },
    )
    return code if complete and code is not None else 1


def _interpreter(args: argparse.Namespace) -> dict[str, object]:
    expected = args.source / ".venv"
    executable = Path(sys.executable)
    record: dict[str, object] = {
        "version": sys.version,
        "version_info": list(sys.version_info[:3]),
        "executable": str(executable),
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "platform": sys.platform,
        "machine": platform.machine(),
        "expected_prefix": str(expected),
        "expected_executable": str(expected / "bin/python"),
    }
    admitted = (
        sys.version_info[:2] == (3, 12)
        and sys.platform == "darwin"
        and platform.machine() == "arm64"
        and Path(sys.prefix).resolve() == expected.resolve()
        and os.path.abspath(sys.executable) == str(expected / "bin/python")
        and sys.prefix != sys.base_prefix
    )
    _write(args.output / "interpreter.json", {**record, "admitted": admitted})
    if not admitted:
        raise ValueError("phase_control_interpreter_binding")
    return record


def _controls(args: argparse.Namespace) -> int:
    _interpreter(args)
    _write(args.output / "control-source-before.json", _bindings(args))
    declared = _declared_count(args.source)
    _write(
        args.output / "declared-controls.json",
        {"tests": list(TESTS), "declared_cases": declared, "original_88_calls_executed": False},
    )
    all_python = (*PYTHON_PATHS, str(args.driver / "scripts/ci/priority_launcher_phase_controls.py"))
    stages = (
        ("ruff", [sys.executable, "-m", "ruff", "check", "--output-format", "json", *all_python]),
        ("format", [sys.executable, "-m", "ruff", "format", "--check", *all_python]),
        ("types", [sys.executable, "-m", "basedpyright", "--outputjson", *all_python]),
        ("collect", [sys.executable, "-m", "pytest", "--collect-only", "-q", *TESTS]),
    )
    for name, command in stages:
        if _command(args, name, command):
            return 1
    selectors = [
        line
        for line in (args.output / "collect.stdout").read_text().splitlines()
        if line.startswith("tests/") and "::" in line
    ]
    if len(selectors) != declared or len(set(selectors)) != declared:
        raise ValueError("phase_control_collection_count")
    _write(args.output / "collected-selectors.json", selectors)
    code = _command(
        args,
        "controls",
        [sys.executable, "-m", "pytest", "-q", *TESTS, "--junitxml=" + str(args.output / "controls.xml")],
    )
    xml = (args.output / "controls.xml").read_bytes()
    if len(xml) > MAX_OUTPUT or b"<!DOCTYPE" in xml or b"<!ENTITY" in xml:
        raise ValueError("phase_control_xml_bound")
    cases = []
    for case in ET.fromstring(xml).iter("testcase"):
        selector = case.attrib["classname"].replace(".", "/") + ".py::" + case.attrib["name"]
        status = (
            "failed"
            if case.find("failure") is not None
            else "error"
            if case.find("error") is not None
            else "skipped"
            if case.find("skipped") is not None
            else "passed"
        )
        cases.append({"selector": selector, "status": status})
    passed = (
        code == 0
        and [row["selector"] for row in cases] == selectors
        and all(row["status"] == "passed" for row in cases)
    )
    _write(
        args.output / "control-admission.json",
        {
            "declared_cases": declared,
            "collected": len(selectors),
            "executed": len(cases),
            "cases": cases,
            "passed": passed,
            "original_88_calls_executed": False,
            "scope": (
                "Untimed synthetic forwarding/join/fault/cleanup controls, including contained Python children; "
                "no native workload or timing qualification."
            ),
        },
    )
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("bind", "controls", "after"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.operation == "controls":
            return _controls(args)
        _write(args.output / ("source-" + args.operation + ".json"), _bindings(args))
        if args.operation == "after":
            before = json.loads((args.output / "source-bind.json").read_text())
            after = json.loads((args.output / "source-after.json").read_text())
            if before != after:
                raise ValueError("phase_control_source_changed")
        return 0
    except BaseException as error:
        _write(
            args.output / (args.operation + "-failure.json"),
            {
                "category": type(error).__name__,
                "message_sha256": hashlib.sha256(str(error).encode()).hexdigest(),
                "original_88_calls_executed": False,
                "qualification": False,
            },
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
