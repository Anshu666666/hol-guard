"""Validate the actual private-file reader/writer proposal on supported Python versions."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

_FILES = [
    "ci/native_runtime/windows_atomic_replace_child.py",
    "ci/native_runtime/windows_atomic_replace_reference.py",
    "ci/native_runtime/windows_replaceable_reader_child.py",
    "ci/native_runtime/windows_wtext_acceptance_probe.py",
    "src/codex_plugin_scanner/guard/adapters/codex_daemon_hook_auth.py",
    "src/codex_plugin_scanner/guard/daemon/manager_pending_launch.py",
    "src/codex_plugin_scanner/guard/private_file_io.py",
    "src/codex_plugin_scanner/guard/windows_atomic_replace.py",
    "src/codex_plugin_scanner/guard/windows_replaceable_file.py",
    "tests/test_guard_private_file_io.py",
    "tests/test_private_reader_descriptor_guards.py",
    "tests/test_windows_atomic_replace.py",
    "tests/test_windows_atomic_replace_process.py",
    "tests/test_windows_replaceable_file.py",
    "tests/test_windows_replaceable_reader_process.py",
    "tests/test_windows_replaceable_unicode_crt.py",
    "tests/test_windows_wtext_acceptance_probe.py",
]
_CHANGED_FILES = [
    ".github/workflows/native-wheel-ci.yml",
    "ci/native_runtime/windows_atomic_replace_child.py",
    "ci/native_runtime/windows_atomic_replace_reference.py",
    "ci/native_runtime/windows_replaceable_reader_child.py",
    "ci/native_runtime/windows_wtext_acceptance_probe.py",
    "src/codex_plugin_scanner/guard/adapters/codex_daemon_hook_auth.py",
    "src/codex_plugin_scanner/guard/daemon/manager_pending_launch.py",
    "src/codex_plugin_scanner/guard/private_file_io.py",
    "src/codex_plugin_scanner/guard/windows_atomic_replace.py",
    "src/codex_plugin_scanner/guard/windows_replaceable_file.py",
    "tests/test_private_reader_descriptor_guards.py",
    "tests/test_windows_atomic_replace.py",
    "tests/test_windows_atomic_replace_process.py",
    "tests/test_windows_replaceable_file.py",
    "tests/test_windows_replaceable_reader_process.py",
    "tests/test_windows_replaceable_unicode_crt.py",
    "tests/test_windows_wtext_acceptance_probe.py",
]
_BOUND_FILES = sorted([*_FILES, "uv.lock", "pyproject.toml", ".github/workflows/native-wheel-ci.yml"])
_MODULES = [
    "tests/test_guard_private_file_io.py",
    "tests/test_private_reader_descriptor_guards.py",
    "tests/test_windows_replaceable_file.py",
    "tests/test_windows_replaceable_reader_process.py",
    "tests/test_windows_replaceable_unicode_crt.py",
    "tests/test_windows_wtext_acceptance_probe.py",
    "tests/test_windows_atomic_replace.py",
    "tests/test_windows_atomic_replace_process.py",
]
_IMPORTS = [
    "codex_plugin_scanner.guard.private_file_io",
    "codex_plugin_scanner.guard.windows_replaceable_file",
    "codex_plugin_scanner.guard.windows_atomic_replace",
    "codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth",
    "codex_plugin_scanner.guard.daemon.manager",
    "codex_plugin_scanner.guard.daemon.manager_pending_launch",
]
_BASE_SHA = "124472b8949805e0dd36052df6894b335d8b519d"
_BASE_TREE = "a0c139c4e02535545c5b0e602c240a38affde5fe"
_TOTAL_CASES = 151
_MODULE_COUNTS = {
    "test_guard_private_file_io": 7,
    "test_private_reader_descriptor_guards": 12,
    "test_windows_replaceable_file": 37,
    "test_windows_replaceable_reader_process": 20,
    "test_windows_replaceable_unicode_crt": 12,
    "test_windows_wtext_acceptance_probe": 22,
    "test_windows_atomic_replace": 27,
    "test_windows_atomic_replace_process": 14,
}
_POSIX_ONLY = {
    "test_private_regular_file_read_rejects_public_file_or_parent",
    "test_private_regular_file_read_rejects_parent_mode_change_during_read",
    "test_opened_descriptor_owner_must_still_match",
}


def _json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _git(where: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(where), *arguments],
        text=True,
        timeout=15,
    ).strip()


def _blob(source: Path, revision: str, name: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(source), "show", f"{revision}:{name}"],
        timeout=15,
    )


def _binding(args, output: Path) -> None:
    source, driver = args.source.resolve(), args.driver.resolve()
    source_sha = _git(source, "rev-parse", "HEAD")
    source_tree = _git(source, "rev-parse", "HEAD^{tree}")
    parent_sha = _git(source, "rev-parse", "HEAD^")
    parent_tree = _git(source, "rev-parse", f"{parent_sha}^{{tree}}")
    driver_sha = _git(driver, "rev-parse", "HEAD")
    actual = _git(source, "diff", "--name-only", parent_sha, source_sha).splitlines()
    assert source_sha == args.source_sha and source_tree == args.source_tree
    assert parent_sha == _BASE_SHA and parent_tree == _BASE_TREE
    assert driver_sha == os.environ["GITHUB_SHA"]
    assert actual == _CHANGED_FILES
    assert not _git(source, "status", "--porcelain")
    assert not _git(driver, "status", "--porcelain")
    assert platform.python_version() == args.expected_python
    assert platform.system() == args.expected_platform
    assert args.expected_python in ("3.10.11", "3.12.10")
    assert args.expected_platform in ("Windows", "Linux")
    assert sys.implementation.name == "cpython"
    assert Path(sys.prefix).resolve() == (source / ".venv").resolve()
    assert sys.prefix != sys.base_prefix
    records = []
    for name in _BOUND_FILES:
        raw = (source / name).read_bytes()
        blob = _blob(source, "HEAD", name)
        assert raw.replace(b"\r\n", b"\n") == blob
        records.append(
            {
                "path": name,
                "checkout_bytes": len(raw),
                "checkout_sha256": hashlib.sha256(raw).hexdigest(),
                "git_blob_bytes": len(blob),
                "git_blob_sha256": hashlib.sha256(blob).hexdigest(),
            }
        )
    for name in ("uv.lock", "pyproject.toml"):
        assert _blob(source, "HEAD", name) == _blob(source, parent_sha, name)
    for name in _IMPORTS:
        module = importlib.import_module(name)
        relative = Path(*name.split(".")).with_suffix(".py")
        assert Path(module.__file__).resolve() == (source / "src" / relative).resolve()
    dependencies = sorted(
        [{"name": item.metadata["Name"], "version": item.version} for item in importlib.metadata.distributions()],
        key=lambda item: (item["name"].lower(), item["version"]),
    )
    binding = {
        "schema": 1,
        "phase": args.phase,
        "source_sha": source_sha,
        "source_tree": source_tree,
        "base_sha": parent_sha,
        "base_tree": parent_tree,
        "driver_sha": driver_sha,
        "driver_tree": _git(driver, "rev-parse", "HEAD^{tree}"),
        "source_clean": True,
        "driver_clean": True,
        "only_declared_product_control_workflow_paths_changed": True,
        "imports_from_pinned_source": True,
        "source_files": records,
        "dependencies": dependencies,
        "python": platform.python_version(),
        "python_build": sys.version,
        "python_executable": sys.executable,
        "python_prefix": sys.prefix,
        "python_base_prefix": sys.base_prefix,
        "platform": platform.system(),
        "python_executable_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        "workflow_run": os.environ["GITHUB_RUN_ID"],
        "workflow_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "source_controls_only": True,
        "installed_artifact_qualification": False,
        "historical_handle_attributed": False,
        "reader_only_repair_rejected": True,
        "unicode_delete_sharing_improvement_claimed": False,
        "product_promotion": False,
    }
    _json(output / f"source-{args.phase}.json", binding)
    if args.phase == "after":
        before = json.loads((output / "source-before.json").read_text(encoding="utf-8"))
        before_valid = isinstance(before, dict) and set(before) == set(binding) and before.get("phase") == "before"
        same = {key: before_valid and before[key] == value for key, value in binding.items() if key != "phase"}
        _json(
            output / "binding-comparison.json",
            {"schema": 1, "before_valid": before_valid, "unchanged": same, "all_unchanged": all(same.values())},
        )
        assert before_valid and all(same.values())


def _attempt(source: Path, output: Path, label: str, arguments: list[str], timeout: int) -> dict:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    try:
        result = subprocess.run(
            [sys.executable, *arguments],
            cwd=source,
            env=environment,
            capture_output=True,
            timeout=timeout,
        )
        stdout, stderr, code, timed_out = result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code, timed_out = error.stdout or b"", error.stderr or b"", None, True
    (output / f"{label}.stdout").write_bytes(stdout)
    (output / f"{label}.stderr").write_bytes(stderr)
    return {"name": label, "return_code": code, "timed_out": timed_out, "process_attempts": 1}


def _static(source: Path, output: Path) -> None:
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    # Windows helpers remain in this entire type cohort on the Linux host.
    system = "Windows" if platform.system() == "Windows" else "All"
    _json(
        output / "static-type-target.json",
        {"python_version": version, "python_platform": system, "runtime_platform": platform.system(), "files": _FILES},
    )
    commands = [
        ("ruff", ["-m", "ruff", "check", *_FILES]),
        ("format", ["-m", "ruff", "format", "--check", *_FILES]),
        ("types", ["-m", "basedpyright", "--pythonversion", version, "--pythonplatform", system, *_FILES]),
    ]
    outcomes = [_attempt(source, output, name, argv, 120) for name, argv in commands]
    _json(output / "static-result.json", outcomes)
    if any(row["return_code"] != 0 or row["timed_out"] for row in outcomes):
        raise SystemExit(1)


def _properties(case: ET.Element) -> dict[str, str]:
    values = {}
    for row in case.findall("./properties/property"):
        name = row.attrib["name"]
        if name in values:
            raise ValueError("duplicate_control_property")
        values[name] = row.attrib["value"]
    return values


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_child_json_key")
        result[key] = value
    return result


def _native_case(case: ET.Element) -> bool:
    module = case.attrib["classname"].rsplit(".", 1)[-1]
    name = case.attrib["name"]
    return module in ("test_windows_replaceable_reader_process", "test_windows_atomic_replace_process") or (
        module == "test_windows_wtext_acceptance_probe"
        and name.startswith(
            ("test_supported_wtext_default_preserves_original_read", "test_original_audit_can_enter_wtext")
        )
    )


def _frame(case: ET.Element, label: str, value: str) -> tuple[dict, dict]:
    capture = json.loads(value, object_pairs_hook=_unique_object)
    content = capture["stdout_content"].encode("utf-8")
    assert len(content) == capture["stdout_bytes"]
    assert hashlib.sha256(content).hexdigest() == capture["stdout_sha256"]
    assert capture["stderr_bytes"] == 0 and not capture["timed_out"] and not capture["kill_requested"]
    assert capture["cleanup_error"] is None
    report = json.loads(content, object_pairs_hook=_unique_object)
    wtext = label.startswith("wtext_child_")
    assert capture["retired" if wtext else "process_retired"]
    if wtext:
        assert capture["return_code"] == 0 and report == capture["report"]
        assert report["observation_complete"] and report["operation_calls"] == 1
        assert report["default_mode_restored"] and report["cleanup_error"] is None
        assert report["reader_import_binding_verified"] and not report["qualification"]
        assert len(report["events"]) == 1
    else:
        assert capture["report_valid"]
        assert capture["return_code"] in (0, 1)
    return report, {
        "case": case.attrib["name"],
        "label": label,
        "stdout_bytes": len(content),
        "stdout_sha256": capture["stdout_sha256"],
        "return_code": capture["return_code"],
        "retired": True,
    }


def _case_gate(output: Path, gate: dict) -> None:
    raw = (output / "controls.xml").read_bytes()
    gate["verification_stage"] = "xml_parse"
    assert len(raw) <= 8_000_000 and b"<!DOCTYPE" not in raw
    xml = ET.fromstring(raw)
    cases = xml.findall(".//testcase")
    gate["total_cases"] = len(cases)
    gate["failed_cases"] = len(xml.findall(".//failure"))
    gate["errored_cases"] = len(xml.findall(".//error"))
    skipped = [case for case in cases if case.find("skipped") is not None]
    gate["skipped_cases"] = len(skipped)
    gate["skipped_identities"] = [{key: case.attrib[key] for key in ("classname", "name")} for case in skipped]
    gate["verification_stage"] = "collection_identity"
    assert len(cases) == _TOTAL_CASES
    identities = [(case.attrib["classname"], case.attrib["name"]) for case in cases]
    assert len(set(identities)) == len(cases)
    modules = {}
    for case in cases:
        name = case.attrib["classname"].rsplit(".", 1)[-1]
        modules[name] = modules.get(name, 0) + 1
        _properties(case)
    gate["modules"] = modules
    assert modules == _MODULE_COUNTS
    native = [case for case in cases if _native_case(case)]
    assert len(native) == 52
    windows = platform.system() == "Windows"
    gate["mandatory_windows_cases"] = len(native)
    gate["verification_stage"] = "platform_admission"
    if windows:
        assert {case.attrib["name"] for case in skipped} == _POSIX_ONLY and len(skipped) == 3
        assert all(case.find("skipped") is None for case in native)
    else:
        assert len(skipped) == 52 and all(_native_case(case) for case in skipped)
    gate["verification_stage"] = "original_child_frames"
    joins, wtext_pairs = [], []
    for case in cases:
        values = _properties(case)
        reports = {}
        for label, value in values.items():
            if label.startswith(("child_capture_", "wtext_child_")):
                report, joined = _frame(case, label, value)
                reports[label] = report
                joins.append(joined)
        if "wtext_child_original" in reports:
            original, candidate = reports["wtext_child_original"], reports["wtext_child_candidate"]
            assert original["candidate"] is False and candidate["candidate"] is True
            assert values["wtext_original_candidate_parity"] == "True"
            assert {key: value for key, value in original.items() if key != "candidate"} == {
                key: value for key, value in candidate.items() if key != "candidate"
            }
            wtext_pairs.append(case.attrib["name"])
        for label, report in reports.items():
            if not label.startswith("child_capture_"):
                continue
            suffix = label.removeprefix("child_capture_")
            matches = [name for name in (f"{suffix}_report", f"{suffix}_writer_report") if name in values]
            if suffix == "writer" and "writer_report" in values:
                matches.append("writer_report")
            assert matches and all(
                json.loads(values[name], object_pairs_hook=_unique_object) == report for name in matches
            )
    gate["child_frame_joins"], gate["wtext_pairs"] = joins, wtext_pairs
    assert len(joins) == (90 if windows else 0)
    assert len(wtext_pairs) == (18 if windows else 0)
    gate["verification_stage"] = "original_case_outcomes"
    assert gate["failed_cases"] == gate["errored_cases"] == 0
    gate["checks_passed"] = True
    gate["verification_stage"] = "complete"


def _controls(source: Path, output: Path) -> None:
    result = _attempt(
        source,
        output,
        "controls",
        [
            "-m",
            "pytest",
            "--noconftest",
            "-o",
            "junit_family=legacy",
            "-q",
            *_MODULES,
            "--junitxml",
            str(output / "controls.xml"),
        ],
        180,
    )
    _json(
        output / "process-result.json",
        {
            **result,
            "source_controls_only": True,
            "corpus_or_performance_run": False,
        },
    )
    gate = {
        "checks_passed": False,
        "source_controls_only": True,
        "installed_artifact_qualification": False,
        "historical_handle_attributed": False,
        "product_promotion": False,
        "unicode_delete_sharing_improvement_claimed": False,
        "verification_stage": "not_started",
    }
    try:
        _case_gate(output, gate)
    except (AssertionError, OSError, ValueError, KeyError, TypeError, ET.ParseError) as error:
        gate["verification_error_type"] = type(error).__name__
    finally:
        _json(output / "control-gate.json", gate)
    if result["return_code"] != 0 or result["timed_out"] or not gate["checks_passed"]:
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--expected-python", required=True)
    parser.add_argument("--expected-platform", required=True)
    parser.add_argument("--phase", choices=("before", "static", "controls", "after"), required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(exist_ok=True)
    if args.phase in ("before", "after"):
        _binding(args, args.output)
    elif args.phase == "static":
        _static(args.source.resolve(), args.output)
    else:
        _controls(args.source.resolve(), args.output)


if __name__ == "__main__":
    main()
