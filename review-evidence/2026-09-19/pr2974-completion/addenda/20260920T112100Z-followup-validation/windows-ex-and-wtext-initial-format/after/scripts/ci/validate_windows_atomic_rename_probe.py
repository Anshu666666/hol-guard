"""Validate the isolated Windows Ex22 API probe without product promotion."""

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

_FILES = sorted(
    [
        "ci/native_runtime/windows_atomic_rename_probe.py",
        "ci/native_runtime/windows_atomic_rename_probe_child.py",
        "tests/test_windows_atomic_rename_probe.py",
        "tests/test_windows_replaceable_reader_process.py",
    ]
)
_BOUND_FILES = sorted(
    {
        *_FILES,
        "src/codex_plugin_scanner/guard/windows_replaceable_file.py",
        "src/codex_plugin_scanner/guard/private_file_io.py",
        "src/codex_plugin_scanner/guard/adapters/codex_daemon_hook_auth.py",
        "src/codex_plugin_scanner/guard/daemon/manager_pending_launch.py",
        "ci/native_runtime/windows_replaceable_reader_child.py",
        "uv.lock",
        "pyproject.toml",
    }
)
_MODULES = ["tests/test_windows_atomic_rename_probe.py"]
_IMPORTS = [
    "codex_plugin_scanner.guard.private_file_io",
    "codex_plugin_scanner.guard.windows_replaceable_file",
    "codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth",
    "codex_plugin_scanner.guard.daemon.manager",
    "codex_plugin_scanner.guard.daemon.manager_pending_launch",
]
_BASE_SHA = "60619956b77c7770c0e53c474f948be095340ffb"
_BASE_TREE = "375fe06dc5aa6be6191294db38ec4dfba58ec89d"
_TOTAL_CASES = 17


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
    assert actual == _FILES
    assert not _git(source, "status", "--porcelain")
    assert not _git(driver, "status", "--porcelain")
    assert sys.version_info[:3] == (3, 12, 10) and sys.platform == "win32"
    assert sys.implementation.name == "cpython"
    assert Path(sys.prefix).resolve() == (source / ".venv").resolve()
    assert sys.prefix != sys.base_prefix
    records = []
    for name in _BOUND_FILES:
        raw = (source / name).read_bytes()
        blob = _blob(source, "HEAD", name)
        assert raw.replace(b"\r\n", b"\n") == blob
        if name.endswith(".py"):
            assert len(blob.splitlines()) <= 500
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
        "only_four_declared_probe_paths_changed": True,
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
        "unicode_mode_acceptance_unresolved": True,
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
    commands = [
        ("ruff", ["-m", "ruff", "check", *_FILES]),
        ("format", ["-m", "ruff", "format", "--check", *_FILES]),
        ("types", ["-m", "basedpyright", "--pythonversion", "3.12", "--pythonplatform", "Windows", *_FILES]),
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
    if result["return_code"] != 0 or result["timed_out"]:
        raise SystemExit(1)
    xml = ET.parse(output / "controls.xml")
    cases = xml.findall(".//testcase")
    assert len(cases) == _TOTAL_CASES
    assert not xml.findall(".//failure") and not xml.findall(".//error")
    for case in cases:
        _properties(case)
    assert not xml.findall(".//skipped")
    assert all(case.attrib["classname"].endswith("test_windows_atomic_rename_probe") for case in cases)
    groups = {
        "held_reader": ("test_ex_rename_with_actual_held_reader", 4),
        "writer_admission": ("test_ex_writer_admission_and_destination_types", 5),
        "rename_audit": ("test_ex_rename_preserves_original_audit_boundary", 2),
        "source_guards": ("test_ex_source_guards_reject_before_mutation", 3),
        "snapshot_failure": ("test_snapshot_failure_preserves_original_close_then_error", 1),
        "commit_cleanup_report": ("test_native_report_keeps_committed_rename_separate_from_close_failure", 1),
        "absolute_buffer": ("test_ex_buffer_uses_absolute_name_null_root_and_sdk_layout", 1),
    }
    selected = {}
    for group, (prefix, expected) in groups.items():
        selected[group] = [case for case in cases if case.attrib["name"].startswith(prefix)]
        assert len(selected[group]) == expected
    for case in selected["held_reader"]:
        values = _properties(case)
        assert values["reader_retired"] == values["reader_descriptor_closed"] == "True"
        assert values["writer_is_separate_process"] == "True"
    for case in [*selected["held_reader"], *selected["writer_admission"]]:
        values = _properties(case)
        report = json.loads(values["writer_report"])
        assert report["writer_calls"] == report["replace_calls"] == 1
        assert report["original_exception_identity_preserved"] and report["temporary_siblings_removed"]
        assert report["probe"]["writer_snapshot_taken"] and report["probe"]["owned_handles_remaining"] == 0
        capture = json.loads(values["child_capture_writer"])
        assert capture["report_valid"] and capture["process_retired"] and not capture["timed_out"]
        assert capture["return_code"] == int(values["writer_exit_code"])
        assert json.loads(capture["stdout_content"]) == report
    for case in selected["rename_audit"]:
        values = _properties(case)
        reports = []
        for label in ("original", "candidate"):
            report = json.loads(values[f"{label}_report"])
            capture = json.loads(values[f"child_capture_{label}"])
            assert capture["return_code"] == 0 and capture["report_valid"] and capture["process_retired"]
            assert not capture["timed_out"] and json.loads(capture["stdout_content"]) == report
            assert report["probe"]["owned_handles_remaining"] == 0
            reports.append({key: value for key, value in report.items() if key != "probe"})
        assert reports[0] == reports[1]
    _json(
        output / "control-gate.json",
        {
            "total_cases": len(cases),
            "groups": {name: len(rows) for name, rows in selected.items()},
            "failed_or_errored": 0,
            "skipped_cases": 0,
            "source_controls_only": True,
            "installed_artifact_qualification": False,
            "historical_handle_attributed": False,
            "reader_only_repair_rejected": True,
            "unicode_mode_acceptance_unresolved": True,
            "product_promotion": False,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-tree", required=True)
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
