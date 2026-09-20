"""Execute one source-bound parent startup diagnostic without changing its selector."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

BASE = "4afa20cf014ccba918bf2fa61552dafe66767930"
BASE_TREE = "0f924adeb6501adb22f68f82f1c20b9a6e945513"
PYTHON_FILES = [
    "ci/native_runtime/windows_startup_record.py",
    "ci/native_runtime/windows_startup_capture.py",
    "ci/native_runtime/test_windows_startup_capture.py",
]
SELECTOR = (
    "ci/native_runtime/test_native_hook_client_transport.py::"
    "test_native_hook_client_rejects_duplicate_edge_keys_without_fallback"
)
ORIGINAL_FILES = [
    "ci/native_runtime/test_native_hook_client_transport.py",
    "ci/native_runtime/native_hook_client_support.py",
    "pyproject.toml", "uv.lock", "rust/Cargo.toml", "rust/Cargo.lock",
    "rust/crates/guard-runtime/Cargo.toml",
]
CARGO = ["cargo", "--color", "never"]
CONTROL_PREFIX = "native_windows_startup_observation::"


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _load(path: Path) -> Any:
    if path.stat().st_size > 1048576:
        raise ValueError("json_bound")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique)


def _save(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _sha(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _git(where: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(where), *arguments], text=True, timeout=15,
    ).strip()


def _git_bytes(where: Path, revision: str, path: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(where), "show", f"{revision}:{path}"], timeout=15,
    )


def _environment(args: Any) -> dict[str, str]:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env["CARGO_TERM_COLOR"] = "never"
    env["CARGO_TARGET_DIR"] = str(args.target)
    env["HOL_GUARD_BUILD_SHA"] = args.source_sha
    return env


def _attempt(args: Any, label: str, argv: list[str], timeout: int,
             environment: dict[str, str] | None = None) -> dict[str, Any]:
    with (args.output / f"{label}.stdout").open("xb") as stdout, (
        args.output / f"{label}.stderr"
    ).open("xb") as stderr:
        try:
            result = subprocess.run(
                argv, cwd=args.source, env=environment or _environment(args),
                stdout=stdout, stderr=stderr, timeout=timeout, check=False,
            )
            code, timed_out = result.returncode, False
        except subprocess.TimeoutExpired:
            code, timed_out = None, True
    outcome = {
        "label": label, "argv": argv, "returncode": code, "timeout": timed_out,
        "attempts": 1, "complete_descendant_cleanup": False,
    }
    _save(args.output / f"{label}.process.json", outcome)
    return outcome


def _require(outcome: dict[str, Any]) -> None:
    if outcome["returncode"] != 0 or outcome["timeout"]:
        raise RuntimeError("command_failed")


def _binding(args: Any, after: bool) -> None:
    source_sha = _git(args.source, "rev-parse", "HEAD")
    source_tree = _git(args.source, "rev-parse", "HEAD^{tree}")
    parents = _git(args.source, "rev-list", "--parents", "-n", "1", "HEAD").split()
    manifest = _load(args.driver / "startup-diagnostic/source-manifest.json")
    paths = sorted(item["path"] for item in manifest["files"])
    checks = {
        "source_commit": source_sha == args.source_sha,
        "source_tree": source_tree == args.source_tree == manifest["candidate_tree"],
        "sole_original_parent": parents == [source_sha, BASE],
        "base_tree": _git(args.source, "rev-parse", f"{BASE}^{{tree}}") == BASE_TREE,
        "changed_paths": _git(args.source, "diff", "--name-only", "--no-renames", BASE, "HEAD").splitlines() == paths,
        "source_clean": not _git(args.source, "status", "--porcelain"),
        "driver_clean": not _git(args.driver, "status", "--porcelain"),
        "driver_commit": _git(args.driver, "rev-parse", "HEAD") == os.environ["GITHUB_SHA"],
        "interpreter": sys.version_info[:3] == (3, 12, 10) and sys.platform == "win32",
        "venv": Path(sys.prefix).resolve() == (args.source / ".venv").resolve() and sys.prefix != sys.base_prefix,
        "assertions_enabled": sys.flags.optimize == 0,
    }
    members = []
    for item in manifest["files"]:
        path = args.source / item["path"]
        content = path.read_bytes()
        expected = _git_bytes(args.source, "HEAD", item["path"])
        matches = content == expected and len(content) == item["bytes"] and hashlib.sha256(content).hexdigest() == item["sha256"]
        checks[f"member:{item['path']}"] = matches
        members.append({"path": item["path"], "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    for name in ORIGINAL_FILES:
        actual = (args.source / name).read_bytes()
        checks[f"unchanged:{name}"] = actual == _git_bytes(args.source, BASE, name)
    binding = {
        "schema": "pr2974-windows-startup-source-binding.v1",
        "phase": "after" if after else "before",
        "source_sha": source_sha, "source_tree": source_tree, "parents": parents[1:],
        "driver_sha": _git(args.driver, "rev-parse", "HEAD"),
        "driver_tree": _git(args.driver, "rev-parse", "HEAD^{tree}"),
        "python": platform.python_version(), "python_build": sys.version,
        "python_executable": sys.executable, "python_prefix": sys.prefix,
        "python_base_prefix": sys.base_prefix,
        "python_executable_sha256": _sha(Path(sys.executable)),
        "dependencies": sorted(
            [{"name": item.metadata["Name"], "version": item.version} for item in importlib.metadata.distributions()],
            key=lambda item: (item["name"].lower(), item["version"]),
        ),
        "members": members, "checks": checks,
        "workflow_run": os.environ["GITHUB_RUN_ID"],
        "workflow_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "qualification_complete": False,
    }
    _save(args.output / f"source-{'after' if after else 'before'}.json", binding)
    if after:
        before = _load(args.output / "source-before.json")
        changes = {key: before.get(key) == value for key, value in binding.items() if key != "phase"}
        _save(args.output / "binding-comparison.json", {"unchanged": changes, "all_unchanged": all(changes.values())})
        if not all(changes.values()):
            raise RuntimeError("source_or_environment_changed")
    if not all(checks.values()):
        raise RuntimeError("binding_failed")


def _static(args: Any) -> None:
    files = [*PYTHON_FILES, str(Path(__file__)), str(args.driver / "startup-diagnostic/retain_results.py")]
    commands = [
        ("python-format", [sys.executable, "-m", "ruff", "format", "--check", *files]),
        ("python-lint", [sys.executable, "-m", "ruff", "check", *files]),
        ("python-types", [sys.executable, "-m", "basedpyright", "--pythonversion", "3.12",
                          "--pythonplatform", "Windows", *files]),
        ("rust-format", [*CARGO, "fmt", "--manifest-path", "rust/Cargo.toml", "--all", "--check"]),
        ("rust-clippy-default", [*CARGO, "clippy", "--manifest-path", "rust/Cargo.toml",
                                "--locked", "-p", "hol-guard-runtime", "--all-targets", "--", "-D", "warnings"]),
        ("rust-clippy-diagnostic", [*CARGO, "clippy", "--manifest-path", "rust/Cargo.toml",
                                   "--locked", "-p", "hol-guard-runtime", "--all-targets",
                                   "--features", "diagnostic-phases", "--", "-D", "warnings"]),
    ]
    for name, argv in commands:
        _require(_attempt(args, name, argv, 900))


def _junit(path: Path) -> tuple[list[ET.Element], int, int, int]:
    root = ET.parse(path).getroot()
    cases = root.findall(".//testcase")
    names = [(row.attrib["classname"], row.attrib["name"]) for row in cases]
    if len(names) != len(set(names)):
        raise ValueError("duplicate_junit_case")
    for case in cases:
        keys = [item.attrib["name"] for item in case.findall("./properties/property")]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate_junit_property")
    return cases, len(root.findall(".//failure")), len(root.findall(".//error")), len(root.findall(".//skipped"))


def _python_controls(args: Any) -> None:
    module = PYTHON_FILES[-1]
    expected = _load(args.driver / "startup-diagnostic/expected-controls.json")["python_cases"]
    _require(_attempt(args, "python-collection", [sys.executable, "-m", "pytest", "-q", "--collect-only", module], 180))
    listed = [line for line in (args.output / "python-collection.stdout").read_text(encoding="utf-8").splitlines() if line.startswith(module + "::")]
    if len(listed) != expected or len(set(listed)) != expected:
        raise RuntimeError("python_collection_mismatch")
    _require(_attempt(args, "python-controls", [sys.executable, "-m", "pytest", "-q", module,
             "--tb=short", "--junitxml", str(args.output / "python-controls.xml")], 180))
    cases, failures, errors, skipped = _junit(args.output / "python-controls.xml")
    junit_names = [
        case.attrib["classname"].replace(".", "/") + ".py::" + case.attrib["name"]
        for case in cases
    ]
    identity_join = sorted(junit_names) == sorted(listed)
    gate = {"collected": len(listed), "cases": len(cases), "failures": failures,
            "errors": errors, "skipped": skipped, "source_controls_only": True,
            "collected_junit_identity_equal": identity_join,
            "collected_nodes": listed, "junit_nodes": junit_names}
    _save(args.output / "python-control-gate.json", gate)
    if len(cases) != expected or failures or errors or skipped or not identity_join:
        raise RuntimeError("python_controls_failed")


def _rust_controls(args: Any) -> None:
    expected = _load(args.driver / "startup-diagnostic/expected-controls.json")
    results = {}
    for mode in ("default", "diagnostic"):
        command = [*CARGO, "test", "--manifest-path", "rust/Cargo.toml", "--locked",
                   "-p", "hol-guard-runtime"]
        if mode == "diagnostic":
            command += ["--features", "diagnostic-phases"]
        command += [CONTROL_PREFIX]
        _require(_attempt(args, f"rust-{mode}-collection", [*command, "--", "--list"], 900))
        listing = (args.output / f"rust-{mode}-collection.stdout").read_text(encoding="utf-8")
        actual = sorted(line[:-6] for line in listing.splitlines() if line.endswith(": test"))
        if actual != expected[mode]:
            raise RuntimeError("rust_collection_mismatch")
        _require(_attempt(args, f"rust-{mode}-controls", [*command, "--", "--test-threads=1", "--nocapture"], 180))
        text = (args.output / f"rust-{mode}-controls.stdout").read_text(encoding="utf-8")
        passed = sorted(re.findall(r"^test ([^\r\n ]+) \.\.\. ok$", text, re.MULTILINE))
        if passed != expected[mode] or not re.search(
            rf"test result: ok\. {len(actual)} passed; 0 failed; 0 ignored; 0 measured;", text,
        ):
            raise RuntimeError("rust_result_mismatch")
        results[mode] = {"collected": actual, "passed": passed, "failed": 0, "ignored": 0}
    _save(args.output / "rust-control-gate.json", results)


def _build(args: Any) -> None:
    _require(_attempt(args, "diagnostic-build", [*CARGO, "build", "--manifest-path", "rust/Cargo.toml",
             "--locked", "--release", "-p", "hol-guard-runtime", "--features", "diagnostic-phases"], 900))
    runtime = args.target / "release/hol-guard-runtime.exe"
    args.output.joinpath("runtime").mkdir()
    copied = args.output / "runtime/hol-guard-runtime.exe"
    shutil.copyfile(runtime, copied)
    _save(args.output / "runtime-before.json", {
        "path": str(copied), "bytes": copied.stat().st_size, "sha256": _sha(copied),
        "source": args.source_sha, "source_tree": args.source_tree,
        "feature": "diagnostic-phases", "default_artifact_timing": False,
    })


def _decoded(value: dict[str, Any]) -> bytes:
    if value["present"] is not True or value["complete"] is not True:
        raise ValueError("incomplete_original_output")
    raw = base64.b64decode(value["base64"], validate=True)
    if len(raw) != value["bytes"] or hashlib.sha256(raw).hexdigest() != value["sha256"]:
        raise ValueError("original_output_hash")
    return raw


def _workload(args: Any) -> None:
    runtime = (args.output / "runtime/hol-guard-runtime.exe").resolve(strict=True)
    before = _load(args.output / "runtime-before.json")
    if _sha(runtime) != before["sha256"]:
        raise RuntimeError("runtime_changed_before_selector")
    environment = _environment(args)
    environment["HOL_GUARD_NATIVE_BINARY"] = str(runtime)
    environment["HOL_GUARD_WINDOWS_STARTUP_CAPTURE"] = str(args.output / "original-capture.json")
    result = _attempt(args, "original-selector", [
        sys.executable, "-m", "pytest", "-q", SELECTOR, "--tb=short",
        "-p", "ci.native_runtime.windows_startup_capture",
        "--junitxml", str(args.output / "original-selector.xml"),
    ], 90, environment)
    runtime_after_sha = _sha(runtime)
    _save(args.output / "runtime-after.json", {
        "path": str(runtime), "bytes": runtime.stat().st_size, "sha256": runtime_after_sha,
        "unchanged": runtime_after_sha == before["sha256"],
    })
    capture = _load(args.output / "original-capture.json")
    cases, failures, errors, skipped = _junit(args.output / "original-selector.xml")
    sys.path.insert(0, str(args.source))
    parser = importlib.import_module("ci.native_runtime.windows_startup_record")
    if Path(parser.__file__).resolve() != args.source / "ci/native_runtime/windows_startup_record.py":
        raise RuntimeError("parser_import_binding")
    returned = capture.get("returned") or {}
    observation = None
    original_error = None
    if returned.get("kind") == "completed_process":
        stdout = _decoded(returned["stdout"])
        stderr = _decoded(returned["stderr"])
        parsed = parser.parse_stderr(stderr, returned["returncode"])
        original_error = parsed.pop("original_stderr")
        if parsed != returned["observation"]:
            raise RuntimeError("capture_parser_join")
        observation = parsed
        if returned["returncode"] == 0 and json.loads(stdout) != {"error": "native_request_invalid_json", "retryable": False}:
            raise RuntimeError("original_stdout_contract")
    gates = {
        "one_original_case": len(cases) == 1 and cases[0].attrib["name"] == SELECTOR.split("::")[1] and cases[0].attrib["classname"] == SELECTOR.split("::")[0][:-3].replace("/", "."),
        "one_exact_original_call": capture["target_calls"] == capture["exact_calls"] == 1,
        "capture_not_lost": capture["capture_lost"] is False,
        "original_phase_records": set(capture["phases"]) == {"setup", "call", "teardown"},
        "original_stop_observed": capture["original_stop_calls"] == 1,
        "parent_record_valid": observation is not None and observation["status"] == "valid",
        "runtime_unchanged": runtime_after_sha == before["sha256"],
        "original_pytest_success": result["returncode"] == capture["original_pytest_exit"] == 0 and not result["timeout"],
        "original_junit_success": failures == errors == skipped == 0,
    }
    _save(args.output / "original-selector-gate.json", {
        "gates": gates, "original_pytest": result, "original_assertions_preserved": True,
        "original_failure_reproduced": returned.get("returncode") == 2 and original_error == b"native_resident_start_timeout\n",
        "parent_observation": observation,
        "child_observed": False, "child_cause_available": False,
        "complete_descendant_cleanup": False, "headline_timing_eligible": False,
        "qualification_complete": False,
        "historical_cohort_cause_resolved": False,
    })
    if not all(gates.values()):
        raise RuntimeError("original_selector_or_observation_failed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "driver", "output", "target"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    for name in ("source-sha", "source-tree"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--phase", choices=("before", "static", "python", "rust", "build", "workload", "after"), required=True)
    args = parser.parse_args()
    for name in ("source", "driver", "output", "target"):
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(exist_ok=True)
    try:
        if args.phase in ("before", "after"):
            _binding(args, args.phase == "after")
        else:
            actions = {"static": _static, "python": _python_controls, "rust": _rust_controls,
                       "build": _build, "workload": _workload}
            actions[args.phase](args)
    except Exception as error:
        _save(args.output / f"driver-error-{args.phase}.json", {
            "phase": args.phase, "error_kind": type(error).__name__,
            "original_result_unchanged": True, "qualification_complete": False,
        })
        raise


if __name__ == "__main__":
    main()
