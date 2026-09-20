"""Bounded exact-source RSP-100 pair validation; no old campaigns or native build."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
import traceback
from contextlib import suppress
from pathlib import Path
from xml.etree import ElementTree

EXPECTED = {
    "schema_version": 1,
    "classification": "bounded_unexecuted_RSP100_pair_validation",
    "product_base": "2ac6b1bd84516c75fc169c7d1c849f9aad7b89bd",
    "product_base_tree": "89c4343c8a528e2abdc0b755b3242f9ae52e6323",
    "reviewed_before_commit": "4d10758e2cb44e5afa72a08aa631a02541dad534",
    "reviewed_before_tree": "fbc00caa3788eb422158a2263a578e83ac626183",
    "proposal_tree": "6d3211d4a06934229bb9fa1f4bb69338fd71f4c2",
    "unchanged_dependency_proof": (
        "Direct full tree comparison: only the two listed non-MCP retirement paths "
        "differ between reviewed before and product base."
    ),
    "base_diff_vs_reviewed": [
        {
            "path": "scripts/native_slo_workspace_poststart_session.py",
            "old": "23d4ae366bcdfcf5aa84f0f4d8cf1b2b52b960ba",
            "new": "4d8760cabd6756719357a864447e5f021acf92b4",
        },
        {
            "path": "tests/test_native_slo_workspace_poststart_session.py",
            "old": "008cc88a1c705a545592c8aca3f4bdfe41e711aa",
            "new": "f4075cdee56f4a4e608427e16638558590a4e6b7",
        },
    ],
    "source_files": [
        {
            "path": "src/codex_plugin_scanner/guard/mcp_request_risk.py",
            "git_blob_sha": "a08b4ab7e1a6086bca9b652741a444add6ddadbe",
            "bytes": 4415,
        },
        {
            "path": "src/codex_plugin_scanner/guard/mcp_risk_dependencies.py",
            "git_blob_sha": "f6968525ef099b0d7606ffd6099fa17683d19bad",
            "bytes": 17870,
        },
        {
            "path": "src/codex_plugin_scanner/guard/mcp_tool_calls.py",
            "git_blob_sha": "59e6f1e04024aa652c913da2cbc594d9ad5a75b0",
            "bytes": 74024,
        },
        {
            "path": "src/codex_plugin_scanner/guard/proxy/runtime_mcp.py",
            "git_blob_sha": "8e5be3a11a1621bedeed63ec0b6341cdb0d77b29",
            "bytes": 189824,
        },
        {
            "path": "tests/test_mcp_invocation_risk_pair.py",
            "git_blob_sha": "fc0f7c5802dc2016350e48da44fcf99328f2f910",
            "bytes": 18042,
        },
        {
            "path": "tests/test_mcp_risk_dependencies.py",
            "git_blob_sha": "2390f86c9dff7648b999f16e1b12c8e9f54b1880",
            "bytes": 11082,
        },
    ],
    "python": "3.12",
    "tests": [
        "tests/test_mcp_risk_dependencies.py",
        "tests/test_mcp_invocation_risk_pair.py",
        "tests/test_mcp_request_risk_facts.py",
        "tests/test_runtime_mcp_authority_callbacks.py",
        "tests/test_runtime_mcp_tool_call_binding.py",
        "tests/test_guard_browser_mcp_intent.py",
        "tests/test_mcp_risk_prefilter.py",
        "tests/test_mcp_package_drain_authority_review.py",
    ],
    "old_campaigns_authorized": False,
    "approval_summary_receipt_complete": False,
    "task_status": "OPEN",
}
DRIVER_PATHS = (
    ".github/workflows/pr2974-rsp100-pair-validation.yml",
    "scripts/ci/validate_pr2974_rsp100_pair.py",
)
OUT = Path(os.environ.get("RSP100_EVIDENCE_DIR", "rsp100-pair-evidence"))
# Keep the executable symlink: resolving it bypasses virtualenv startup selection.
PYTHON = str(Path(".venv/bin/python").absolute())
ENV = dict(os.environ, PYTHONPATH=str(Path("src").resolve()), PYTHONUNBUFFERED="1")
_RUN_DEADLINE = time.monotonic() + 25 * 60


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def blob(path: str) -> dict[str, object]:
    data = Path(path).read_bytes()
    header = f"blob {len(data)}\0".encode()
    return {
        "path": path,
        "bytes": len(data),
        "git_blob_sha": hashlib.sha1(header + data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def emit(name: str, value: object) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    # Finite original JSON records, independently recoverable from job logs.
    if len(data) > 65536:
        raise RuntimeError(f"record_limit:{name}:{len(data)}:{digest}")
    print(f"RSP100_RECORD name={name} bytes={len(data)} sha256={digest}", flush=True)
    for offset in range(0, len(data), 3072):
        print(
            f"RSP100_BASE64 name={name} offset={offset} data="
            + base64.b64encode(data[offset : offset + 3072]).decode(),
            flush=True,
        )


def source_binding() -> dict[str, object]:
    driver = git("rev-parse", "HEAD")
    source = git("rev-parse", "HEAD^")
    base = git("rev-parse", "HEAD^^")
    source_changes = sorted(git("diff", "--name-only", base, source).splitlines())
    driver_changes = sorted(git("diff", "--name-only", source, driver).splitlines())
    actual = [blob(item["path"]) for item in EXPECTED["source_files"]]
    matches = all(
        found["git_blob_sha"] == expected["git_blob_sha"] and found["bytes"] == expected["bytes"]
        for found, expected in zip(actual, EXPECTED["source_files"], strict=True)
    )
    result = {
        "expected": EXPECTED,
        "driver_commit": driver,
        "driver_tree": git("rev-parse", "HEAD^{tree}"),
        "source_commit": source,
        "source_tree": git("rev-parse", source + "^{tree}"),
        "base_commit": base,
        "base_tree": git("rev-parse", base + "^{tree}"),
        "source_changes": source_changes,
        "driver_changes": driver_changes,
        "source_files": actual,
        "driver_files": [blob(path) for path in DRIVER_PATHS],
        "tracked_files_unchanged": git("status", "--porcelain", "--untracked-files=no") == "",
        "source_blobs_match": matches,
        "python_driver": sys.version,
        "platform": platform.platform(),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "workflow_sha": os.environ.get("GITHUB_SHA"),
    }
    result["verified"] = (
        base == EXPECTED["product_base"]
        and result["base_tree"] == EXPECTED["product_base_tree"]
        and source_changes == sorted(item["path"] for item in EXPECTED["source_files"])
        and driver_changes == sorted(DRIVER_PATHS)
        and matches
        and result["tracked_files_unchanged"]
        and driver == os.environ.get("GITHUB_SHA")
    )
    return result


def run(name: str, command: list[str], timeout: int) -> dict[str, object]:
    start = time.monotonic()
    configured_timeout = timeout
    remaining = _RUN_DEADLINE - start - 120  # Reserve result/cleanup time.
    timeout = min(timeout, max(1, int(remaining)))
    timed_out = False
    group_retired = None
    group_signal = None
    actual_returncode = None
    try:
        if remaining <= 0:
            raise TimeoutError("driver_validation_budget_exhausted_before_launch")
        process = subprocess.Popen(
            command, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            group_signal = "SIGKILL"
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b"", error.stderr or b""
                process.stdout.close()
                process.stderr.close()
            code = 124
        actual_returncode = process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            group_retired = True
        else:
            group_retired = False
            group_signal = "SIGKILL"
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                group_retired = True
            # Remaining group members are an explicit failure, even if the
            # direct command exited zero. Do not proceed to another test stage.
            code = code or 126
    except OSError as error:
        code, stdout, stderr = 125, b"", str(error).encode()
    (OUT / f"{name}.stdout.log").write_bytes(stdout)
    (OUT / f"{name}.stderr.log").write_bytes(stderr)
    result = {
        "name": name,
        "command": command,
        "exit_code": code,
        "actual_process_returncode": actual_returncode,
        "timed_out": timed_out,
        "configured_timeout_s": configured_timeout,
        "effective_timeout_s": timeout,
        "validation_budget_exhausted": remaining <= 0,
        "process_group_retired": group_retired,
        "group_signal": group_signal,
        "containment_scope": "driver_process_group_only",
        "escaped_descendant_containment_proven": False,
        "elapsed_s": round(time.monotonic() - start, 6),
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }
    emit(f"{name}-result.json", result)
    # Retain each short original child output exactly in recoverable job records.
    for stream, data in (("stdout", stdout), ("stderr", stderr)):
        if len(data) <= 32768:
            emit(
                f"{name}-{stream}-original.json",
                {
                    "encoding": "base64",
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "data": base64.b64encode(data).decode(),
                },
            )
    return result


IMPORT = """
import hashlib, importlib, json, sys
from pathlib import Path
venv = Path(".venv").absolute()
executable = venv / "bin" / "python"
config_path = venv / "pyvenv.cfg"
config_bytes = config_path.read_bytes() if config_path.is_file() else None
environment = {
    "classification": "child_virtualenv_identity_before_product_import",
    "python": sys.version,
    "executable": str(Path(sys.executable).absolute()),
    "executable_resolved": str(Path(sys.executable).resolve()),
    "prefix": str(Path(sys.prefix).absolute()),
    "base_prefix": str(Path(sys.base_prefix).absolute()),
    "expected_executable": str(executable),
    "expected_prefix": str(venv),
    "pyvenv_config_path": str(config_path),
    "pyvenv_config_bytes": len(config_bytes) if config_bytes is not None else None,
    "pyvenv_config_sha256": hashlib.sha256(config_bytes).hexdigest() if config_bytes is not None else None,
}
environment["verified"] = (
    environment["executable"] == str(executable)
    and environment["prefix"] == str(venv)
    and environment["prefix"] != environment["base_prefix"]
    and config_bytes is not None
)
print(json.dumps(environment, sort_keys=True, allow_nan=False), flush=True)
if not environment["verified"]:
    raise SystemExit(1)
expected = [
    [
        "codex_plugin_scanner.guard.mcp_request_risk",
        "src/codex_plugin_scanner/guard/mcp_request_risk.py"
    ],
    [
        "codex_plugin_scanner.guard.mcp_risk_dependencies",
        "src/codex_plugin_scanner/guard/mcp_risk_dependencies.py"
    ],
    [
        "codex_plugin_scanner.guard.mcp_tool_calls",
        "src/codex_plugin_scanner/guard/mcp_tool_calls.py"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "src/codex_plugin_scanner/guard/proxy/runtime_mcp.py"
    ]
]
loaded = []
for name, path in expected:
    module = importlib.import_module(name)
    actual = Path(module.__file__).resolve()
    wanted = Path(path).resolve()
    loaded.append({"module": name, "actual": str(actual), "expected": str(wanted), "matches": actual == wanted})
from codex_plugin_scanner.guard import mcp_tool_calls as calls
report = {
    "python": sys.version,
    "environment": environment,
    "modules": loaded,
    "all_import_paths_match": all(item["matches"] for item in loaded),
    "available": calls._RISK_PAIR_HELPERS.available,
    "refusal_reason": calls._RISK_PAIR_HELPERS.refusal_reason,
    "binding_count": len(calls._RISK_PAIR_HELPERS._bindings),
}
print(json.dumps(report, sort_keys=True, allow_nan=False))
raise SystemExit(0 if report["available"] and report["all_import_paths_match"]
                 and sys.version_info[:2] == (3, 12) else 1)
"""
TRACE_IMPORT = """
import json, sys
events = []
def trace(frame, event, value):
    if event == "exception" and frame.f_code.co_filename.endswith("/mcp_risk_dependencies.py"):
        if len(events) < 48:
            observed = frame.f_locals.get("value")
            observed_kind = type(observed)
            member = frame.f_locals.get("name")
            events.append({
                "function": frame.f_code.co_name, "line": frame.f_lineno,
                "exception_type": value[0].__name__,
                "observed_value_type": observed_kind.__module__ + "." + observed_kind.__qualname__,
                "member_name": member[:160] if type(member) is str else None,
            })
    return trace
sys.settrace(trace)
try:
    from codex_plugin_scanner.guard import mcp_tool_calls as calls
    result = {"available": calls._RISK_PAIR_HELPERS.available,
              "refusal_reason": calls._RISK_PAIR_HELPERS.refusal_reason}
except BaseException as error:
    result = {"import_exception_type": type(error).__name__}
finally:
    sys.settrace(None)
result.update({"classification": "diagnostic_only_traced_import", "events": events})
print(json.dumps(result, sort_keys=True, allow_nan=False))
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind-only", action="store_true")
    options = parser.parse_args()
    initial = source_binding()
    emit("source-before.json", initial)
    if not initial["verified"]:
        return 2
    if options.bind_only:
        return 0
    results = []
    status = 1
    try:
        first = run("import-admission", [PYTHON, "-c", IMPORT], 180)
        results.append(first)
        if first["timed_out"] or first["process_group_retired"] is False:
            return 1
        if first["exit_code"] != 0:
            results.append(run("diagnostic-import-trace", [PYTHON, "-c", TRACE_IMPORT], 180))
            return 1
        results.append(
            run(
                "focused-pytest",
                [
                    PYTHON,
                    "-m",
                    "pytest",
                    "-q",
                    "--tb=short",
                    "--junitxml=" + str(OUT / "focused.xml"),
                    *EXPECTED["tests"],
                ],
                900,
            )
        )
        if results[-1]["timed_out"] or results[-1]["process_group_retired"] is False:
            return 1
        xml = OUT / "focused.xml"
        counts = {"xml_exists": xml.exists(), "positive_shape_controls_passed": False}
        if xml.exists():
            root = ElementTree.fromstring(xml.read_bytes())
            suites = list(root.iter("testsuite"))
            controls = {}
            for shape in ("plain", "secret", "schema", "description", "browser"):
                name = f"test_production_graph_admits_each_supported_risk_shape[{shape}]"
                found = [case for case in root.iter("testcase") if case.get("name") == name]
                controls[shape] = len(found) == 1 and not any(
                    child.tag in ("failure", "error", "skipped") for child in found[0]
                )
            counts.update(
                {
                    "tests": sum(int(suite.get("tests", "0")) for suite in suites),
                    "failures": sum(int(suite.get("failures", "0")) for suite in suites),
                    "errors": sum(int(suite.get("errors", "0")) for suite in suites),
                    "skipped": sum(int(suite.get("skipped", "0")) for suite in suites),
                    "positive_shape_controls": controls,
                    "positive_shape_controls_passed": all(controls.values()),
                    "xml_sha256": hashlib.sha256(xml.read_bytes()).hexdigest(),
                }
            )
        emit("pytest-counts.json", counts)
        if not counts["positive_shape_controls_passed"]:
            results[-1]["evidence_verified"] = False
            results[-1]["positive_control_evidence_missing"] = True
        paths = [item["path"] for item in EXPECTED["source_files"]]
        results.append(run("ruff", [PYTHON, "-m", "ruff", "check", *paths], 180))
        if results[-1]["timed_out"] or results[-1]["process_group_retired"] is False:
            return 1
        results.append(run("format", [PYTHON, "-m", "ruff", "format", "--check", *paths], 180))
        if results[-1]["timed_out"] or results[-1]["process_group_retired"] is False:
            return 1
        results.append(
            run(
                "typecheck",
                [
                    PYTHON,
                    "-m",
                    "basedpyright",
                    "--level",
                    "error",
                    *[path for path in paths if path.startswith("src/")],
                ],
                600,
            )
        )
        status = int(any(result["exit_code"] != 0 or result.get("evidence_verified") is False for result in results))
    finally:
        after = source_binding()
        emit("source-after.json", after)
        emit(
            "result.json",
            {
                "classification": "bounded_RSP100_pair_functional_validation",
                "source_verified_before": initial["verified"],
                "source_verified_after": after["verified"],
                "stages": results,
                "all_stages_succeeded": (
                    len(results) == 5
                    and all(
                        result["exit_code"] == 0 and result.get("evidence_verified") is not False for result in results
                    )
                    and bool(after["verified"])
                ),
                "approval_summary_receipt_complete": False,
                "RSP100_complete": False,
                "qualification_complete": False,
                "old_campaigns_executed": False,
            },
        )
    return max(status, int(not after["verified"]))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        OUT.mkdir(parents=True, exist_ok=True)
        failure = traceback.format_exc()
        (OUT / "driver-failure.log").write_text(failure)
        emit("driver-failure.json", {"classification": "driver_failure", "traceback": failure})
        raise
