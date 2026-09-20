"""Isolated exact-source renderer controls for RSP-024; no native qualification."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
import traceback
import xml.etree.ElementTree as ET
from contextlib import suppress
from pathlib import Path

EXPECTED = json.loads(r"""
{
  "base_commit": "124472b8949805e0dd36052df6894b335d8b519d",
  "base_tree": "a0c139c4e02535545c5b0e602c240a38affde5fe",
  "source_tree": "bf17840af5147dfc96eef5d68911e7b80330332e",
  "proposal_tree": "ec3c5297007ab00388feb7a49df714a72198eaea",
  "files": [
    {
      "path": "docs/guard/native-runtime-technical-contract-review.md",
      "blob": "b34d9dc359f6927d6e49b8316eb2f3b8edac9497",
      "bytes": 13393,
      "sha256": "8fc53062f5eccaaa33dcc3732f1c07288b1d7e60dbb741f0690dc5b0eb93f1e0"
    },
    {
      "path": "tests/test_native_runtime_delivery_contract.py",
      "blob": "8533affb76b4e80fd64dd7e3e20483ae55d8fac8",
      "bytes": 7696,
      "sha256": "13369e43c55e9fa1e072c200f5ad7986d6713698111a38e249b48ee2bf5c6069"
    },
    {
      "path": "docs/guard/adr/0006-native-rust-runtime-boundary.md",
      "blob": "b164b58036422521704efa12dd5510e12d4cc8c8",
      "bytes": 2635,
      "sha256": "458944e810f0d5a2bed62d02ffdca5dae67ad582c3915391af6763eb84e13419"
    },
    {
      "path": "docs/guard/adr/0007-native-runtime-packaging.md",
      "blob": "0ea63446028f74e706ead22c96d57d623cdeb9b7",
      "bytes": 2812,
      "sha256": "db17e71ff0672668f018eeef242b9fc82cab033ba35bf50a605c4bbec7a89af2"
    },
    {
      "path": "docs/guard/adr/0009-native-and-daemon-critical-failure.md",
      "blob": "a040281dc4cc16744ee03dbac350370fda4ffb37",
      "bytes": 3371,
      "sha256": "ba59792da98c1c5eaf28bba9390db1d156bbb1568f35c9fa36e8a147d3f65e73"
    },
    {
      "path": "docs/guard/adr/0010-native-posttool-default-auto.md",
      "blob": "b00c2b0675ca654d2a6e779aa12ef6b2bdabbd5f",
      "bytes": 2702,
      "sha256": "b025ac3a8cd9f793bb52dabe47644fa0bd17613da2feac29c6b2e5fd84ef43f7"
    },
    {
      "path": "docs/guard/contracts/rust-native-fail-safe-matrix.v1.json",
      "blob": "105a04146848e57e957287a078fb2e645541d183",
      "bytes": 2209,
      "sha256": "02a8393e30a45f000b63eb5266ce326c6b97b6a95194b42114c4d0e842fb4c55"
    },
    {
      "path": "docs/guard/contracts/hook-data-plane-ownership.v2.json",
      "blob": "503ff57930318c3228c5a9d40263642d21f50f95",
      "bytes": 28424,
      "sha256": "e0ba91cb30398b39424e7cf42fca98704823c6bae4c84f760827728800a0dfa1"
    },
    {
      "path": "docs/guard/native-hook-data-plane-ownership.md",
      "blob": "a3bc197df059fddde00a9ba01aa6d38e1c70b7e4",
      "bytes": 13841,
      "sha256": "7436f932d2a86b402ca9c7688a1ded83477378b38e971cdf3d2f69105974a72d"
    },
    {
      "path": "docs/guard/native-approval-enrollment.md",
      "blob": "4daed4595a4e1cdbfaa8e803553b71990ee3ecc0",
      "bytes": 4390,
      "sha256": "2958ce2fcb282536db7742ae98f231a39e2cdc4fde1a6b23f27887086efb2560"
    },
    {
      "path": "docs/guard/native-hook-capability-cleanup.md",
      "blob": "268e9fbe14e3aca2b904e6d12abeb3eff5378f1e",
      "bytes": 4819,
      "sha256": "05550fb967e6e91992f4dbddc132e4ab2790af945bbef814f96e4a361036f643"
    },
    {
      "path": "tests/test_rust_hardening_contracts.py",
      "blob": "97e7204d061e3abda9223cdfff2dbe7cef86b778",
      "bytes": 6734,
      "sha256": "1dabddf0ca8e32eaeedd4380ebb6fad4432e03a24669999c9e0047f7a007c2d5"
    }
  ]
}
""")
DRIVER_PATHS = (
    ".github/workflows/pr2974-rsp024-delivery-validation.yml",
    "scripts/ci/validate_pr2974_rsp024_delivery.py",
)
COHORTS = (
    "tests/test_native_runtime_delivery_contract.py",
    "tests/test_rust_hardening_contracts.py",
    "tests/test_hook_availability_policy.py",
    "tests/test_hook_worker_native_post_tool_watch.py",
    "tests/test_native_route_receipt.py",
    "tests/test_guard_native_qualification_corpus.py",
)
RENDERER_CASES = {
    "test_unavailability_warns_without_creating_native_success": 24,
    "test_integrity_rejection_still_denies_in_both_postures": 12,
    "test_posttool_unavailability_and_completed_block_are_different": 3,
    "test_permission_availability_does_not_invent_an_approval": 4,
    "test_cursor_unavailable_and_malformed_input_keep_distinct_contracts": 2,
    "test_watch_copy_does_not_rewrite_the_native_block": 1,
}
OUT = Path(os.environ["RSP024_EVIDENCE_DIR"]).absolute()
PYTHON = str(Path(".venv/bin/python").absolute())
ENV = dict(os.environ, PYTHONPATH=str(Path("src").resolve()), PYTHONUNBUFFERED="1")
DEADLINE = time.monotonic() + 20 * 60


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, timeout=30).strip()


def file_identity(path: str) -> dict[str, object]:
    data = Path(path).read_bytes()
    return {
        "path": path,
        "blob": hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest(),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def emit(name: str, value: object) -> None:
    data = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"RSP024_RECORD name={name} bytes={len(data)} sha256={digest}", flush=True)
    if len(data) > 65536:
        raise RuntimeError(f"record_limit:{name}")
    for offset in range(0, len(data), 3072):
        encoded = base64.b64encode(data[offset : offset + 3072]).decode()
        print(f"RSP024_BASE64 name={name} offset={offset} data={encoded}", flush=True)


def binding() -> dict[str, object]:
    head, source, base = (git("rev-parse", ref) for ref in ("HEAD", "HEAD^", "HEAD^^"))
    source_tree = git("rev-parse", source + "^{tree}")
    base_tree = git("rev-parse", base + "^{tree}")
    changes = sorted(git("diff", "--name-only", base, source).splitlines())
    driver_changes = sorted(git("diff", "--name-only", source, head).splitlines())
    files = [file_identity(row["path"]) for row in EXPECTED["files"]]
    clean = git("status", "--porcelain", "--untracked-files=no") == ""
    parents = {
        "driver": git("show", "-s", "--format=%P", head).split(),
        "source": git("show", "-s", "--format=%P", source).split(),
    }
    verified = (
        base == EXPECTED["base_commit"]
        and base_tree == EXPECTED["base_tree"]
        and source_tree == EXPECTED["source_tree"]
        and parents == {"driver": [source], "source": [base]}
        and changes == sorted(row["path"] for row in EXPECTED["files"])
        and files == EXPECTED["files"]
        and driver_changes == sorted(DRIVER_PATHS)
        and head == os.environ.get("GITHUB_SHA")
        and platform.system() == "Linux"
        and platform.machine() == "x86_64"
        and sys.version_info[:2] == (3, 12)
        and clean
    )
    return {
        "verified": verified,
        "head": head,
        "driver_tree": git("rev-parse", "HEAD^{tree}"),
        "source": source,
        "source_tree": source_tree,
        "base": base,
        "base_tree": base_tree,
        "parents": parents,
        "source_changes": changes,
        "driver_changes": driver_changes,
        "files": files,
        "driver_files": [file_identity(path) for path in DRIVER_PATHS],
        "tracked_clean": clean,
        "python": sys.version,
        "platform": platform.platform(),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "proposal_tree": EXPECTED["proposal_tree"],
    }


def environment_check() -> None:
    venv = Path(".venv").absolute()
    config = (venv / "pyvenv.cfg").read_bytes()
    record = {
        "executable": str(Path(sys.executable).absolute()),
        "prefix": str(Path(sys.prefix).absolute()),
        "base_prefix": str(Path(sys.base_prefix).absolute()),
        "config_bytes": len(config),
        "config_sha256": hashlib.sha256(config).hexdigest(),
        "python": sys.version,
    }
    record["verified"] = (
        record["executable"] == PYTHON
        and record["prefix"] == str(venv)
        and record["base_prefix"] != str(venv)
        and sys.version_info[:2] == (3, 12)
    )
    emit("environment.json", record)
    if not record["verified"]:
        raise RuntimeError("unexpected_virtualenv")
    imported = []
    for name in (
        "guard.daemon.hook_availability_policy",
        "guard.daemon.hook_worker_native",
        "guard.daemon.hook_worker_responses",
        "guard.native_route_receipt",
    ):
        module = importlib.import_module("codex_plugin_scanner." + name)
        expected = Path("src/codex_plugin_scanner") / (name.replace(".", "/") + ".py")
        actual = Path(module.__file__).resolve()
        imported.append({"module": module.__name__, "path": str(actual), "expected": str(expected.resolve())})
        if actual != expected.resolve():
            emit("imports.json", imported)
            raise RuntimeError("unexpected_product_import")
    emit("imports.json", imported)


def run(name: str, command: list[str], timeout: int) -> dict[str, object]:
    started = time.monotonic()
    remaining = DEADLINE - started - 90
    if remaining <= 0:
        raise TimeoutError("driver_budget_exhausted")
    timeout = min(timeout, max(1, int(remaining)))
    timed_out = False
    group_retired = False
    actual_returncode = None
    try:
        process = subprocess.Popen(
            command, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b"", error.stderr or b""
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
            code = 124
        actual_returncode = process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            group_retired = True
        else:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            code = code or 126
    except OSError as error:
        code, stdout, stderr = 125, b"", str(error).encode()
    for stream, data in (("stdout", stdout), ("stderr", stderr)):
        (OUT / f"{name}.{stream}.log").write_bytes(data)
        if len(data) <= 32768:
            emit(
                f"{name}-{stream}.json",
                {
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "base64": base64.b64encode(data).decode(),
                },
            )
    result = {
        "command": command,
        "exit_code": code,
        "actual_process_returncode": actual_returncode,
        "timed_out": timed_out,
        "timeout_s": timeout,
        "elapsed_s": time.monotonic() - started,
        "direct_process_retired": actual_returncode is not None,
        "process_group_retired": group_retired,
        "containment_scope": "owned_process_group_only",
        "escaped_descendants_proven_retired": False,
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }
    emit(f"{name}-result.json", result)
    return result


def junit() -> dict[str, object]:
    data = (OUT / "pytest.xml").read_bytes()
    root = ET.fromstring(data)
    cases = list(root.iter("testcase"))
    selected = [
        case
        for case in cases
        if case.attrib.get("classname", "").split(".")[-1] == "test_native_runtime_delivery_contract"
    ]
    counts = {name: sum(case.attrib["name"].split("[", 1)[0] == name for case in selected) for name in RENDERER_CASES}
    cohorts = {
        Path(path).stem: sum(case.attrib.get("classname", "").split(".")[-1] == Path(path).stem for case in cases)
        for path in COHORTS
    }
    failures = [
        dict(case.attrib) for case in cases if case.find("failure") is not None or case.find("error") is not None
    ]
    skipped = [dict(case.attrib) for case in cases if case.find("skipped") is not None]
    identities = [(case.attrib.get("classname"), case.attrib.get("name")) for case in cases]
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "total": len(cases),
        "cohorts": cohorts,
        "renderer_case_counts": counts,
        "failures": failures,
        "skipped": skipped,
        "renderer_all46_passed": counts == RENDERER_CASES
        and len(selected) == 46
        and all(case.find(tag) is None for case in selected for tag in ("failure", "error", "skipped")),
        "verified": counts == RENDERER_CASES
        and len(selected) == 46
        and not failures
        and all(case.find("skipped") is None for case in selected)
        and all(cohorts.values())
        and len(set(identities)) == len(identities),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind-only", action="store_true")
    parser.add_argument("--environment-only", action="store_true")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if args.environment_only:
        environment_check()
        return 0
    summary: dict[str, object] = {
        "passed": False,
        "runtime_behavior_changed": False,
        "native_execution_qualified": False,
        "rsp024_complete": False,
    }
    stages = []
    try:
        before = binding()
        emit("source-before.json", before)
        if not before["verified"]:
            raise RuntimeError("source_binding_failed")
        if args.bind_only:
            summary["passed"] = True
        else:
            stages.append(run("environment", [PYTHON, __file__, "--environment-only"], 90))
            if stages[-1]["exit_code"] != 0:
                raise RuntimeError("environment_failed")
            stages.append(
                run(
                    "pytest",
                    [PYTHON, "-m", "pytest", *COHORTS, "-q", "--tb=short", "--junitxml", str(OUT / "pytest.xml")],
                    600,
                )
            )
            if (OUT / "pytest.xml").exists():
                result = junit()
                emit("pytest-junit.json", result)
                summary["junit"] = result
            else:
                result = {"verified": False}
            if stages[-1]["exit_code"] != 0 or not result["verified"]:
                raise RuntimeError("pytest_or_required_cases_failed")
            paths = [COHORTS[0], COHORTS[1], DRIVER_PATHS[1]]
            for name, command in (
                ("ruff", [PYTHON, "-m", "ruff", "check", *paths]),
                ("format", [PYTHON, "-m", "ruff", "format", "--check", *paths]),
                ("types", [PYTHON, "-m", "basedpyright", COHORTS[0]]),
            ):
                stages.append(run(name, command, 180))
                if stages[-1]["exit_code"] != 0:
                    raise RuntimeError(f"{name}_failed")
            summary["passed"] = True
    except Exception as error:
        summary["failure"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    finally:
        try:
            after = binding()
            emit("source-after.json", after)
            if not after["verified"]:
                summary["passed"] = False
        except Exception as error:
            summary["passed"] = False
            summary["binding_cleanup_failure"] = {"type": type(error).__name__, "message": str(error)}
        summary["stages"] = stages
        if not args.bind_only:
            emit("summary.json", summary)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
