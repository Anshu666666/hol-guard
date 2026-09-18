"""Run a frozen tests-only review baseline and emit a closed diagnostic receipt."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.etree import ElementTree

BASE = "9a6e66718892bcbdb6b8bd98ecbdeeb1d79b1e47"
TREE = "56bb19526d5d716a933c2406d55dae4c6bdbe27f"
WORKFLOW = ".github/workflows/ci.yml"
SCRIPT = "scripts/guard-review-regression-diagnostic.py"
BASE_COUNT = 4077
OVERLAY_COUNT = 4085
OVERLAYS = {
    "tests/test_daemon_hook_response_lifecycle.py": "e8ac854c5e3d5dd540bd5c0726700d682e352d1a",
    "tests/test_daemon_refresh_worker_fixture_isolation.py": "f4fb093f05628703924b048c656d08a1cbbbf735",
    "tests/test_policy_bundle_delivery_local_race.py": "a99cb7cada55997852efc4f7437bcdbda51c1308",
    "tests/test_policy_bundle_future_sync_retention.py": "4929c4bdd7aff06f450cfa885cba0d0f2a0b0c82",
    "tests/test_policy_bundle_sync_outcomes.py": "2efefbe43ccede0827fab6c574ade5294c9e6eca",
    "tests/test_policy_generic_validated_ack_retention.py": "a219d8f8710ce12956a5deecee45d17739ade6fd",
    "tests/test_policy_memory_malformed_payload.py": "5b36965f070959ac936049daf7a9b9ff926508d1",
    "tests/test_policy_offline_lifetime_truth.py": "5933d39dece635344d47b88030aebddfe0c155ce",
    "tests/test_policy_sync_rejection_truth.py": "221ab5128f294eed9a971a68dfcd1d414a009bb7",
    "tests/test_policy_upload_ack_current_device.py": "8c909a0ef18822fe587e3a8c0af69197b6be9ee8",
}

EXPECTED_CASES = {
    "tests/test_daemon_hook_response_lifecycle.py": 5,
    "tests/test_daemon_refresh_worker_fixture_isolation.py": 4,
    "tests/test_policy_bundle_delivery_local_race.py": 3,
    "tests/test_policy_bundle_delivery_runtime.py": 8,
    "tests/test_policy_bundle_future_sync_retention.py": 1,
    "tests/test_policy_bundle_sync_outcomes.py": 11,
    "tests/test_policy_generic_validated_ack_retention.py": 10,
    "tests/test_policy_memory_malformed_payload.py": 17,
    "tests/test_policy_offline_lifetime_truth.py": 16,
    "tests/test_policy_signer_rotation_runtime.py": 8,
    "tests/test_policy_sync_rejection_truth.py": 8,
    "tests/test_policy_upload_ack_current_device.py": 11,
}

CONTROLS = {
    "tests/test_policy_bundle_delivery_runtime.py": "538e0cbc25bb311eacc57d6b09f11e63d802e214",
    "tests/test_policy_signer_rotation_runtime.py": "825a741c36eed3593d0b4655ad869eba6a0527c4",
}
ERROR_CLASSES = {
    "AssertionError", "AttributeError", "TypeError", "ValueError", "KeyError",
    "IndexError", "RuntimeError", "OSError", "FileNotFoundError", "PermissionError",
    "TimeoutError", "TimeoutExpired", "CalledProcessError", "ParseError",
    "ImportError", "ModuleNotFoundError", "SyntaxError", "ResponseNotReady", "Failed",
}
DIAGNOSTIC = Path(__file__).resolve().parents[1]
ROOT = DIAGNOSTIC.parent / "source"
DESTINATION = Path(os.environ["HGP_REVIEW_RECEIPT"])
SUMMARY: dict[str, object] = {
    "schema": "guard.review-regression-baseline.v1",
    "baseCommit": BASE,
    "baseTree": TREE,
    "evidenceTier": "E2",
    "installedRuntimeVerified": False,
    "rawOutputPublished": False,
    "sourceObservation": "Whole tracked-file hashes and modes before and after; no import, child, or OS attestation.",
    "expectedFiles": len(EXPECTED_CASES),
    "expectedCases": sum(EXPECTED_CASES.values()),
    "overlayBlobs": OVERLAYS,
    "controlBlobs": CONTROLS,
}
stage = "preflight"


def blob(payload: bytes) -> str:
    header = b"blob " + str(len(payload)).encode() + b"\0"
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def git(root: Path, *arguments: str) -> bytes:
    return subprocess.check_output(
        ["git", *arguments], cwd=root, stderr=subprocess.PIPE, timeout=20,
    )


def inventory(root: Path) -> dict[str, tuple[str, str]]:
    result = {}
    for row in git(root, "ls-tree", "-rz", "HEAD").split(b"\0"):
        if not row:
            continue
        metadata, raw_path = row.split(b"\t", 1)
        mode, kind, digest = metadata.decode().split()
        path = raw_path.decode()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("source_entry_mismatch")
        if Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("source_path_mismatch")
        result[path] = (mode, digest)
    return result


def verify(root: Path, expected: dict[str, tuple[str, str]]) -> None:
    for relative, (mode, digest) in expected.items():
        path = root / relative
        info = path.lstat()
        if mode == "120000":
            if not stat.S_ISLNK(info.st_mode):
                raise ValueError("source_mode_mismatch")
            payload = os.readlink(path).encode()
        else:
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("source_mode_mismatch")
            if bool(info.st_mode & 0o111) != (mode == "100755"):
                raise ValueError("source_mode_mismatch")
            payload = path.read_bytes()
        if blob(payload) != digest:
            raise ValueError("tracked_source_changed")


def frozen_head() -> None:
    if (
        git(ROOT, "rev-parse", "HEAD").decode().strip() != BASE
        or git(ROOT, "rev-parse", "HEAD^{tree}").decode().strip() != TREE
    ):
        raise ValueError("base_mismatch")


def exception_class(error: BaseException) -> str:
    name = type(error).__name__
    return name if name in ERROR_CLASSES else "OtherException"


def failure_class(element: ElementTree.Element) -> str:
    kind = element.get("type", "")
    if kind in ERROR_CLASSES:
        return kind
    message = element.get("message", "")
    for name in sorted(ERROR_CLASSES):
        if message == name or message.startswith(name + ":"):
            return name
    if message.startswith("assert ") or message.startswith("AssertionError"):
        return "AssertionError"
    return "OtherException"


def known_functions() -> dict[str, tuple[str, set[str]]]:
    known = {}
    for path in EXPECTED_CASES:
        module = path.removesuffix(".py").replace("/", ".")
        parsed = ast.parse((ROOT / path).read_bytes(), filename=path)
        functions = {
            node.name for node in parsed.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith("test_")
        }
        if not functions or any(not re.fullmatch(r"test_[a-zA-Z0-9_]+", name) for name in functions):
            raise ValueError("test_definition_mismatch")
        known[module] = (path, functions)
    return known


def summarize(junit: Path, known: dict[str, tuple[str, set[str]]]) -> bool:
    cases = list(ElementTree.parse(junit).getroot().iter("testcase"))
    records = []
    seen: dict[tuple[str, str], int] = {}
    file_counts = {path: 0 for path in EXPECTED_CASES}
    unique_cases = set()
    counts = {"collected": len(cases), "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    for case in cases:
        module, name = case.get("classname", ""), case.get("name", "")
        if module not in known:
            raise ValueError("unexpected_test_module")
        path, functions = known[module]
        function = name.split("[", 1)[0]
        if function not in functions or (name != function and not name.endswith("]")):
            raise ValueError("unexpected_test_function")
        identity = (module, name)
        if identity in unique_cases:
            raise ValueError("duplicate_test_case")
        unique_cases.add(identity)
        key = (path, function)
        ordinal = seen.get(key, 0) + 1
        seen[key] = ordinal
        file_counts[path] += 1
        failures, errors, skipped = case.findall("failure"), case.findall("error"), case.findall("skipped")
        if errors:
            outcome = "errors"
        elif failures:
            outcome = "failed"
        elif skipped:
            outcome = "skipped"
        else:
            outcome = "passed"
        counts[outcome] += 1
        records.append({
            "file": path, "function": function, "parameterOrdinal": ordinal,
            "outcome": outcome,
            "exceptionClasses": sorted({failure_class(item) for item in [*failures, *errors]}),
        })
    expected_functions = {(path, name) for path, functions in known.values() for name in functions}
    selected = (
        file_counts == EXPECTED_CASES and set(seen) == expected_functions
        and not counts["errors"] and not counts["skipped"]
    )
    SUMMARY.update({
        "counts": counts, "fileCounts": file_counts, "cases": records,
        "selectionValid": selected, "junitSha256": hashlib.sha256(junit.read_bytes()).hexdigest(),
    })
    return selected


def run() -> int:
    global stage
    if tuple(sys.version_info[:2]) != (3, 12):
        raise ValueError("interpreter_mismatch")
    diagnostic_commit = git(DIAGNOSTIC, "rev-parse", "HEAD").decode().strip()
    if diagnostic_commit != os.environ.get("GITHUB_SHA"):
        raise ValueError("diagnostic_commit_mismatch")
    diagnostic_tree = git(DIAGNOSTIC, "rev-parse", "HEAD^{tree}").decode().strip()
    diagnostic_inventory = inventory(DIAGNOSTIC)
    diagnostic_paths = [WORKFLOW, SCRIPT, *OVERLAYS]
    diagnostic_expected = {path: diagnostic_inventory[path] for path in diagnostic_paths}
    verify(DIAGNOSTIC, diagnostic_expected)
    SUMMARY.update({
        "diagnosticCommit": diagnostic_commit, "diagnosticTree": diagnostic_tree,
        "workflowBlob": diagnostic_expected[WORKFLOW][1],
        "scriptBlob": diagnostic_expected[SCRIPT][1],
        "workflowSha256": hashlib.sha256((DIAGNOSTIC / WORKFLOW).read_bytes()).hexdigest(),
        "scriptSha256": hashlib.sha256((DIAGNOSTIC / SCRIPT).read_bytes()).hexdigest(),
    })
    frozen_head()
    expected = inventory(ROOT)
    if len(expected) != BASE_COUNT:
        raise ValueError("inventory_mismatch")
    verify(ROOT, expected)
    for path, digest in CONTROLS.items():
        if expected.get(path) != ("100644", digest):
            raise ValueError("control_blob_mismatch")
    for path, digest in OVERLAYS.items():
        payload = (DIAGNOSTIC / path).read_bytes()
        if diagnostic_expected[path] != ("100644", digest) or blob(payload) != digest:
            raise ValueError("test_blob_mismatch")
        destination = ROOT / path
        if path not in expected and destination.exists():
            raise ValueError("unexpected_overlay_destination")
        destination.write_bytes(payload)
        destination.chmod(0o644)
        expected[path] = ("100644", digest)
    if len(expected) != OVERLAY_COUNT:
        raise ValueError("overlay_count_mismatch")
    verify(ROOT, expected)
    known = known_functions()
    SUMMARY["sourcePrecheckPassed"] = True
    with tempfile.TemporaryDirectory(prefix="guard-review-regressions-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        junit, capture = Path(temporary) / "private.xml", Path(temporary) / "private.log"
        stage = "pytest"
        timed_out = False
        try:
            with capture.open("wb") as output:
                with subprocess.Popen(
                    [sys.executable, "-m", "pytest", "-q", "--tb=no", "--junitxml=" + str(junit),
                     *sorted(EXPECTED_CASES)],
                    cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
                ) as process:
                    try:
                        result = process.wait(timeout=600)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        os.killpg(process.pid, signal.SIGKILL)
                        result = process.wait(timeout=10)
                    SUMMARY["pytestExit"] = result
                    SUMMARY["timedOut"] = timed_out
        finally:
            if capture.exists():
                SUMMARY["privateOutputSha256"] = hashlib.sha256(capture.read_bytes()).hexdigest()
            if junit.exists():
                SUMMARY["junitSha256"] = hashlib.sha256(junit.read_bytes()).hexdigest()
            stage = "postcheck"
            frozen_head()
            verify(ROOT, expected)
            verify(DIAGNOSTIC, diagnostic_expected)
            if (
                git(DIAGNOSTIC, "rev-parse", "HEAD").decode().strip() != diagnostic_commit
                or git(DIAGNOSTIC, "rev-parse", "HEAD^{tree}").decode().strip() != diagnostic_tree
            ):
                raise ValueError("diagnostic_base_changed")
            SUMMARY["trackedSourceCount"] = len(expected)
            SUMMARY["sourcePrePostPassed"] = True
        if timed_out:
            SUMMARY["evidenceComplete"] = False
            return 124
        stage = "junit"
        selected = summarize(junit, known)
        complete = selected and result in {0, 1}
        SUMMARY["evidenceComplete"] = complete
        return result if complete else 2


def main() -> int:
    os.umask(0o077)
    try:
        exit_code = run()
    except BaseException as error:
        SUMMARY.update({
            "status": "diagnostic_error", "stage": stage,
            "exceptionClass": exception_class(error), "evidenceComplete": False,
        })
        exit_code = 124 if isinstance(error, subprocess.TimeoutExpired) else 2
    SUMMARY["diagnosticExit"] = exit_code
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    DESTINATION.write_text(json.dumps(SUMMARY, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(SUMMARY, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
