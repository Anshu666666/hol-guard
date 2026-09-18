"""Compare current baseline and candidate semantics without changing resource gates."""

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

BASE = "bc0479bcab1cbc925421c9ebc7a7b926bccd131d"
TREE = "28ad4a5c3f0f3f5860f81a19c150b43aca7b6ba6"
WORKFLOW = ".github/workflows/ci.yml"
SCRIPT = "scripts/guard-performance-semantics-diagnostic.py"
PERF_WORKSPACE = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
DIAGNOSTIC = PERF_WORKSPACE / "diagnostic"
TEST = "tests/test_guard_executable_literal_prefix.py"
TEST_SHA = "45ba97f07d899deb666a1d434da7a40e6094e439"
CHANGES = {
    "src/codex_plugin_scanner/guard/runtime/command_rules.py": (
        "92ac6b419d22d821d75b0e9b2e95cb21ad51e852", "eb5b987102ff6b124adf4134705539b6811673f4",
    ),
    "src/codex_plugin_scanner/guard/runtime/shell_structure.py": (
        "6e75e7829a4622dbca888a575c1d22e8188cb076", "cac15b32c502c024626413c0fbaba91702fee93f",
    ),
}
TESTS = {
    TEST: TEST_SHA,
    "tests/test_guard_command_model.py": "43344bd4d8945ae0d8fbe2dbdf25d448a2dc820c",
    "tests/test_guard_data_flow.py": "17bcbc185bae8b53262f6bc1eff8b7de90bfcfb8",
    "tests/test_guard_shell_read_syntax_fidelity.py": "f03aa8bccb1bcce66cb5d69dce70e1ad9d852e61",
}
PRESERVED = {
    "src/codex_plugin_scanner/guard/runtime/command_option_parsing.py": "e2a0ee5cd39a932b9dddfe7c38db05f65fa49ac9",
    "src/codex_plugin_scanner/guard/runtime/command_model.py": "e9aaa178cca6728b3e6abb2f520286d665a6578f",
    "tests/guard_command_decision_diff_runner.py": "3ff1e896e0c0b8a32c57988b7f5914b320b66ba3",
    "tests/test_guard_command_decision_diff.py": "8d5fa7b75cb70bfb607075834adc97e1fd46a717",
    "tests/fixtures/guard-command-corpus/seed-manifest.json": "f26cda4652a06f51b412486721e2a615f0abdb98",
}
SUMMARY: dict[str, object] = {
    "schema": "guard.performance-semantic-pair.v1", "baseCommit": BASE, "baseTree": TREE,
    "expectedCasesPerSide": 157, "newRegressionCases": 50, "expectedModules": 4,
    "evidenceTier": "E2", "rawOutputPublished": False,
    "performanceMeasured": False, "resourceGateVerified": False,
    "generatorExecuted": False, "reportKnownStale": True, "reportChecked": False,
    "fullCIVerified": False, "sourceOverlays": {"baseline": [TEST], "candidate": [TEST, *CHANGES]},
    "testBlobs": TESTS, "preservedBlobs": PRESERVED, "phases": {},
}
SAFE_CODES = {
    "source_entry", "source_path", "source_contents",
    "source_untracked", "source_commit", "source_tree",
    "test_definitions", "collection_identity", "collection_duplicate",
    "collection_count", "regression_count", "junit_identity",
    "junit_collection_mismatch", "junit_missing", "interpreter", "diagnostic_identity",
    "source_count", "critical_pin", "existing_regression",
    "diagnostic_mode", "diagnostic_delta", "source_inventory",
    "collection_process", "collection_changed", "test_process",
    "test_result", "lint_or_format_process", "diagnostic_changed",
}
stage = "preflight"


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE, timeout=20)


def inventory(root: Path) -> dict[str, tuple[str, str]]:
    values = {}
    for entry in git(root, "ls-tree", "-rz", "HEAD").split(b"\0"):
        if not entry:
            continue
        meta, raw_name = entry.split(b"\t", 1)
        mode, kind, digest = meta.decode().split()
        name = raw_name.decode()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("source_entry")
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError("source_path")
        values[name] = (mode, digest)
    return values


def verify(root: Path, expected: dict[str, tuple[str, str]], *, overlay: bool) -> None:
    for name, (mode, digest) in expected.items():
        path = root / name
        info = path.lstat()
        actual_mode = "120000" if stat.S_ISLNK(info.st_mode) else (
            "100755" if info.st_mode & 0o111 else "100644"
        )
        data = os.readlink(path).encode() if mode == "120000" else path.read_bytes()
        if mode != actual_mode or blob(data) != digest:
            raise ValueError("source_contents")
    unknown = {name.decode() for name in git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0") if name}
    if unknown != ({TEST} if overlay else set()):
        raise ValueError("source_untracked")


def fixed_source(root: Path) -> None:
    if git(root, "rev-parse", "HEAD").decode().strip() != BASE:
        raise ValueError("source_commit")
    if git(root, "rev-parse", "HEAD^{tree}").decode().strip() != TREE:
        raise ValueError("source_tree")


def execute(command: list[str], root: Path, output: Path, timeout: int) -> dict[str, object]:
    timed_out = reap_timed_out = False
    with output.open("wb") as stream:
        process = subprocess.Popen(
            command, cwd=root, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            result = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                result = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                reap_timed_out = True
                result = process.poll()
    if timed_out:
        SUMMARY["timedOut"] = True
    return {
        "exit": result, "timedOut": timed_out, "reapTimedOut": reap_timed_out,
        "outputSha256": hashlib.sha256(output.read_bytes()).hexdigest(),
    }


def functions(root: Path) -> dict[str, set[str]]:
    result = {}
    for name in TESTS:
        parsed = ast.parse((root / name).read_bytes())
        result[name] = {
            item.name for item in parsed.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test_")
        }
        if not result[name] or any(re.fullmatch(r"test_[A-Za-z0-9_]+", value) is None for value in result[name]):
            raise ValueError("test_definitions")
    return result


def collection(path: Path, known: dict[str, set[str]], record: dict[str, object]) -> list[str]:
    identities, seen = [], set()
    unexpected = duplicates = observed = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        name, separator, rest = line.partition("::")
        if not separator or not name.endswith(".py"):
            continue
        observed += 1
        function = rest.split("[", 1)[0]
        if name not in TESTS or function not in known[name] or (rest != function and not rest.endswith("]")):
            unexpected += 1
            continue
        if line in seen:
            duplicates += 1
        seen.add(line)
        identities.append(line)
    seen_functions = {(item.partition("::")[0], item.partition("::")[2].split("[", 1)[0]) for item in identities}
    expected_functions = {(name, function) for name, values in known.items() for function in values}
    new_count = sum(item.startswith(TEST + "::") for item in identities)
    record.update({
        "collected": observed, "unexpectedCollectionIdentities": unexpected,
        "duplicateCollectionIdentities": duplicates, "newRegressionCollected": new_count,
        "collectionFileCounts": {
            name: sum(item.startswith(name + "::") for item in identities) for name in TESTS
        },
        "collectionComplete": (
            observed == len(identities) == 157 and new_count == 50
            and unexpected == 0 and duplicates == 0 and seen_functions == expected_functions
        ),
    })
    return sorted(identities)


def junit_result(path: Path, collected: list[str], known: dict[str, set[str]]) -> dict[str, object]:
    counts = {"cases": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    identities, records, ordinals = [], [], {}
    unexpected = 0
    module_paths = {name.removesuffix(".py").replace("/", "."): name for name in TESTS}
    for case in ElementTree.parse(path).getroot().iter("testcase"):
        outcome = "errors" if case.findall("error") else (
            "failed" if case.findall("failure") else "skipped" if case.findall("skipped") else "passed"
        )
        counts["cases"] += 1
        counts[outcome] += 1
        module, name = case.get("classname", ""), case.get("name", "")
        source = module_paths.get(module)
        function = name.split("[", 1)[0]
        if source is None or function not in known[source]:
            unexpected += 1
            continue
        identities.append(source + "::" + name)
        key = (source, function)
        ordinals[key] = ordinals.get(key, 0) + 1
        records.append({"file": source, "function": function, "parameterOrdinal": ordinals[key], "outcome": outcome})
    matched = unexpected == 0 and sorted(identities) == collected
    return {
        "counts": counts, "cases": records, "unexpectedIdentities": unexpected,
        "identitiesMatchCollection": matched,
        "junitSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "complete": matched and counts["cases"] == 157 and counts["errors"] == 0 and counts["skipped"] == 0,
    }


def run() -> int:
    global stage
    if tuple(sys.version_info[:2]) != (3, 12):
        raise ValueError("interpreter")
    diagnostic_sha = git(DIAGNOSTIC, "rev-parse", "HEAD").decode().strip()
    if diagnostic_sha != os.environ.get("GITHUB_SHA"):
        raise ValueError("diagnostic_identity")
    original = inventory(PERF_WORKSPACE / "baseline")
    if len(original) != 4087:
        raise ValueError("source_count")
    for name, sha in {**PRESERVED, **{name: pair[0] for name, pair in CHANGES.items()}}.items():
        if original.get(name) != ("100644", sha):
            raise ValueError("critical_pin")
    if TEST in original:
        raise ValueError("existing_regression")
    diagnostic = inventory(DIAGNOSTIC)
    expected_diagnostic = {**original, TEST: ("100644", TEST_SHA)}
    for name, pair in CHANGES.items():
        expected_diagnostic[name] = ("100644", pair[1])
    for name in (WORKFLOW, SCRIPT):
        if diagnostic.get(name, ("", ""))[0] != "100644":
            raise ValueError("diagnostic_mode")
        expected_diagnostic[name] = diagnostic[name]
    if diagnostic != expected_diagnostic:
        raise ValueError("diagnostic_delta")
    verify(DIAGNOSTIC, diagnostic, overlay=False)
    SUMMARY.update({
        "diagnosticCommit": diagnostic_sha,
        "diagnosticTree": git(DIAGNOSTIC, "rev-parse", "HEAD^{tree}").decode().strip(),
        "workflowBlob": diagnostic[WORKFLOW][1], "scriptBlob": diagnostic[SCRIPT][1],
        "diagnosticTrackedFiles": len(diagnostic),
    })
    expected_sources = {}
    for label in ("baseline", "candidate"):
        root = PERF_WORKSPACE / label
        fixed_source(root)
        if inventory(root) != original:
            raise ValueError("source_inventory")
        verify(root, original, overlay=False)
        expected = {**original, TEST: ("100644", TEST_SHA)}
        paths = [TEST, *CHANGES] if label == "candidate" else [TEST]
        for name in paths:
            (root / name).write_bytes((DIAGNOSTIC / name).read_bytes())
            if name in CHANGES:
                expected[name] = ("100644", CHANGES[name][1])
        verify(root, expected, overlay=True)
        expected_sources[label] = expected
    SUMMARY["sourcePrecheckPassed"] = True
    results, collections, exits = {}, {}, []
    try:
        with tempfile.TemporaryDirectory(prefix="guard-perf-semantic-", dir=os.environ["RUNNER_TEMP"]) as temporary:
            temp = Path(temporary)
            for label in ("baseline", "candidate"):
                root = PERF_WORKSPACE / label
                known = functions(root)
                stage = label + "-collection"
                output = temp / (label + "-collection.log")
                outcome = execute(["uv", "run", "--no-sync", "python", "-m", "pytest", "--collect-only", "-q", "--color=no", *sorted(TESTS)], root, output, 60)
                record = {"collectionProcess": outcome}
                SUMMARY["phases"][label] = record
                identities = collection(output, known, record)
                if outcome["exit"] != 0 or outcome["timedOut"]:
                    raise ValueError("collection_process")
                if record["collectionComplete"] is not True:
                    raise ValueError("collection_count")
                collections[label] = identities
                record["collectionSha256"] = hashlib.sha256(json.dumps(identities, separators=(",", ":")).encode()).hexdigest()
                record["collected"] = len(identities)
                if label == "candidate" and identities != collections["baseline"]:
                    raise ValueError("collection_changed")
                stage = label + "-pytest"
                junit, output = temp / (label + ".xml"), temp / (label + "-pytest.log")
                outcome = execute(["uv", "run", "--no-sync", "python", "-m", "pytest", "-q", "--tb=no", "--junitxml=" + str(junit), *sorted(TESTS)], root, output, 180)
                record["testProcess"] = outcome
                if junit.exists():
                    record["junitSha256"] = hashlib.sha256(junit.read_bytes()).hexdigest()
                    record["results"] = junit_result(junit, identities, known)
                if outcome["timedOut"] or outcome["exit"] not in {0, 1}:
                    raise ValueError("test_process")
                if "results" not in record:
                    raise ValueError("junit_missing")
                result = record["results"]
                results[label] = result
                if not result["complete"] or (outcome["exit"] == 0) != (result["counts"]["failed"] == 0):
                    raise ValueError("test_result")
                exits.append(outcome["exit"])
            SUMMARY["identicalCollectedIds"] = collections["baseline"] == collections["candidate"]
            SUMMARY["identicalResults"] = results["baseline"]["cases"] == results["candidate"]["cases"]
            stage = "candidate-lint"
            root = PERF_WORKSPACE / "candidate"
            paths = [*CHANGES, TEST]
            for mode, arguments in (("lint", ["check", *paths]), ("format", ["format", "--check", *paths])):
                stage = "candidate-" + mode
                output = temp / (mode + ".log")
                outcome = execute(["uv", "run", "--no-sync", "python", "-m", "ruff", *arguments], root, output, 60)
                SUMMARY[mode] = outcome
                if outcome["timedOut"] or outcome["exit"] not in {0, 1}:
                    raise ValueError("lint_or_format_process")
                exits.append(outcome["exit"])
    finally:
        pending_stage = stage
        stage = "source-postcheck"
        for label, expected in expected_sources.items():
            fixed_source(PERF_WORKSPACE / label)
            verify(PERF_WORKSPACE / label, expected, overlay=True)
        verify(DIAGNOSTIC, diagnostic, overlay=False)
        if git(DIAGNOSTIC, "rev-parse", "HEAD").decode().strip() != diagnostic_sha:
            raise ValueError("diagnostic_changed")
        SUMMARY["sourcePrePostPassed"] = True
        SUMMARY["expectedFilesPerSide"] = 4088
        stage = pending_stage
    SUMMARY["complete"] = True
    return 0 if SUMMARY["identicalResults"] and not any(exits) else 1


def main() -> int:
    os.umask(0o077)
    try:
        result = run()
    except BaseException as error:
        name = type(error).__name__
        SUMMARY.update({
            "complete": False, "stage": stage,
            "exceptionClass": name if name in {"ValueError", "OSError", "TimeoutExpired", "CalledProcessError", "SyntaxError", "ParseError", "KeyError", "TypeError"} else "OtherException",
        })
        if type(error) is ValueError and str(error) in SAFE_CODES:
            SUMMARY["failureCode"] = str(error)
        result = 124 if SUMMARY.get("timedOut") is True else 2
    SUMMARY["exit"] = result
    path = Path(os.environ["HGP_PERF_RECEIPT"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(SUMMARY, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(SUMMARY, sort_keys=True))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
