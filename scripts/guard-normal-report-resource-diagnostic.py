"""Run the normal report generator and original resource gate on pinned source."""

from __future__ import annotations

import ast
import hashlib
import json
import math
import re
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.etree import ElementTree

BASE = "363b2b8e7b8bf2d05714524ce80051647e765837"
TREE = "b3563e89de1e273e55a116980a7aa2124a4405df"
EXPECTED_FILES = 4128
WORKFLOW = ".github/workflows/ci.yml"
SCRIPT = "scripts/guard-normal-report-resource-diagnostic.py"
REPORT = "tests/fixtures/guard-command-corpus/decision-diff-report.json"
GENERATOR = "tests/guard_command_decision_diff.py"
RESOURCE = "tests/test_guard_command_decision_diff.py"
CASE = "test_fresh_process_report_is_environment_independent_and_bounded"
REPORT_WORKSPACE = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
SOURCE = REPORT_WORKSPACE / "source"
DIAGNOSTIC = REPORT_WORKSPACE / "diagnostic"
OUTPUT = Path(os.environ["RUNNER_TEMP"]) / "guard-normal-report-resource"
EXPECTED_CHANGED_PATHS = (
    "src/codex_plugin_scanner/guard/runtime/mcp_protection.py",
    "src/codex_plugin_scanner/guard/runtime/mcp_server_catalog.py",
    "src/codex_plugin_scanner/guard/runtime/mcp_server_contribution.py",
    "src/codex_plugin_scanner/guard/runtime/mcp_server_grants.py",
)
PINS = {
    GENERATOR: "2150c9eb1da9371966b26cbfd1a8737fbf7e2e64",
    RESOURCE: "8d5fa7b75cb70bfb607075834adc97e1fd46a717",
    "tests/guard_command_decision_diff_runner.py": "3ff1e896e0c0b8a32c57988b7f5914b320b66ba3",
    "tests/fixtures/guard-command-corpus/seed-manifest.json": "f26cda4652a06f51b412486721e2a615f0abdb98",
    "uv.lock": "87a7e665302f34c6ae1100387425572bab6e7c51",
    "pyproject.toml": "dd7ea7046ebb399bde94d1532dce9149437cab43",
    REPORT: "b9da3c75468eba05baf499967fe0b82b5bb2c1d9",
}
SUMMARY: dict[str, object] = {
    "schema": "guard.normal-report-resource.v1",
    "sourceCommit": BASE, "sourceTree": TREE, "expectedSourceFiles": EXPECTED_FILES,
    "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
    "pins": PINS, "expectedSourceBindings": 405,
    "limits": {"corpusCases": 51000, "seconds": 60, "rssMiB": 512, "childSeconds": 75},
    "runner": {"partitions": 32, "workers": 4},
    "rawOutputPublished": False, "reportMetadataHandEdited": False,
    "phases": {}, "complete": False, "sourcePrePostPassed": False,
}
SAFE_CODES = {
    "arguments", "source_entry", "source_path", "source_contents", "source_untracked",
    "source_identity", "source_count", "source_pin", "diagnostic_identity",
    "diagnostic_delta", "binding_expression", "binding_paths", "binding_count",
    "binding_mismatch", "fixture_mismatch", "report_structure", "report_changed", "changed_bindings",
    "generator_failed", "report_check_failed", "resource_incomplete",
    "report_input", "limits_changed", "runtime", "diagnostic_changed",
}
stage = "preflight"


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE, timeout=20)


def inventory(root: Path) -> dict[str, tuple[str, str]]:
    result = {}
    for item in git(root, "ls-tree", "-rz", "HEAD").split(b"\0"):
        if not item:
            continue
        meta, raw_path = item.split(b"\t", 1)
        mode, kind, digest = meta.decode().split()
        name = raw_path.decode()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("source_entry")
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError("source_path")
        result[name] = (mode, digest)
    return result


def verify(root: Path, expected: dict[str, tuple[str, str]]) -> None:
    git(root, "diff", "--cached", "--quiet", "HEAD", "--")
    for name, (mode, digest) in expected.items():
        path = root / name
        info = path.lstat()
        actual_mode = "120000" if stat.S_ISLNK(info.st_mode) else (
            "100755" if info.st_mode & 0o111 else "100644"
        )
        data = os.readlink(path).encode() if mode == "120000" else path.read_bytes()
        if mode != actual_mode or blob(data) != digest:
            raise ValueError("source_contents")
    if git(root, "ls-files", "--others", "--exclude-standard", "-z"):
        raise ValueError("source_untracked")


def source_identity() -> None:
    if (
        git(SOURCE, "rev-parse", "HEAD").decode().strip() != BASE
        or git(SOURCE, "rev-parse", "HEAD^{tree}").decode().strip() != TREE
    ):
        raise ValueError("source_identity")


def runner_capacity() -> dict[str, object]:
    count = os.cpu_count()
    affinity = sorted(os.sched_getaffinity(0))
    memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    if not isinstance(count, int) or count < 1 or not affinity or memory < 1:
        raise ValueError("runtime")
    return {"logicalCpuCount": count, "affinityCpus": affinity, "physicalMemoryBytes": memory}


def execute(command: list[str], output: Path, timeout: int) -> dict[str, object]:
    timed_out = reap_timed_out = False
    with output.open("wb") as stream:
        process = subprocess.Popen(
            command, cwd=SOURCE, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                reap_timed_out = True
                code = process.poll()
    if timed_out:
        SUMMARY["timedOut"] = True
    return {
        "exit": code, "timedOut": timed_out, "reapTimedOut": reap_timed_out,
        "outputSha256": hashlib.sha256(output.read_bytes()).hexdigest(),
    }


def string(node: ast.AST) -> str:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        raise ValueError("binding_expression")
    return node.value


def source_path(node: ast.AST) -> Path:
    if isinstance(node, ast.Name) and node.id == "REPO_ROOT":
        return SOURCE
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return source_path(node.left) / string(node.right)
    if (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "joinpath" and not node.keywords
    ):
        return source_path(node.func.value).joinpath(*(string(arg) for arg in node.args))
    raise ValueError("binding_expression")


def binding_paths(original: dict[str, tuple[str, str]]) -> list[str]:
    module = ast.parse((SOURCE / GENERATOR).read_bytes())
    assignments = [
        item for item in module.body
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)
        and item.target.id == "_EVIDENCE_SOURCE_PATHS"
    ]
    if len(assignments) != 1 or not isinstance(assignments[0].value, ast.Tuple):
        raise ValueError("binding_expression")
    paths = []
    for node in assignments[0].value.elts:
        if isinstance(node, ast.Starred):
            call = node.value
            if (
                not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute)
                or call.func.attr != "glob" or len(call.args) != 1 or call.keywords
            ):
                raise ValueError("binding_expression")
            paths.extend(source_path(call.func.value).glob(string(call.args[0])))
        else:
            paths.append(source_path(node))
    names = sorted({str(path.resolve().relative_to(SOURCE)) for path in paths})
    if len(names) != 405 or any(name not in original for name in names):
        raise ValueError("binding_paths")
    return names


def audit_report(original: dict[str, tuple[str, str]], previous: bytes) -> dict[str, object]:
    payload = (SOURCE / REPORT).read_bytes()
    report, before = json.loads(payload), json.loads(previous)
    if not isinstance(report, dict) or not isinstance(before, dict):
        raise ValueError("report_structure")
    names = binding_paths(original)
    observed, records = {}, []
    for name in names:
        source_id = "source-" + hashlib.sha256(name.encode()).hexdigest()[:24]
        digest = hashlib.sha256((SOURCE / name).read_bytes()).hexdigest()
        observed[source_id] = digest
        records.append({"sourceId": source_id, "gitBlob": original[name][1], "sha256": digest})
    actual = report.get("bindings", {}).get("sources_sha256")
    SUMMARY["sourceBindingAudit"] = {
        "count": len(records), "entries": records, "exact": actual == observed,
    }
    if len(observed) != 405 or actual != observed:
        raise ValueError("binding_mismatch")
    expected_fixtures = {
        name: hashlib.sha256((SOURCE / "tests/fixtures/guard-command-corpus" / name).read_bytes()).hexdigest()
        for name in ("known-gaps.json", "minimal-delta-pairs.json", "seed-manifest.json")
    }
    if report["bindings"].get("fixtures_sha256") != expected_fixtures:
        raise ValueError("fixture_mismatch")
    if set(before.get("bindings", {}).get("sources_sha256", {})) != set(observed):
        raise ValueError("binding_count")
    changed = sorted(key for key in observed if before["bindings"]["sources_sha256"][key] != observed[key])
    expected_changes = {"source-" + hashlib.sha256(name.encode()).hexdigest()[:24] for name in EXPECTED_CHANGED_PATHS}
    SUMMARY["changedSourceBindings"] = changed
    if set(changed) != expected_changes:
        raise ValueError("changed_bindings")
    restored = json.loads(payload)
    restored["bindings"]["sources_sha256"] = before["bindings"]["sources_sha256"]
    if (json.dumps(restored, indent=2, sort_keys=True) + "\n").encode() != previous:
        raise ValueError("report_changed")
    before["bindings"]["sources_sha256"] = {}
    report["bindings"]["sources_sha256"] = {}
    if report != before:
        raise ValueError("report_changed")
    canonical = (json.dumps(json.loads(payload), indent=2, sort_keys=True) + "\n").encode()
    if payload != canonical:
        raise ValueError("report_structure")
    return {
        "blob": blob(payload), "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload),
        "framedSha256": hashlib.sha256(len(payload).to_bytes(8, "big") + payload).hexdigest(),
        "changedSourceBindings": changed, "allOtherReportContentUnchanged": True,
        "fixtureBindingsExact": True, "exactInverseToPreviousBytes": True,
    }


def failure_class(failure: ElementTree.Element) -> str:
    known = {
        "AssertionError": "AssertionError",
        "subprocess.TimeoutExpired": "TimeoutExpired",
        "TimeoutExpired": "TimeoutExpired",
        "subprocess.CalledProcessError": "CalledProcessError",
        "CalledProcessError": "CalledProcessError",
    }
    value = failure.get("type", "")
    if value in known:
        return known[value]
    message = failure.get("message", "")
    for prefix, result in known.items():
        if message.startswith(prefix + ":"):
            return result
    return "OtherFailure"


def finite_metric(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def resource_metrics(failures: list[ElementTree.Element], expected_digest: str) -> dict[str, object]:
    unknown = {"complete": False, "classification": "unavailable"}
    if len(failures) != 1:
        return unknown
    kind = failure_class(failures[0])
    if kind == "TimeoutExpired":
        return {"complete": False, "classification": "child_timeout"}
    if kind != "AssertionError":
        return unknown
    text = failures[0].get("message", "") + "\n" + (failures[0].text or "")
    if len(text) > 32768:
        return {"complete": False, "classification": "bounded_input_exceeded"}
    candidates = list(re.finditer(r"\[\s*\{", text))
    if len(candidates) > 16:
        return {"complete": False, "classification": "ambiguous"}
    valid = {}
    for candidate in candidates:
        start = candidate.start()
        end = text.find("]", start + 1, min(len(text), start + 4096))
        if end == -1:
            continue
        try:
            value = ast.literal_eval(text[start:end + 1])
        except (ValueError, SyntaxError, RecursionError, MemoryError):
            continue
        if (
            type(value) is not list or len(value) != 2
            or any(type(item) is not dict or set(item) != {
                "elapsed_seconds", "rss_mib", "report_framed_sha256",
            } for item in value)
        ):
            continue
        if any(
            not finite_metric(item[name])
            for item in value for name in ("elapsed_seconds", "rss_mib")
        ):
            continue
        if any(
            type(item["report_framed_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", item["report_framed_sha256"]) is None
            or item["report_framed_sha256"] != expected_digest
            for item in value
        ):
            continue
        valid[json.dumps(value, sort_keys=True)] = value
    if len(valid) != 1:
        return {"complete": False, "classification": "ambiguous" if valid else "unavailable"}
    values = next(iter(valid.values()))
    return {
        "complete": True, "classification": "assertion_metrics",
        "metrics": values,
        "elapsedWithinOriginalLimit": [item["elapsed_seconds"] < 60 for item in values],
        "rssWithinOriginalLimit": [item["rss_mib"] < 512 for item in values],
        "digestsMatchGeneratedReport": True,
        "observationalOnly": True,
    }


def resource_result(path: Path, expected_digest: str) -> dict[str, object]:
    counts = {"cases": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    identities_ok = True
    failure_classes = []
    exact_failures = []
    for case in ElementTree.parse(path).getroot().iter("testcase"):
        identity = (
            case.get("classname") == "tests.test_guard_command_decision_diff"
            and case.get("name") == CASE
        )
        identities_ok = identities_ok and identity
        outcome = "errors" if case.findall("error") else (
            "failed" if case.findall("failure") else "skipped" if case.findall("skipped") else "passed"
        )
        counts["cases"] += 1
        counts[outcome] += 1
        for failure in (*case.findall("failure"), *case.findall("error")):
            failure_classes.append(failure_class(failure))
            if identity:
                exact_failures.append(failure)
    return {
        "counts": counts, "identityExact": identities_ok,
        "failureClasses": failure_classes,
        "failureObservation": resource_metrics(exact_failures, expected_digest) if identities_ok else {
            "complete": False, "classification": "unavailable",
        },
        "junitSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "complete": identities_ok and counts["cases"] == 1 and counts["errors"] == counts["skipped"] == 0,
    }


def run(mode: str, version: str) -> int:
    global stage
    if mode not in {"generate", "resource"} or version not in {"3.10", "3.12", "3.13"}:
        raise ValueError("arguments")
    if ".".join(map(str, sys.version_info[:2])) != version or (mode == "generate" and version != "3.12"):
        raise ValueError("runtime")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    if (
        os.environ["GITHUB_REPOSITORY"] != "hashgraph-online/hol-guard"
        or event.get("repository", {}).get("private") is not False
        or os.environ["GITHUB_REF"] != "refs/heads/hgp/diagnostic-normal-report-resource-20260918"
    ):
        raise ValueError("diagnostic_identity")
    SUMMARY.update({"mode": mode, "python": version, "runnerCapacity": runner_capacity()})
    source_identity()
    original = inventory(SOURCE)
    if len(original) != EXPECTED_FILES:
        raise ValueError("source_count")
    for name, sha in PINS.items():
        if original.get(name) != ("100644", sha):
            raise ValueError("source_pin")
    verify(SOURCE, original)
    diagnostic_sha = git(DIAGNOSTIC, "rev-parse", "HEAD").decode().strip()
    if diagnostic_sha != os.environ["GITHUB_SHA"]:
        raise ValueError("diagnostic_identity")
    diagnostic = inventory(DIAGNOSTIC)
    expected_diagnostic = dict(original)
    for name in (WORKFLOW, SCRIPT):
        if diagnostic.get(name, ("", ""))[0] != "100644":
            raise ValueError("diagnostic_delta")
        expected_diagnostic[name] = diagnostic[name]
    if diagnostic != expected_diagnostic:
        raise ValueError("diagnostic_delta")
    verify(DIAGNOSTIC, diagnostic)
    SUMMARY.update({
        "diagnosticCommit": diagnostic_sha,
        "diagnosticTree": git(DIAGNOSTIC, "rev-parse", "HEAD^{tree}").decode().strip(),
        "diagnosticFiles": len(diagnostic), "workflowBlob": diagnostic[WORKFLOW][1],
        "scriptBlob": diagnostic[SCRIPT][1], "sourcePrecheckPassed": True,
    })
    previous = (SOURCE / REPORT).read_bytes()
    SUMMARY["previousReportBlob"] = blob(previous)
    expected = dict(original)
    exit_code = 2
    try:
        with tempfile.TemporaryDirectory(prefix="guard-normal-evidence-", dir=os.environ["RUNNER_TEMP"]) as temporary:
            temporary = Path(temporary)
            if mode == "generate":
                stage = "generator-write"
                phase = execute(["uv", "run", "--no-sync", "python", GENERATOR, "--write"], temporary / "write.log", 75)
                SUMMARY["phases"]["write"] = phase
                SUMMARY["candidateReportBlob"] = blob((SOURCE / REPORT).read_bytes())
                expected[REPORT] = (original[REPORT][0], SUMMARY["candidateReportBlob"])
                if phase["exit"] != 0 or phase["timedOut"]:
                    raise ValueError("generator_failed")
            else:
                stage = "report-input"
                incoming = OUTPUT / "input" / "decision-diff-report.json"
                producer = json.loads((OUTPUT / "input" / "summary.json").read_bytes())
                if (
                    producer.get("sourceCommit") != BASE or producer.get("sourceTree") != TREE
                    or producer.get("diagnosticCommit") != diagnostic_sha
                    or producer.get("scriptBlob") != diagnostic[SCRIPT][1]
                    or producer.get("workflowBlob") != diagnostic[WORKFLOW][1]
                    or producer.get("runId") != os.environ["GITHUB_RUN_ID"]
                    or producer.get("runAttempt") != os.environ["GITHUB_RUN_ATTEMPT"]
                    or producer.get("mode") != "generate" or producer.get("exit") != 0
                    or producer.get("complete") is not True or producer.get("sourcePrePostPassed") is not True
                    or hashlib.sha256(incoming.read_bytes()).hexdigest() != producer.get("report", {}).get("sha256")
                ):
                    raise ValueError("report_input")
                shutil.copyfile(incoming, SOURCE / REPORT)
                SUMMARY["candidateReportBlob"] = blob((SOURCE / REPORT).read_bytes())
                expected[REPORT] = (original[REPORT][0], SUMMARY["candidateReportBlob"])
            stage = "binding-audit"
            SUMMARY["report"] = audit_report(original, previous)
            verify(SOURCE, expected)
            if mode == "generate":
                stage = "generator-check"
                phase = execute(["uv", "run", "--no-sync", "python", GENERATOR, "--check"], temporary / "check.log", 75)
                SUMMARY["phases"]["check"] = phase
                if phase["exit"] != 0 or phase["timedOut"]:
                    raise ValueError("report_check_failed")
                exit_code = 0
            else:
                stage = "resource-test"
                junit = temporary / "resource.xml"
                phase = execute([
                    "uv", "run", "--no-sync", "python", "-m", "pytest", "-q", "--tb=no",
                    "--junitxml=" + str(junit), RESOURCE + "::" + CASE,
                ], temporary / "resource.log", 210)
                SUMMARY["phases"]["resource"] = phase
                if junit.exists():
                    SUMMARY["resourceResult"] = resource_result(junit, SUMMARY["report"]["framedSha256"])
                result = SUMMARY.get("resourceResult", {})
                if (
                    phase["timedOut"] or phase["exit"] not in {0, 1}
                    or result.get("complete") is not True
                    or (phase["exit"] == 0) != (result.get("counts", {}).get("failed") == 0)
                ):
                    raise ValueError("resource_incomplete")
                exit_code = phase["exit"]
    finally:
        pending_stage = stage
        stage = "source-postcheck"
        source_identity()
        verify(SOURCE, expected)
        verify(DIAGNOSTIC, diagnostic)
        if git(DIAGNOSTIC, "rev-parse", "HEAD").decode().strip() != diagnostic_sha:
            raise ValueError("diagnostic_changed")
        SUMMARY["sourcePrePostPassed"] = True
        stage = pending_stage
    SUMMARY["complete"] = True
    if mode == "generate" and exit_code == 0:
        export = OUTPUT / "export"
        export.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / REPORT, export / "decision-diff-report.json")
    return exit_code


def main() -> int:
    os.umask(0o077)
    try:
        if len(sys.argv) != 3:
            raise ValueError("arguments")
        code = run(sys.argv[1], sys.argv[2])
    except BaseException as error:
        name = type(error).__name__
        SUMMARY.update({
            "complete": False, "stage": stage,
            "exceptionClass": name if name in {
                "ValueError", "OSError", "TimeoutExpired", "CalledProcessError",
                "SyntaxError", "ParseError", "KeyError", "TypeError",
            } else "OtherException",
        })
        if type(error) is ValueError and str(error) in SAFE_CODES:
            SUMMARY["failureCode"] = str(error)
        code = 124 if SUMMARY.get("timedOut") is True else 2
    SUMMARY["exit"] = code
    OUTPUT.mkdir(parents=True, exist_ok=True)
    content = json.dumps(SUMMARY, sort_keys=True) + "\n"
    (OUTPUT / "summary.json").write_text(content, encoding="utf-8")
    if SUMMARY.get("mode") == "generate" and code == 0 and SUMMARY.get("complete") is True:
        (OUTPUT / "export" / "summary.json").write_text(content, encoding="utf-8")
    print(content, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
