"""Prove the frozen heredoc guard using original tests and corpus gates."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from heredoc_proof_common import (
    BASE_COMMIT, BASE_REPORT, BASE_SHELL, BASE_TREE, FINAL_SHELL, GENERATOR,
    REPORT, SHELL, REQUIRED_IMPORTS, atomic_write, check_sources,
    exception_metadata, framed, frozen_source, git_blob, private_output,
    sha256, source_bytes, source_id,
)
from heredoc_proof_observer import run_pytest_phase


def clean_environment(root, output, map_digest):
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_") or name in {
            "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
            "PYTHONSTARTUP", "PYTHONHOME", "HGP_HEREDOC_NORMAL_AUDIT",
        }:
            del environment[name]
    environment.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join((str(Path(__file__).resolve().parent), str(root / "src"), str(root))),
        "HGP_HEREDOC_SOURCE": str(root), "HGP_HEREDOC_OUTPUT": str(output),
        "HGP_HEREDOC_MAP_SHA256": map_digest,
    })
    return environment


def write_map(output, expected):
    payload = json.dumps({
        "baseCommit": BASE_COMMIT, "baseTree": BASE_TREE, "blobs": expected,
    }, sort_keys=True).encode()
    atomic_write(output / "source-map.json", payload)
    return sha256(payload)


def run_child(command, root, environment, timeout):
    started = time.perf_counter()
    timed_out = False
    with tempfile.TemporaryFile() as captured:
        child = subprocess.Popen(
            command, cwd=root, env=environment, stdout=captured,
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        try:
            code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            code = 124
    return {
        "exitCode": code, "supervisorTimeout": timed_out,
        "supervisorSeconds": timeout, "elapsedWithSupervisorSeconds": time.perf_counter() - started,
    }


def pytest_step(kind, root, output, expected):
    map_digest = write_map(output, expected)
    environment = clean_environment(root, output, map_digest)
    result = run_child(
        [sys.executable, str(Path(__file__).resolve()), "--pytest", kind],
        root, environment, 180,
    )
    receipt_path = output / (kind + ".json")
    if receipt_path.is_file():
        result["receipt"] = json.loads(receipt_path.read_bytes())
    check_sources(root, expected)
    return result


def require_pytest_success(result, count=None):
    receipt = result.get("receipt", {})
    collected = receipt.get("collectedCaseIds", [])
    if (
        result["exitCode"] != 0 or result["supervisorTimeout"]
        or receipt.get("pytestExit") != 0 or not collected
        or receipt.get("failedReports") or receipt.get("skippedCaseIds")
        or receipt.get("collectionErrors") or receipt.get("deselected")
        or receipt.get("passedCaseIds") != collected
        or len(set(collected)) != len(collected)
        or (count is not None and len(collected) != count)
    ):
        raise ValueError("pytest_phase_failed")
    return collected


def apply_guard(root, expected):
    original = source_bytes(root, SHELL)
    before = (
        b"def _heredoc_declarations(line: str) -> tuple[re.Match[str], ...]:\n"
        b"    matches: list[re.Match[str]] = []"
    )
    after = (
        b"def _heredoc_declarations(line: str) -> tuple[re.Match[str], ...]:\n"
        b"    if \"<<\" not in line:\n"
        b"        return ()\n"
        b"    matches: list[re.Match[str]] = []"
    )
    if git_blob(original) != BASE_SHELL or original.count(before) != 1:
        raise ValueError("guard_predecessor_mismatch")
    candidate = original.replace(before, after)
    if git_blob(candidate) != FINAL_SHELL or candidate.replace(after, before) != original:
        raise ValueError("guard_candidate_mismatch")
    atomic_write(root / SHELL, candidate)
    expected[SHELL] = FINAL_SHELL
    check_sources(root, expected)


def accept_generated_report(root, output, expected, original):
    actual = (root / REPORT).read_bytes()
    old = json.loads(original)
    current = json.loads(actual)
    old_bindings = old["bindings"]["sources_sha256"]
    current_bindings = current["bindings"]["sources_sha256"]
    key = source_id(SHELL)
    old_hash = old_bindings[key]
    new_hash = sha256(source_bytes(root, SHELL))
    if (
        len(old_bindings) != 394 or len(current_bindings) != 394
        or key not in current_bindings or old_hash == new_hash
        or current_bindings[key] != new_hash
    ):
        raise ValueError("report_binding_shape_changed")
    token = (json.dumps(key) + ": " + json.dumps(old_hash)).encode()
    replacement = (json.dumps(key) + ": " + json.dumps(new_hash)).encode()
    if original.count(token) != 1 or actual != original.replace(token, replacement):
        raise ValueError("report_changed_beyond_shell_fingerprint")
    identities = {source_id(path): path for path in expected}
    if len(identities) != len(expected):
        raise ValueError("source_identity_collision")
    for identity, digest in current_bindings.items():
        path = identities.get(identity)
        if path is None or sha256(source_bytes(root, path)) != digest:
            raise ValueError("generated_source_binding_mismatch")
    if current["corpus"]["total_count"] != 51000:
        raise ValueError("generated_workload_changed")
    expected[REPORT] = git_blob(actual)
    check_sources(root, expected)
    atomic_write(output / "generated-report.json", actual)
    return {
        "actualNormalWrite": True, "reportBlob": git_blob(actual),
        "reportRawSha256": sha256(actual), "reportFramedSha256": framed(actual),
        "reportSourceBindingCount": len(current_bindings), "fullCorpusCount": 51000,
        "onlyChangedFingerprint": {
            "sourceId": key, "before": old_hash, "after": new_hash,
        },
        "allRemainingReportBytesEqual": True,
    }


def accept_normal_audits(output, expected):
    records = [json.loads(path.read_bytes()) for path in sorted((output / "normal-audits").glob("process-*.json"))]
    workers = [row for row in records if row.get("kind") == "worker"]
    coordinators = [row for row in records if row.get("kind") == "coordinator"]
    required = {source_id(path): expected[path] for path in REQUIRED_IMPORTS}
    if (
        not records or any(not row.get("ok") or row.get("networkDenials")
                           or row.get("sourceDenials") for row in records)
        or len(workers) != 4 or len({row["pid"] for row in workers}) != 4
        or len(coordinators) != 1
        or any(any(row["loadedSources"].get(key) != value for key, value in required.items())
               for row in workers + coordinators)
        or coordinators[0]["loadedSources"].get(source_id(GENERATOR)) != expected[GENERATOR]
    ):
        raise ValueError("normal_process_source_audit_failed")
    return {
        "processRecords": records, "actualWorkerCount": len(workers),
        "actualCoordinatorCount": len(coordinators),
        "observerScope": "Normal report generation only; resource workers have no audit preload.",
    }


def normal_step(root, output, expected, summary):
    original = (root / REPORT).read_bytes()
    if git_blob(original) != BASE_REPORT:
        raise ValueError("normal_report_predecessor_mismatch")
    atomic_write(root / REPORT, original)
    preload = output / "normal-preload"
    preload.mkdir()
    (output / "normal-audits").mkdir()
    (preload / "sitecustomize.py").write_text(
        "from heredoc_proof_observer import install_normal_audit\ninstall_normal_audit()\n"
    )
    map_digest = write_map(output, expected)
    environment = clean_environment(root, output, map_digest)
    environment["PYTHONPATH"] = str(preload) + os.pathsep + environment["PYTHONPATH"]
    environment["HGP_HEREDOC_NORMAL_AUDIT"] = "1"
    environment.update({"PYTHONHASHSEED": "1", "TZ": "UTC", "LC_ALL": "C"})
    result = run_child(
        [sys.executable, str(root / GENERATOR), "--write"], root, environment, 75,
    )
    summary["normalGeneration"] = result
    if result["exitCode"] != 0 or result["supervisorTimeout"]:
        raise ValueError("normal_generator_failed")
    result["report"] = accept_generated_report(root, output, expected, original)
    result["sourceAudits"] = accept_normal_audits(output, expected)
    return result["report"]["reportFramedSha256"]


def supervise():
    wanted = os.environ["HGP_HEREDOC_PYTHON"]
    if wanted not in {"3.10", "3.12"} or ".".join(map(str, sys.version_info[:2])) != wanted:
        raise ValueError("unexpected_interpreter")
    root = Path.cwd().resolve()
    output = Path(os.environ["HGP_HEREDOC_OUTPUT"]).resolve()
    output.relative_to(Path(os.environ["RUNNER_TEMP"]).resolve())
    if output == root or root in output.parents or output in root.parents:
        raise ValueError("unsafe_output_directory")
    output.mkdir(parents=True, exist_ok=False)
    summary = {
        "schema": "guard.heredoc-scan-proof.v1", "sourceBaseCommit": BASE_COMMIT,
        "sourceBaseTree": BASE_TREE, "interpreter": list(sys.version_info[:3]),
        "guardBefore": BASE_SHELL, "guardAfter": FINAL_SHELL,
        "resourceBudgetSeconds": 60, "resourceRssBudgetMiB": 512,
        "resourceChildTimeoutSeconds": 75, "acceptanceBudgetsChanged": False,
        "workloadFiltered": False, "rawOutputPublished": False,
        "resourceWorkersInstrumented": False, "proofPassed": False,
    }
    try:
        expected = frozen_source(root)
        summary["trackedSourceCount"] = len(expected)
        summary["baselineSemantics"] = pytest_step("baseline", root, output, expected)
        baseline_ids = require_pytest_success(summary["baselineSemantics"])
        apply_guard(root, expected)
        summary["candidateSemantics"] = pytest_step("candidate", root, output, expected)
        if require_pytest_success(summary["candidateSemantics"]) != baseline_ids:
            raise ValueError("semantic_collection_changed")
        digest = normal_step(root, output, expected, summary)
        summary["resourceAcceptance"] = pytest_step("resource", root, output, expected)
        require_pytest_success(summary["resourceAcceptance"], 1)
        metrics = summary["resourceAcceptance"]["receipt"]["resourceMetrics"]
        if (
            [row["environmentIndex"] for row in metrics] != [0, 1]
            or any(row["childReturnCode"] != 0 or row["childTimeoutSeconds"] != 75 for row in metrics)
            or any(row["metrics"]["report_framed_sha256"] != digest for row in metrics)
            or any(row["metrics"]["elapsed_seconds"] >= 60 or row["metrics"]["rss_mib"] >= 512 for row in metrics)
        ):
            raise ValueError("resource_receipt_failed")
        check_sources(root, expected)
        summary["finalChangedBlobs"] = {source_id(path): expected[path] for path in (SHELL, REPORT)}
        summary["proofPassed"] = True
    except BaseException as error:
        summary["exception"] = exception_metadata(error)
    finally:
        summary["proofHelperBlobs"] = {
            source_id(path.name): git_blob(path.read_bytes())
            for path in Path(__file__).parent.glob("*heredoc*.py")
        }
        (output / "summary.json").write_text(json.dumps(summary, sort_keys=True))
    return 0 if summary["proofPassed"] else 1


def entry():
    try:
        with private_output():
            os.umask(0o077)
            if sys.argv[1:] == ["--self-test"]:
                from heredoc_proof_controls import self_test

                controls = self_test()
                code = 0
            elif len(sys.argv) == 3 and sys.argv[1] == "--pytest":
                code = run_pytest_phase(sys.argv[2])
            elif not sys.argv[1:]:
                code = supervise()
            else:
                raise ValueError("unsupported_proof_command")
    except BaseException as error:
        print(json.dumps({
            "proofStatus": "error", "exception": exception_metadata(error),
            "rawOutputPublished": False,
        }, sort_keys=True))
        return 2
    receipt = {"proofExit": code, "rawOutputPublished": False}
    if sys.argv[1:] == ["--self-test"]:
        receipt["boundaryControls"] = controls
    print(json.dumps(receipt, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(entry())
