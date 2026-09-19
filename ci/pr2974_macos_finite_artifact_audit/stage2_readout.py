"""Read four pinned failed Stage2 artifacts without rerunning their source or tests."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import stat
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG as AUDITOR, HARNESS, OUTPUT, REPORT, digest, failure, frame, git, headers, parsed, write_json
from download import api, download, population, read_zip

HERE = Path(__file__).resolve().parent
SETTINGS = parsed({"stage2-config.json": (HERE / "stage2-config.json").read_bytes()}, "stage2-config.json")
EMIT_LIMIT = 8 * 1024 * 1024


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def manifest(commit: str, tree: str, parent: str, count: int) -> dict:
    record = api("/git/commits/" + commit)
    assert record["sha"] == commit and record["tree"]["sha"] == tree
    assert [row["sha"] for row in record["parents"]] == [parent]
    value = api("/git/trees/" + tree + "?recursive=1")
    assert value["sha"] == tree and value["truncated"] is False
    rows = {row["path"]: row for row in value["tree"] if row["type"] == "blob"}
    assert len(rows) == count
    assert all(row["mode"] in {"100644", "100755"} for row in rows.values())
    return rows


def source_map(value: dict, expected: dict) -> None:
    assert set(value["files"]) == set(expected)
    for path, row in value["files"].items():
        bound = expected[path]
        assert row["git_blob"] == bound["sha"] and row["mode"] == bound["mode"], path
        assert row["bytes"] == bound["size"], path
        assert re.fullmatch("[0-9a-f]{64}", row["sha256"]), path


def observer_witness(label: str) -> dict:
    assert os.environ["GITHUB_EVENT_NAME"] == "push"
    assert os.environ["GITHUB_REF"] == "refs/heads/" + AUDITOR["branch"]
    assert os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    assert not OUTPUT.is_relative_to(HARNESS)
    commit = git("rev-parse", "HEAD", cwd=HARNESS).decode().strip()
    assert commit == os.environ["GITHUB_SHA"]
    assert headers(commit, HARNESS)["parents"] == [AUDITOR["original_harness_sha"]]
    changes = git("diff-tree", "--no-commit-id", "--name-status", "-r",
                  AUDITOR["original_harness_sha"], commit, cwd=HARNESS).decode().splitlines()
    assert len(changes) == len(AUDITOR["additions"])
    assert set(changes) == {"A\t" + path for path in AUDITOR["additions"]}
    files = {}
    for relative in AUDITOR["additions"]:
        path = HARNESS / relative
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), relative
        raw = path.read_bytes()
        assert raw == git("show", commit + ":" + relative, cwd=HARNESS), relative
        files[relative] = digest(raw)
    for relative, expected in AUDITOR["original_files"].items():
        raw = (HARNESS / relative).read_bytes()
        assert digest(raw) == expected, relative
        assert raw == git("show", commit + ":" + relative, cwd=HARNESS), relative
        files[relative] = digest(raw)
    assert not git("status", "--porcelain", "--untracked-files=all", cwd=HARNESS).strip()
    result = {"observer_sha": commit, "observer_tree": headers(commit, HARNESS)["tree"],
              "observer_parent": AUDITOR["original_harness_sha"], "files": files}
    write_json(REPORT / ("stage2-observer-source-" + label + ".json"), result)
    return result


def original_metadata() -> dict:
    assert os.environ["GITHUB_REPOSITORY"] == SETTINGS["repository"]
    assert sys.version_info[:3] == (3, 12, 13)
    assert sys.flags.isolated == 1 and sys.dont_write_bytecode
    for path, expected in SETTINGS["shared_helpers"].items():
        assert digest((HERE / path).read_bytes()) == expected, path
    run_id = str(SETTINGS["original_run_id"])
    run = api("/actions/runs/" + run_id)
    assert run["id"] == SETTINGS["original_run_id"] and run["run_attempt"] == 1
    for actual, key in (("head_sha", "original_harness_sha"), ("head_branch", "original_branch"),
                        ("name", "original_workflow_name"), ("path", "original_workflow_path")):
        assert run[actual] == SETTINGS[key], actual
    assert run["event"] == "push"
    assert run["repository"]["id"] == run["head_repository"]["id"] == SETTINGS["repository_id"]
    assert (run["status"], run["conclusion"]) == ("completed", "failure")
    jobs = population("/actions/runs/" + run_id + "/attempts/1/jobs", "jobs")
    assert {str(row["id"]): row["name"] for row in jobs} == SETTINGS["original_jobs"]
    by_job = {row["id"]: row for row in jobs}
    artifacts = population("/actions/runs/" + run_id + "/artifacts", "artifacts")
    by_artifact = {row["id"]: row for row in artifacts}
    for pin in SETTINGS["artifacts"]:
        job, item = by_job[pin["job_id"]], by_artifact[pin["id"]]
        assert job["run_id"] == SETTINGS["original_run_id"] and job["run_attempt"] == 1
        assert job["head_sha"] == SETTINGS["original_harness_sha"]
        assert job["status"] == "completed" and job["conclusion"] == "failure"
        assert item["name"] == pin["name"] and item["size_in_bytes"] == pin["bytes"]
        assert item["digest"] == "sha256:" + pin["sha256"] and item["expired"] is False
        assert item["workflow_run"]["id"] == SETTINGS["original_run_id"]
        assert item["workflow_run"]["head_sha"] == SETTINGS["original_harness_sha"]
        assert item["workflow_run"]["head_branch"] == SETTINGS["original_branch"]
    result = {"run": run, "jobs": jobs, "artifacts": artifacts, "only_four_pinned_failed_jobs_read": True}
    write_json(REPORT / "stage2-original-api-metadata.json", result)
    return result


def audit_archive(pin: dict, payloads: dict, source: dict, baseline: dict, harness: dict) -> dict:
    outcome = parsed(payloads, "job-outcome.json")
    assert outcome["job"] == pin["job"] and outcome["status"] == "finished"
    assert outcome["source_sha"] == SETTINGS["source_sha"] and outcome["source_tree"] == SETTINGS["source_tree"]
    assert outcome["harness_sha"] == SETTINGS["original_harness_sha"]
    assert outcome["run_id"] == str(SETTINGS["original_run_id"]) and outcome["run_attempt"] == "1"
    assert outcome["passed"] is False and outcome["workflow_gate_passed"] is False
    assert outcome["source_unchanged"] is True and outcome["qualification_complete"] is False
    before, after = parsed(payloads, "source-before.json"), parsed(payloads, "source-after.json")
    assert before == after
    assert before["source_sha"] == SETTINGS["source_sha"] and before["source_tree"] == SETTINGS["source_tree"]
    assert before["source_parent"] == SETTINGS["baseline_sha"]
    assert before["harness_sha"] == SETTINGS["original_harness_sha"]
    source_map(before, source)
    extra = set(harness) - set(source)
    assert len(extra) == 19 and set(before["harness_files"]) == extra
    for path in set(source):
        assert harness[path]["sha"] == source[path]["sha"] and harness[path]["mode"] == source[path]["mode"]
    for path, row in before["harness_files"].items():
        assert row["git_blob"] == harness[path]["sha"] and row["bytes"] == harness[path]["size"]
        assert re.fullmatch("[0-9a-f]{64}", row["sha256"])
    baseline_current = None
    if pin["kind"] != "gitleaks":
        left, right = parsed(payloads, "baseline-before.json"), parsed(payloads, "baseline-after.json")
        assert left == right
        assert left["commit"] == SETTINGS["baseline_sha"] and left["tree"] == SETTINGS["baseline_tree"]
        source_map(left, baseline)
        assert outcome["baseline_source_unchanged"] is True
        assert payloads["environment-before.json"] == payloads["environment-after.json"]
        baseline_current = True
    index = parsed(payloads, "artifact-manifest.json")
    for path, expected in index.items():
        assert path in payloads and digest(payloads[path]) == expected, path
    assert digest(payloads["log-projection-packet.json"]) == SETTINGS["projection_packets"][pin["kind"]]
    packet = parsed(payloads, "log-projection-packet.json")
    for path, expected in packet["original_files"].items():
        assert path in payloads and digest(payloads[path]) == expected, path
    for step in outcome["steps"]:
        if "log_sha256" in step:
            raw = payloads[step["name"] + ".log"]
            assert digest(raw) == {"sha256": step["log_sha256"], "bytes": step["log_bytes"]}
    for path in ("observed-source-retention-baseline.json", "observed-source-retention-candidate.json"):
        if path in payloads:
            for row in parsed(payloads, path).values():
                assert digest(payloads[row["retained_path"]]) == {"sha256": row["sha256"], "bytes": row["bytes"]}
    names = ["job-outcome.json", "steps.json", "artifact-manifest.json", "source-before.json", "source-after.json"]
    if pin["kind"] != "gitleaks":
        names += ["baseline-before.json", "baseline-after.json", "environment-before.json", "environment-after.json"]
    for name in names:
        frame(pin["label"] + "/" + name, payloads[name], limit=EMIT_LIMIT)
    return {"artifact": pin, "original_outcome": outcome, "all_zip_members_read_and_crc_checked": True,
            "original_manifest_and_projection_file_hashes_verified": True,
            "complete_source_map_matches_immutable_git_tree": True,
            "full_before_after_source_maps_equal": True, "baseline_current": baseline_current,
            "all_retained_fixture_source_bytes_verified": True,
            "independent_all_project_sha256_content_refetch": False,
            "original_failed_job_remains_failed": True, "qualification_complete": False}


def differences(left: object, right: object, path: list, output: list) -> None:
    assert len(output) < 4096, "Comparison differences exceed the explicit bound"
    if type(left) is not type(right):
        output.append({"path": path, "kind": "type", "baseline": left, "candidate": right})
    elif isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                output.append({"path": [*path, key], "kind": "member",
                               "baseline_present": key in left, "candidate_present": key in right,
                               "baseline": left.get(key), "candidate": right.get(key)})
            else:
                differences(left[key], right[key], [*path, key], output)
    elif isinstance(left, list):
        if len(left) != len(right):
            output.append({"path": path, "kind": "list_length", "baseline": left, "candidate": right})
        else:
            for index, (old, new) in enumerate(zip(left, right, strict=True)):
                differences(old, new, [*path, index], output)
    elif left != right:
        output.append({"path": path, "kind": "value", "baseline": left, "candidate": right})


def codex_report(payloads: dict) -> dict:
    names = ["baseline-existing-collection.json", "candidate-existing-collection.json"]
    values = []
    for name in names:
        assert digest(payloads[name]) == SETTINGS["snapshots"][name]
        value = parsed(payloads, name)
        assert value["passed"] is True and value["terminal"] is True and value["exit_code"] == 0
        assert value["mode"] == "collection_only" and value["actual_cases"] == 21
        assert value["collection_complete"] and value["observed_source_files_unchanged"]
        assert not value["body_reports"] and not value["errors"] and not value["refused_execution"]
        assert len(value["comparison"]) == len(value["raw_origins"]) == 21
        frame("stage2-codex/" + name, payloads[name], limit=EMIT_LIMIT)
        values.append(value)
    left, right = values
    mismatches = []
    for index, (old, new) in enumerate(zip(left["comparison"], right["comparison"], strict=True)):
        delta = []
        differences(old, new, [], delta)
        if delta:
            mismatches.append({"index": index, "nodeid": old["nodeid"], "differences": delta,
                               "baseline_row": old, "candidate_row": new,
                               "baseline_origin": left["raw_origins"][index],
                               "candidate_origin": right["raw_origins"][index],
                               "baseline_row_sha256": digest(encoded(old))["sha256"],
                               "candidate_row_sha256": digest(encoded(new))["sha256"]})
    assert [row["index"] for row in mismatches] == SETTINGS["codex_expected_mismatch_indices"]
    assert mismatches[0]["nodeid"] == SETTINGS["codex_expected_node"]
    assert mismatches[0]["baseline_row_sha256"] == SETTINGS["codex_row_sha256"]["baseline"]
    assert mismatches[0]["candidate_row_sha256"] == SETTINGS["codex_row_sha256"]["candidate"]
    report = {"original_collected_cases_each": 21, "unchanged_comparison_rows": 20,
              "exact_recursive_comparison_differences": mismatches,
              "test_bodies_or_seams_executed": False, "normalization_or_source_correction_applied": False,
              "qualification_complete": False}
    raw = encoded(report)
    assert len(raw) <= EMIT_LIMIT
    write_json(REPORT / "stage2-codex-exact-comparison-differences.json", report)
    frame("stage2-codex/exact-comparison-differences.json", raw, limit=EMIT_LIMIT)
    return {"mismatch_indices": [row["index"] for row in mismatches],
            "difference_report": digest(raw), "body_execution": False}


def gitleaks_report(payloads: dict) -> dict:
    findings = parsed(payloads, "gitleaks-findings.json")
    assert isinstance(findings, list) and len(findings) == SETTINGS["gitleaks_findings"] == 4
    result = parsed(payloads, "gitleaks-result.json")
    assert result["findings"] == 4 and result["scan_command_exit"] == 1
    assert result["range"] == SETTINGS["release_base"] + ".." + SETTINGS["source_sha"]
    assert result["default_rule_configuration"] is True and result["dir_fallback"] is False
    redacted = []
    for finding in findings:
        row = dict(finding)
        for name in ("Secret", "Match"):
            if name in row:
                row[name] = "[REDACTED FOR READOUT]"
        redacted.append(row)
    report = {"original_member": digest(payloads["gitleaks-findings.json"]),
              "findings": redacted, "additional_secret_match_redaction_only": True,
              "original_finding_count": 4, "original_scan_exit": 1,
              "original_failed_gate_remains_failed": True, "qualification_complete": False}
    write_json(REPORT / "stage2-gitleaks-findings-redacted.json", report)
    frame("stage2-gitleaks/findings-redacted.json", encoded(report), limit=512 * 1024)
    for name in ("gitleaks-result.json", "gitleaks-binary.json", "range-proof.json",
                 "gitleaks-default-full-range.log", "go-build-info.log"):
        frame("stage2-gitleaks/" + name, payloads[name], limit=EMIT_LIMIT)
    return {"findings": 4, "redacted_report": digest(encoded(report)), "original_scan_exit": 1}


def source_report(payloads: dict) -> dict:
    outcome = parsed(payloads, "job-outcome.json")
    failed = [row for row in outcome["steps"] if not row["passed"]]
    assert [row["name"] for row in failed] == ["scoped-ruff-check"]
    assert failed[0]["returncode"] == 1 and not failed[0]["timed_out"]
    for name in ("scoped-ruff-check.log", "scoped-error-level-types.json", "source-gates-result.json",
                 "physical-line-bounds.json", "corpus-binding-currentness.json", "package-members.json",
                 "command-source-inverse.json", "surface-source-inverse.json"):
        frame("stage2-source/" + name, payloads[name], limit=EMIT_LIMIT)
    return {"failed_original_commands": [row["name"] for row in failed],
            "all_other_original_commands_passed": True, "source_changes_applied": False,
            "original_failed_gate_remains_failed": True, "qualification_complete": False}


def junit_key(nodeid: str) -> tuple[str, str]:
    plain, separator, parameter = nodeid.partition("[")
    parts = plain.split("::")
    assert parts[0].endswith(".py") and len(parts) >= 2
    return (".".join([parts[0][:-3].replace("/", "."), *parts[1:-1]]),
            parts[-1] + (separator + parameter if separator else ""))


def surface_report(payloads: dict) -> dict:
    names = ["baseline-existing-collection.json", "candidate-existing-collection.json",
             "candidate-existing-execution.json"]
    values = []
    for name in names:
        assert digest(payloads[name]) == SETTINGS["surface_snapshots"][name]
        value = parsed(payloads, name)
        assert value["terminal"] and value["collection_complete"] and value["actual_cases"] == 115
        assert value["observed_source_files_unchanged"] and not value["errors"] and not value["refused_execution"]
        assert len(value["comparison"]) == len(value["raw_origins"]) == 115
        assert all(row["outcome"] == "passed" for row in value["collect_reports"])
        if name.endswith("-collection.json"):
            assert value["exit_code"] == 0 and value["mode"] == "collection_only" and not value["body_reports"]
        else:
            assert value["exit_code"] == 1 and value["mode"] == "existing_cases"
            assert value["execution_collection_matches_prior"] is True
            assert value["prior_collection_sha256"] == SETTINGS["surface_snapshots"][names[1]]["sha256"]
        frame("stage2-surface/" + name, payloads[name], limit=EMIT_LIMIT)
        values.append(value)
    baseline, candidate, execution = values
    assert baseline["comparison"] == candidate["comparison"] == execution["comparison"]
    nodes = [row["nodeid"] for row in execution["raw_origins"]]
    assert len(set(nodes)) == 115 and nodes == [row["nodeid"] for row in candidate["raw_origins"]]
    by_node = {node: [] for node in nodes}
    for row in execution["body_reports"]:
        assert row["nodeid"] in by_node and row["wasxfail"] is None
        by_node[row["nodeid"]].append(row)
    failures, skips, passed = [], [], []
    for node, rows in by_node.items():
        phases, outcomes = [row["phase"] for row in rows], [row["outcome"] for row in rows]
        if node == SETTINGS["surface_skip_node"]:
            assert phases == ["setup", "teardown"] and outcomes == ["skipped", "passed"]
            assert SETTINGS["surface_skip_reason"] in rows[0]["longrepr"]
            skips.append(node)
        elif node in SETTINGS["surface_failed_nodes"]:
            assert phases == ["setup", "call", "teardown"] and outcomes == ["passed", "failed", "passed"]
            assert "HTTP Error 400: Bad Request" in rows[1]["longrepr"]
            failures.append(node)
        else:
            assert phases == ["setup", "call", "teardown"] and outcomes == ["passed"] * 3
            passed.append(node)
    assert failures == SETTINGS["surface_failed_nodes"] and skips == [SETTINGS["surface_skip_node"]]
    assert len(passed) == 112
    xml_name = "candidate-existing-execution.xml"
    assert digest(payloads[xml_name]) == SETTINGS["surface_snapshots"][xml_name]
    tree = ET.fromstring(payloads[xml_name])
    suites = [tree] if tree.tag == "testsuite" else list(tree.findall("testsuite"))
    assert suites
    for key, expected in (("tests", 115), ("failures", 2), ("errors", 0), ("skipped", 1)):
        assert sum(int(suite.attrib[key]) for suite in suites) == expected
    cases = [case for suite in suites for case in suite.findall("testcase")]
    assert [(case.attrib["classname"], case.attrib["name"]) for case in cases] == [junit_key(node) for node in nodes]
    for node, case in zip(nodes, cases, strict=True):
        assert not case.findall("error")
        if node in failures:
            assert len(case.findall("failure")) == 1 and not case.findall("skipped")
            assert "HTTP Error 400: Bad Request" in (case.find("failure").text or "")
        elif node in skips:
            assert len(case.findall("skipped")) == 1 and not case.findall("failure")
            assert case.find("skipped").attrib["message"] == SETTINGS["surface_skip_reason"]
        else:
            assert not case.findall("failure") and not case.findall("skipped")
    for name in (xml_name, "candidate-existing-execution.log", "baseline-candidate-collection-comparison.json"):
        frame("stage2-surface/" + name, payloads[name], limit=EMIT_LIMIT)
    report = {"selected_cases": 115, "passed_cases": 112, "failed_cases": 2, "skipped_cases": 1,
              "error_cases": 0, "xfail_cases": 0, "xpass_cases": 0,
              "failed_nodes": failures, "declared_skipped_nodes": skips,
              "all_setup_call_teardown_reports_checked": True, "exact_ordered_junit_bijection": True,
              "all_original_collection_comparison_rows_equal": True,
              "failed_body_reports": [row for row in execution["body_reports"] if row["outcome"] == "failed"],
              "original_failed_gate_remains_failed": True, "failure_cause_attributed": False,
              "no_source_changes_or_reruns": True, "qualification_complete": False}
    write_json(REPORT / "stage2-surface-original-results.json", report)
    frame("stage2-surface/original-results.json", encoded(report), limit=EMIT_LIMIT)
    return report


def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    receipt = {"schema": SETTINGS["schema"], "audit_passed": False, "original_jobs": [],
               "source_code_execution": False, "original_tests_repeated": False, "qualification_complete": False}
    before = None
    try:
        before = observer_witness("before")
        original_metadata()
        source = manifest(SETTINGS["source_sha"], SETTINGS["source_tree"], SETTINGS["source_parent"], 4574)
        baseline = manifest(SETTINGS["baseline_sha"], SETTINGS["baseline_tree"], SETTINGS["baseline_parent"], 4546)
        harness = manifest(SETTINGS["original_harness_sha"], SETTINGS["original_harness_tree"], SETTINGS["source_sha"], 4593)
        for pin in SETTINGS["artifacts"]:
            record = {"artifact": pin, "audit_passed": False}
            try:
                payloads = read_zip(download(pin), pin["label"])
                record.update(audit_archive(pin, payloads, source, baseline, harness))
                callback = {"codex": codex_report, "gitleaks": gitleaks_report,
                            "source": source_report, "surface": surface_report}[pin["kind"]]
                record["readout"] = callback(payloads)
                record["audit_passed"] = True
            except BaseException as error:
                record["audit_error"] = failure(error)
            receipt["original_jobs"].append(record)
        receipt["audit_passed"] = all(row["audit_passed"] for row in receipt["original_jobs"])
    except BaseException as error:
        receipt["error"] = failure(error)
    finally:
        try:
            after = observer_witness("after")
            receipt["observer_source_unchanged"] = before is not None and before == after
            assert receipt["observer_source_unchanged"]
        except BaseException as error:
            receipt["observer_currentness_error"] = failure(error)
            receipt["audit_passed"] = False
        write_json(REPORT / "stage2-artifact-readout.json", receipt)
        frame("stage2-artifact-readout.json", encoded(receipt), limit=EMIT_LIMIT)
    return 0 if receipt["audit_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
