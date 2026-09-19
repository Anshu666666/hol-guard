"""Read two original RSP-131 reports as data; do not repeat the owned-child control."""

from __future__ import annotations

import collections
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import zipfile

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text())
SHARED = HERE
sys.path.insert(0, str(SHARED))
from common import CONFIG as SHARED_CONFIG
from common import HARNESS, OUTPUT, REPORT, SOURCE, digest, failure, frame, git, headers, parsed, write_json
from download import api, download, population, read_zip

MEMBERS = {"job-outcome.json", "owned-inode-report.json"}

def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def tree_hash(files: dict[str, dict[str, object]]) -> str:
    root = {}
    for path, row in files.items():
        target = root
        parts = path.split("/")
        for name in parts[:-1]:
            target = target.setdefault(name, {})
        assert parts[-1] not in target
        target[parts[-1]] = (row["mode"], row["git_blob"])

    def visit(node):
        rows = []
        for name, value in node.items():
            directory = isinstance(value, dict)
            mode, sha = ("40000", visit(value)) if directory else value
            rows.append((name + "/" if directory else name,
                         (mode + " " + name).encode() + b"\0" + bytes.fromhex(sha)))
        payload = b"".join(row[1] for row in sorted(rows, key=lambda row: row[0].encode()))
        return hashlib.sha1(b"tree " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
    return visit(root)


def source_witness(label: str) -> dict[str, object]:
    assert SOURCE != HARNESS and not SOURCE.is_relative_to(HARNESS) and not HARNESS.is_relative_to(SOURCE)
    assert not OUTPUT.is_relative_to(SOURCE) and not OUTPUT.is_relative_to(HARNESS)
    assert os.environ["GITHUB_REPOSITORY"] == CONFIG["repository"] == SHARED_CONFIG["repository"]
    assert os.environ["GITHUB_EVENT_NAME"] == "push" and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    assert os.environ["GITHUB_REF"] == "refs/heads/" + CONFIG["observer_branch"]
    assert git("rev-parse", "HEAD", cwd=SOURCE).decode().strip() == CONFIG["source_sha"]
    assert headers(CONFIG["source_sha"], SOURCE) == {
        "tree": CONFIG["source_tree"], "parents": [CONFIG["source_parent"]]}
    harness = git("rev-parse", "HEAD", cwd=HARNESS).decode().strip()
    assert harness == os.environ["GITHUB_SHA"]
    assert headers(harness, HARNESS)["parents"] == [CONFIG["observer_parent"]]
    assert headers(CONFIG["observer_parent"], HARNESS) == {
        "tree": CONFIG["observer_parent_tree"], "parents": [CONFIG["observer_parent_parent"]]}
    changed = git("diff-tree", "--no-commit-id", "--name-status", "-r",
                  CONFIG["observer_parent"], harness, cwd=HARNESS).decode().splitlines()
    assert set(changed) == {"A\t" + name for name in CONFIG["observer_added_paths"]}
    assert len(changed) == len(CONFIG["observer_added_paths"])
    assert set(CONFIG["observer_added_paths"]) == set(SHARED_CONFIG["added_paths"])
    for name, expected in CONFIG["shared_helper_sha256"].items():
        assert digest((SHARED / name).read_bytes())["sha256"] == expected, name
    files = {}
    for entry in git("ls-tree", "-rz", "--full-tree", "HEAD", cwd=SOURCE).split(b"\0"):
        if not entry:
            continue
        prefix, raw = entry.split(b"\t", 1)
        mode, kind, expected_blob = prefix.decode().split()
        path = raw.decode()
        assert kind == "blob" and mode in {"100644", "100755"}
        target = SOURCE / path
        info = target.lstat()
        assert stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111) == (mode == "100755")
        data = target.read_bytes()
        assert blob(data) == expected_blob, path
        files[path] = {"git_blob": expected_blob, "mode": mode, **digest(data)}
    assert len(files) == CONFIG["tracked_files"] == 4559
    assert tree_hash(files) == CONFIG["source_tree"]
    for root in (SOURCE, HARNESS):
        assert not git("status", "--porcelain", "--untracked-files=all", cwd=root).strip()
    result = {"source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"], "files": files}
    write_json(REPORT / ("source-" + label + ".json"), result)
    return result


def original_metadata() -> None:
    run = api("/actions/runs/" + str(CONFIG["original_run_id"]))
    for key, expected in {
        "id": CONFIG["original_run_id"], "run_attempt": 1, "head_sha": CONFIG["source_sha"],
        "head_branch": CONFIG["original_branch"], "event": "push", "status": "completed",
        "conclusion": "success", "name": CONFIG["original_workflow_name"],
        "path": CONFIG["original_workflow_path"],
    }.items():
        assert run[key] == expected, key
    assert run["repository"]["id"] == run["head_repository"]["id"] == CONFIG["repository_id"]
    jobs = population("/actions/runs/" + str(CONFIG["original_run_id"]) + "/attempts/1/jobs", "jobs")
    assert len(jobs) == 1
    job = jobs[0]
    for key, expected in {
        "id": CONFIG["original_job_id"], "name": CONFIG["original_job_name"], "run_attempt": 1,
        "run_id": CONFIG["original_run_id"], "head_sha": CONFIG["source_sha"],
        "status": "completed", "conclusion": "success",
    }.items():
        assert job[key] == expected, key
    for name, outcome in CONFIG["original_step_outcomes"].items():
        rows = [row for row in job["steps"] if row["name"] == name]
        assert len(rows) == 1 and rows[0]["status"] == "completed" and rows[0]["conclusion"] == outcome, name
    artifacts = population("/actions/runs/" + str(CONFIG["original_run_id"]) + "/artifacts", "artifacts")
    assert len(artifacts) == 1
    actual, pin = artifacts[0], CONFIG["artifact"]
    assert actual["id"] == pin["id"] and actual["name"] == pin["name"]
    assert actual["size_in_bytes"] == pin["bytes"] and actual["digest"] == "sha256:" + pin["sha256"]
    assert actual["expired"] is False
    assert actual["workflow_run"]["id"] == CONFIG["original_run_id"]
    assert actual["workflow_run"]["head_sha"] == CONFIG["source_sha"]
    write_json(REPORT / "original-metadata.json", {"run": run, "jobs": jobs, "artifacts": artifacts})


def original_archive() -> dict[str, bytes]:
    path = download(CONFIG["artifact"])
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        inventory = [{"name": info.filename, "bytes": info.file_size, "compressed_bytes": info.compress_size,
                      "crc32": info.CRC, "directory": info.is_dir()} for info in infos]
        write_json(REPORT / "zip-preflight.json", {"archive": digest(path.read_bytes()), "members": inventory})
        assert len(infos) == 2 and {info.filename for info in infos} == MEMBERS, "Unexpected original report members"
        assert all(not info.is_dir() and 0 < info.file_size <= 4 * 1024 * 1024 for info in infos)
        assert sum(info.file_size for info in infos) <= 8 * 1024 * 1024
    payloads = read_zip(path, "original-rsp131")
    assert set(payloads) == MEMBERS
    return payloads


def control_summary(owned: dict, job: dict, name: str, expected: int, junit_name: str) -> dict:
    row = owned.get(name)
    if row is None:
        return {"record_present": False, "expected_cases": expected}
    assert isinstance(row, dict) and type(row["cases"]) is int and 0 <= row["cases"] <= 256
    records = row["case_records"]
    assert isinstance(records, list) and len(records) == row["cases"]
    assert all(isinstance(case, dict) and isinstance(case["class"], str) and isinstance(case["name"], str)
               and case["outcome"] in {"passed", "failed", "error", "skipped"} for case in records)
    outcomes = dict(collections.Counter(case["outcome"] for case in records))
    families = dict(collections.Counter(case["name"].split("[", 1)[0] for case in records))
    assert outcomes == row["outcomes"] and families == row["families"]
    assert type(row["passed"]) is bool
    assert row["junit_sha256"] == job[junit_name]["sha256"]
    assert job[junit_name]["complete"] is True
    return {
        "record_present": True, "cases": row["cases"], "outcomes": outcomes,
        "reported_passed": row["passed"], "expected_cases": expected,
        "recorded_case_count_matches_expectation": row["cases"] == expected,
        "unique_case_identities": len({(case["class"], case["name"]) for case in records}),
        "junit_sha256": row["junit_sha256"], "junit_bytes": job[junit_name]["bytes_read"],
        "case_records_retained_in_full_original_report": True, "original_junit_bytes_in_archive": False,
    }


def inspect_reports(payloads: dict[str, bytes]) -> dict[str, object]:
    job = parsed(payloads, "job-outcome.json")
    owned = parsed(payloads, "owned-inode-report.json")
    assert isinstance(job, dict) and isinstance(owned, dict)
    # Export the exact original normalized JSON before interpreting its reported counts or refusal.
    for name in sorted(MEMBERS):
        frame("rsp131-original-" + name, payloads[name], limit=4 * 1024 * 1024)
    for value in (job, owned):
        assert value["workflow_commit"] == CONFIG["source_sha"]
        assert value["workflow_run"] == str(CONFIG["original_run_id"])
        assert value["workflow_attempt"] == "1"
        assert value["feasible"] is True
        for name in ("installed_workload", "rsp131_qualified", "sqlite_ingestion_observed",
                     "physical_device_bytes_measured"):
            assert value[name] is False, name
    assert job["status"] == "finished"
    assert job["legacy_finite_status"] == job["new_finite_status"] == "success"
    assert job["owned_probe_status"] == "success"
    assert job["owned_report_sha256"] == digest(payloads["owned-inode-report.json"])["sha256"]
    assert owned["schema"] == "hol-guard.rsp131-owned-inode-driver.v1"
    assert owned["legacy_source_commit"] == "67d90ff0211dbc1d878499b90eecb126da98b7fb"
    return {
        "original_workflow_outcome": "success", "original_owned_probe_step": "success",
        "original_report_status": owned.get("status"),
        "original_error_type": owned.get("error_type"), "original_reason": owned.get("reason"),
        "original_errno": owned.get("errno"),
        "legacy_controls": control_summary(owned, job, "legacy_controls", 111, "legacy.junit.xml"),
        "new_controls": control_summary(owned, job, "new_controls", 92, "new.junit.xml"),
        "source_unchanged_reported": owned.get("source_unchanged"),
        "legacy_source_unchanged_reported": owned.get("legacy_source_unchanged"),
        "environment_unchanged_reported": owned.get("environment_unchanged"),
        "recorded_command_count": len(owned.get("commands", [])),
        "inner_observation_present": "observation" in owned,
        "original_zip_size_and_sha256_verified": True,
        "exact_two_json_members_and_all_crc_verified": True,
        "original_full_normalized_reports_emitted": True,
        "original_finite_junit_and_log_bytes_uploaded_by_original_workflow": False,
        "original_success_preserved": True, "new_workload_execution": False,
    }


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    REPORT.mkdir(parents=True, exist_ok=True)
    before = None
    result = {
        "audit_passed": False, "qualification_complete": False, "new_workload_execution": False,
        "original_run_id": CONFIG["original_run_id"], "original_workflow_outcome": "success",
        "scope": "Read original RSP-131 counts and owned-control success as data; no workload or source repair.",
    }
    try:
        assert sys.version_info[:3] == (3, 12, 13)
        before = source_witness("before")
        original_metadata()
        result.update(inspect_reports(original_archive()), audit_passed=True)
    except BaseException as error:
        result["error"] = failure(error)
    finally:
        try:
            assert before is not None and source_witness("after") == before
        except BaseException as error:
            result["audit_passed"] = False
            result["source_finalizer_error"] = failure(error)
        write_json(REPORT / "readout-outcome.json", result)
        frame("rsp131-readout-outcome.json", (REPORT / "readout-outcome.json").read_bytes(), limit=256 * 1024)
    return 0 if result["audit_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
