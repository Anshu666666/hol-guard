"""Observe original runtime-node evidence; never execute source tests or imports."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HARNESS, OUTPUT, REPORT, SOURCE, digest, failure, frame, git, headers, parsed, write_json
from download import api, population
from runtime_job_logs import job_log
from runtime_archives import archives

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text())


def emit(label: str, value: object, limit: int = 4 * 1024 * 1024) -> None:
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    write_json(REPORT / (label + ".json"), value)
    frame(label + ".json", data, limit=limit)


def source_witness(label: str) -> dict[str, object]:
    assert SOURCE != HARNESS and not SOURCE.is_relative_to(HARNESS) and not HARNESS.is_relative_to(SOURCE)
    assert not OUTPUT.is_relative_to(SOURCE) and not OUTPUT.is_relative_to(HARNESS)
    assert os.environ["GITHUB_REPOSITORY"] == CONFIG["repository"]
    assert os.environ["GITHUB_EVENT_NAME"] == "push" and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    assert os.environ["GITHUB_REF"] == "refs/heads/" + CONFIG["branch"]
    harness_sha = git("rev-parse", "HEAD", cwd=HARNESS).decode().strip()
    assert harness_sha == os.environ["GITHUB_SHA"]
    assert headers(harness_sha, HARNESS)["parents"] == [CONFIG["harness_parent"]]
    assert headers(CONFIG["harness_parent"], HARNESS)["tree"] == CONFIG["harness_parent_tree"]
    changes = git("diff-tree", "--no-commit-id", "--name-status", "-r",
                  CONFIG["harness_parent"], harness_sha, cwd=HARNESS).decode().splitlines()
    assert set(changes) == {"A\t" + path for path in CONFIG["added_paths"]}
    assert len(changes) == len(CONFIG["added_paths"])
    assert headers(CONFIG["source_sha"], SOURCE) == {
        "tree": CONFIG["source_tree"], "parents": [CONFIG["source_parent"]]}
    assert git("rev-parse", "HEAD", cwd=SOURCE).decode().strip() == CONFIG["source_sha"]
    commit = api("/git/commits/" + CONFIG["source_sha"])
    assert commit["tree"]["sha"] == CONFIG["source_tree"]
    assert [row["sha"] for row in commit["parents"]] == [CONFIG["source_parent"]]
    merge = api("/git/commits/" + CONFIG["original_merge_sha"])
    assert merge["tree"]["sha"] == CONFIG["source_tree"]
    assert [row["sha"] for row in merge["parents"]] == CONFIG["original_merge_parents"]
    entries = git("ls-tree", "-rz", "--full-tree", "HEAD", cwd=SOURCE).split(b"\0")
    files = {}
    for entry in entries:
        if not entry:
            continue
        prefix, raw = entry.split(b"\t", 1)
        mode, kind, blob = prefix.decode().split()
        assert kind == "blob"
        files[raw.decode()] = {"git_blob": blob, "mode": mode}
    assert len(files) == CONFIG["tracked_files"]
    expected_paths = set(CONFIG["source_files"])
    actual_paths = {path for path in files if path == "tests/test_guard_runtime.py" or
                    re.fullmatch(r"tests/test_guard_runtime_[0-9]{3}_.+\.py", path)}
    assert actual_paths == expected_paths and len(actual_paths) == 63
    indexes = sorted(int(re.search(r"_([0-9]{3})_", path).group(1))
                     for path in actual_paths if path != "tests/test_guard_runtime.py")
    assert indexes == list(range(1, 63))
    selected = {}
    for path, pin in CONFIG["source_files"].items():
        assert files[path] == {"git_blob": pin["git_blob"], "mode": pin["mode"]}
        data = (SOURCE / path).read_bytes()
        assert len(data) == pin["bytes"]
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == pin["git_blob"]
        selected[path] = {**pin, **digest(data)}
    for path, blob in CONFIG["producer_blobs"].items():
        data = (SOURCE / path).read_bytes()
        assert files[path]["git_blob"] == blob
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == blob
    for root in (SOURCE, HARNESS):
        assert not git("status", "--porcelain", "--untracked-files=all", cwd=root).strip()
    result = {"source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
              "merge_sha": CONFIG["original_merge_sha"], "files": selected, "producer_blobs": CONFIG["producer_blobs"]}
    write_json(REPORT / ("runtime63-source-" + label + ".json"), result)
    return result


def original_metadata() -> dict[str, object]:
    run = api("/actions/runs/" + str(CONFIG["run_id"]))
    for key, expected in (("id", CONFIG["run_id"]), ("run_attempt", 1), ("event", "pull_request"),
                          ("status", "completed"), ("conclusion", "failure"),
                          ("head_sha", CONFIG["source_sha"]), ("path", CONFIG["workflow_path"])):
        assert run[key] == expected, key
    jobs = population("/actions/runs/" + str(CONFIG["run_id"]) + "/attempts/1/jobs", "jobs")
    assert len(jobs) == CONFIG["original_job_count"]
    actual = {row["id"]: row for row in jobs}
    assert len(actual) == len(jobs)
    selected = {}
    for pin in CONFIG["jobs"]:
        row = actual[pin["id"]]
        for key in ("id", "name", "conclusion", "status", "started_at", "completed_at"):
            assert row[key] == pin[key], (pin["id"], key)
        assert row["run_id"] == CONFIG["run_id"] and row["run_attempt"] == 1
        assert row["head_sha"] == CONFIG["source_sha"]
        steps = [{"number": item["number"], "name": item["name"], "status": item["status"],
                  "conclusion": item["conclusion"]} for item in row["steps"]
                 if item["name"] == "Run pytest shard " + str(pin["shard_index"])]
        assert steps == pin["pytest_step"] and len(steps) == 1
        selected[pin["shard_index"]] = row
    assert set(selected) == set(range(96))
    originals = {}
    for run_id in (CONFIG["run_id"], CONFIG["prior_run_id"]):
        originals.update({row["id"]: row for row in
                          population("/actions/runs/" + str(run_id) + "/artifacts", "artifacts")})
    for pin in CONFIG["artifacts"]:
        row = originals[pin["id"]]
        assert row["name"] == pin["name"] and row["size_in_bytes"] == pin["bytes"]
        assert row["digest"] == "sha256:" + pin["sha256"] and row["expired"] is False
        assert row["workflow_run"]["id"] == pin["run_id"]
        expected_head = CONFIG["source_sha"] if pin["run_id"] == CONFIG["run_id"] else CONFIG["prior_harness"]
        assert row["workflow_run"]["head_sha"] == expected_head
    write_json(REPORT / "runtime63-original-metadata.json", {"run": run, "jobs": jobs, "artifacts": originals})
    return selected


def status_partition(log: str, index: int, nodes: dict[str, float], job: dict[str, object]) -> dict[str, object]:
    clean = re.sub(r"\x1b\[[0-9;]*m", "", log)
    lines = [re.sub(r"^\d{4}-\d\d-\d\dT[0-9:.]+Z ", "", line) for line in clean.splitlines()]
    assert CONFIG["original_merge_sha"] in lines, "Original checkout commit missing from job log"
    assert any("--cov --cov-branch --cov-report=" in line for line in lines)
    summaries = [match.group(1) for line in lines if
                 (match := re.search(r"={5,}\s*(.*?)\s+in\s+[0-9.]+s(?:\s*\([^)]+\))?\s*=*", line))]
    assert len(summaries) == 1, "Missing or ambiguous complete pytest terminal summary"
    counts = {name: int(value) for value, name in re.findall(
        r"(\d+)\s+(passed|failed|skipped|deselected|xfailed|xpassed|errors?|warnings?)", summaries[0])}
    failed = set()
    unparsed = []
    for line in lines:
        if line.startswith("FAILED "):
            candidates = [node for node in nodes if line == "FAILED " + node or
                          line.startswith("FAILED " + node + " - ")]
            if len(candidates) == 1:
                failed.add(candidates[0])
            else:
                unparsed.append(line)
    step = next(row for row in job["steps"] if row["name"] == "Run pytest shard " + str(index))
    no_unlocated_status = not any(counts.get(name, 0) for name in ("skipped", "xfailed", "xpassed", "error", "errors"))
    partition_complete = (no_unlocated_status and not unparsed
                          and len(failed) == counts.get("failed", 0)
                          and len(nodes) == counts.get("passed", 0) + len(failed)
                          and step["conclusion"] == ("failure" if failed else "success"))
    return {"job_id": job["id"], "shard_index": index, "job_conclusion": job["conclusion"],
            "pytest_step_conclusion": step["conclusion"], "summary": summaries[0], "summary_counts": counts,
            "failed_nodes": sorted(failed), "unparsed_failure_lines": unparsed,
            "call_partition_complete": partition_complete,
            "meaning": "When complete, all recorded calls are accounted by passed count and explicit failed nodes; otherwise individual status remains unknown"}


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    REPORT.mkdir(parents=True, exist_ok=True)
    before = None
    result = {"audit_passed": False, "qualification_complete": False,
              "source_sha": CONFIG["source_sha"], "original_run_id": CONFIG["run_id"],
              "scope": CONFIG["scope"], "original_failed_sweep_preserved": True}
    try:
        assert sys.version_info[:3] == (3, 12, 13)
        before = source_witness("before")
        jobs = original_metadata()
        shards, durations, expected, reused, selected_indices = archives(CONFIG, emit)
        runtime = set(CONFIG["source_files"])
        actual_plan = {node for nodes in shards.values() for node in nodes
                       if node.split("::", 1)[0] in runtime}
        partitions = {}
        observed = {}
        for index in selected_indices:
            if index == 11:
                retained = reused["separate_retained_data_inflation"]
                partition = dict(retained["original_shard11_status"],
                                 reused_verified_receipt=CONFIG["reused_shard11_receipt"],
                                 no_new_zip_or_log_read=True)
                partitions[index] = partition
                for row in retained["selected20_runtime_calls"]:
                    assert row["job_id"] == jobs[index]["id"] and row["status"] == "passed"
                    observed[row["node"]] = {"duration_seconds": row["seconds"],
                        "job_id": jobs[index]["id"], "shard_index": index,
                        "status": "passed_by_complete_call_partition",
                        "status_basis": "Previously verified exact original236-call/236-passed partition"}
                continue
            log = job_log(jobs[index]["id"], CONFIG["limits"]["job_log_bytes"],
                          CONFIG["limits"]["all_job_log_bytes"])
            emit("original-job-" + str(jobs[index]["id"]) + "-full-log",
                 {"job_id": jobs[index]["id"], "encoding": "utf-8", "content": log,
                  **digest(log.encode())})
            partition = status_partition(log, index, durations[index], jobs[index])
            partitions[index] = partition
            for node, seconds in durations[index].items():
                if node.split("::", 1)[0] not in runtime:
                    continue
                assert node not in observed
                status = "unknown"
                if partition["call_partition_complete"]:
                    status = "failed" if node in partition["failed_nodes"] else "passed_by_complete_call_partition"
                observed[node] = {"duration_seconds": seconds, "job_id": jobs[index]["id"],
                                  "shard_index": index, "status": status}
        counts = {name: sum(row["status"] == name for row in observed.values())
                  for name in ("passed_by_complete_call_partition", "failed", "unknown")}
        result.update(audit_passed=True, expected_collected_nodes=expected, expected_count=len(expected),
                      selected_shard_indices=selected_indices, selected_shard_count=len(selected_indices),
                      natural_planned_count=len(actual_plan), observed_call_count=len(observed),
                      missing_from_natural_plan=sorted(set(expected) - actual_plan),
                      unexpected_natural_nodes=sorted(actual_plan - set(expected)),
                      planned_without_call=sorted(actual_plan - set(observed)),
                      observed_nodes=observed, outcome_counts=counts, shard_result_partitions=partitions,
                      complete_718_passing_calls=(actual_plan == set(expected) == set(observed)
                                                  and counts["passed_by_complete_call_partition"] == 718),
                      planned_19_module_selection="Unavailable; not reconstructed or claimed")
    except BaseException as error:
        result["error"] = failure(error)
    finally:
        try:
            after = source_witness("after")
            assert before is not None and before == after
        except BaseException as error:
            result["audit_passed"] = False
            result["source_finalizer_error"] = failure(error)
        emit("runtime63-original-ci-readout", result)
        files = {str(path.relative_to(OUTPUT)): digest(path.read_bytes())
                 for path in sorted(OUTPUT.rglob("*")) if path.is_file()}
        emit("runtime63-artifact-manifest", {"files": files})
    return 0 if result["audit_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
