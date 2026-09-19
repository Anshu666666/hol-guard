"""Read one retained failed audit archive; do not repeat its original archive sweep."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import sys
import traceback
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HARNESS, OUTPUT, REPORT, SOURCE, digest, failure, frame, git, headers, parsed, write_json
from download import api, download, population, read_zip

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text())


def emit(label, value, limit=16 * 1024 * 1024):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    write_json(REPORT / (label + ".json"), value)
    frame(label + ".json", raw, limit=limit)


def witness(label):
    assert sys.version_info[:3] == (3, 12, 13)
    assert os.environ["GITHUB_REPOSITORY"] == CONFIG["repository"]
    assert os.environ["GITHUB_EVENT_NAME"] == "push" and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    assert os.environ["GITHUB_REF"] == "refs/heads/" + CONFIG["branch"]
    assert SOURCE != HARNESS and not SOURCE.is_relative_to(HARNESS) and not HARNESS.is_relative_to(SOURCE)
    assert not OUTPUT.is_relative_to(SOURCE) and not OUTPUT.is_relative_to(HARNESS)
    observer = git("rev-parse", "HEAD", cwd=HARNESS).decode().strip()
    assert observer == os.environ["GITHUB_SHA"]
    assert headers(observer, HARNESS)["parents"] == [CONFIG["harness_parent"]]
    assert headers(CONFIG["harness_parent"], HARNESS) == {
        "tree": CONFIG["harness_parent_tree"], "parents": [CONFIG["harness_grandparent"]]}
    changes = git("diff-tree", "--no-commit-id", "--name-status", "-r",
                  CONFIG["harness_parent"], observer, cwd=HARNESS).decode().splitlines()
    assert set(changes) == {"A\t" + name for name in CONFIG["added_paths"]}
    assert len(changes) == len(CONFIG["added_paths"])
    assert git("rev-parse", "HEAD", cwd=SOURCE).decode().strip() == CONFIG["source_sha"]
    assert headers(CONFIG["source_sha"], SOURCE) == {
        "tree": CONFIG["source_tree"], "parents": [CONFIG["source_parent"]]}
    entries = {}
    for row in git("ls-tree", "-rz", "--full-tree", "HEAD", cwd=SOURCE).split(b"\0"):
        if row:
            prefix, path = row.split(b"\t", 1)
            mode, kind, blob = prefix.decode().split()
            assert kind == "blob"
            entries[path.decode()] = {"mode": mode, "git_blob": blob}
    assert len(entries) == 4546
    selected = {}
    for path, pin in CONFIG["original_source_files"].items():
        assert entries[path] == {"mode": pin["mode"], "git_blob": pin["git_blob"]}
        raw = (SOURCE / path).read_bytes()
        assert len(raw) == pin["bytes"]
        assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == pin["git_blob"]
        selected[path] = {**entries[path], **digest(raw)}
    for path, expected in CONFIG["original_producer_hashes"].items():
        assert digest((HARNESS / path).read_bytes()) == expected
    for root in (SOURCE, HARNESS):
        assert not git("status", "--porcelain", "--untracked-files=all", cwd=root).strip()
    value = {"observer_sha": observer, "source_sha": CONFIG["source_sha"],
             "source_tree": CONFIG["source_tree"], "tracked_git_entries": len(entries),
             "actual_original_runtime_file_bytes": selected,
             "original_producer_hashes": CONFIG["original_producer_hashes"]}
    write_json(REPORT / ("source-" + label + ".json"), value)
    return value


def metadata():
    run = api("/actions/runs/" + str(CONFIG["run_id"]))
    expected = {"id": CONFIG["run_id"], "run_attempt": 1, "head_sha": CONFIG["harness_parent"],
                "event": "push", "status": "completed", "conclusion": "failure",
                "head_branch": CONFIG["original_branch"], "path": CONFIG["original_workflow_path"]}
    for name, value in expected.items():
        assert run[name] == value, name
    jobs = population("/actions/runs/" + str(CONFIG["run_id"]) + "/attempts/1/jobs", "jobs")
    assert len(jobs) == 1
    job = jobs[0]
    assert job["id"] == CONFIG["job_id"] and job["status"] == "completed" and job["conclusion"] == "failure"
    assert job["head_sha"] == CONFIG["harness_parent"] and job["run_attempt"] == 1
    expected_steps = CONFIG["original_steps"]
    actual = {row["name"]: row["conclusion"] for row in job["steps"] if row["name"] in expected_steps}
    assert actual == expected_steps
    artifacts = population("/actions/runs/" + str(CONFIG["run_id"]) + "/artifacts", "artifacts")
    assert len(artifacts) == 1
    row, pin = artifacts[0], CONFIG["artifact"]
    assert row["id"] == pin["id"] and row["name"] == pin["name"]
    assert row["size_in_bytes"] == pin["bytes"] and row["digest"] == "sha256:" + pin["sha256"]
    assert row["expired"] is False
    assert row["workflow_run"]["id"] == CONFIG["run_id"]
    assert row["workflow_run"]["head_sha"] == CONFIG["harness_parent"]
    value = {"run": run, "jobs": jobs, "artifacts": artifacts}
    emit("original-failed-audit-metadata", value)
    return value


def original_payloads():
    path = download(CONFIG["artifact"])
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        assert 0 < len(infos) <= 80, "Outer original artifact member-count bound"
        assert sum(info.file_size for info in infos) <= 8 * 1024 * 1024, "Outer original expanded bound"
        assert all(0 <= info.file_size <= 2 * 1024 * 1024 for info in infos), "Outer original member bound"
    payloads = read_zip(path, "original-runtime63-failure")
    assert len(payloads) == CONFIG["expected_original_files"]
    name = "audit/runtime63-artifact-manifest.json"
    assert digest(payloads[name]) == CONFIG["original_manifest"]
    manifest = parsed(payloads, name)
    assert set(manifest) == {"files"}
    assert set(payloads) == set(manifest["files"]) | {name}
    for member, expected in manifest["files"].items():
        assert digest(payloads[member]) == expected, member
    files = {}
    import base64
    for member, raw in sorted(payloads.items()):
        try:
            content = raw.decode("utf-8")
            assert content.encode("utf-8") == raw
            encoding = "utf-8"
        except UnicodeDecodeError:
            content, encoding = base64.b64encode(raw).decode("ascii"), "base64"
        files[member] = {**digest(raw), "encoding": encoding, "content": content}
    emit("complete-original-failure-reports", {
        "files": files, "original_file_count": len(files), "all_original_members_included": True,
        "original_archive_digest_verified": True, "all_original_manifest_hashes_verified": True,
        "original_run_id": CONFIG["run_id"], "qualification_complete": False})
    return payloads


def diagnose(payloads):
    outcome = parsed(payloads, "audit/runtime63-original-ci-readout.json")
    assert outcome["audit_passed"] is False and outcome["error"]["type"] == "AssertionError"
    assert outcome["source_sha"] == CONFIG["source_sha"] and outcome["original_run_id"] == 35433592816
    bounds = parsed(payloads, "audit/pytest-durations-11-bounds.json")
    assert bounds["artifact_id"] == 10581271616
    nested = payloads["original-zips/10581271616.zip"]
    assert digest(nested) == CONFIG["nested_duration_zip"]
    original_config = json.loads((HARNESS / CONFIG["original_config_path"]).read_bytes())
    limits = original_config["limits"]
    expected_limits = {"members": 1, "member_bytes": limits["duration_member_bytes"],
                       "total_bytes": limits["duration_member_bytes"],
                       "aggregate_expanded_bytes": limits["all_zip_expanded_bytes"]}
    assert bounds["limits"] == expected_limits
    with zipfile.ZipFile(io.BytesIO(nested)) as archive:
        infos = archive.infolist()
        central = [{"name": info.filename, "file_size": info.file_size,
                    "compressed_bytes": info.compress_size, "flags": info.flag_bits,
                    "crc32": info.CRC, "external_attributes": info.external_attr}
                   for info in infos]
    assert bounds["members"] == len(infos)
    assert bounds["expanded_bytes"] == sum(info.file_size for info in infos)
    assert bounds["largest_member_bytes"] == max((info.file_size for info in infos), default=0)
    checks = {
        "positive_member_count_within_one": 0 < len(infos) <= 1,
        "expanded_size_within_original_member_limit": bounds["expanded_bytes"] <= expected_limits["total_bytes"],
        "aggregate_size_within_original_total_limit": bounds["aggregate_expanded_bytes"] <= expected_limits["aggregate_expanded_bytes"],
        "each_member_size_within_original_member_limit": all(
            0 <= info.file_size <= expected_limits["member_bytes"] for info in infos),
    }
    failed = [name for name, passed in checks.items() if not passed]
    value = {"original_outcome": outcome, "actual_original_bounds": bounds,
             "actual_retained_nested_zip_central_directory": central,
             "original_bound_checks": checks, "failed_original_bounds": failed,
             "first_failed_original_bound": failed[0] if failed else None,
             "preflight_explains_failure": bool(failed),
             "remaining_scope_if_no_failed_bound": "Original member/name/type/CRC validation remains unresolved",
             "nested_members_decompressed_or_executed": False,
             "original_limits_changed": False, "original_98_archive_sweep_repeated": False,
             "original_failure_preserved": True, "qualification_complete": False}
    emit("original-runtime63-failure-diagnosis", value)
    return value


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    REPORT.mkdir(parents=True, exist_ok=True)
    before = None
    result = {"audit_passed": False, "original_run_id": CONFIG["run_id"],
              "source_sha": CONFIG["source_sha"], "qualification_complete": False}
    try:
        before = witness("before")
        metadata()
        payloads = original_payloads()
        result["diagnosis"] = diagnose(payloads)
        result["audit_passed"] = True
    except BaseException as error:
        result["error"] = failure(error)
        result["traceback_locations"] = [
            {"file": Path(row.filename).name, "line": row.lineno, "function": row.name}
            for row in traceback.extract_tb(error.__traceback__)]
    finally:
        try:
            assert before is not None and witness("after") == before
        except BaseException as error:
            result["audit_passed"] = False
            result["source_finalizer_error"] = failure(error)
        emit("readout-outcome", result)
    return 0 if result["audit_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
