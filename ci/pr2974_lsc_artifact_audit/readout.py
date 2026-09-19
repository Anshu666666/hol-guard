"""Recover exact original LSC artifact bytes without repeating its workload."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HARNESS, HERE, OUTPUT, REPORT, SOURCE, digest, failure, frame, git, headers, parsed, write_json
from download import api, download, population, read_zip

ORIGINAL_BYTES = (HERE / "original-config.json").read_bytes()
ORIGINAL = json.loads(ORIGINAL_BYTES)
PINNED_MEMBERS = json.loads((HERE / "original-artifact-manifest.json").read_bytes())


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
    assert os.environ["GITHUB_REPOSITORY"] == CONFIG["repository"]
    assert os.environ["GITHUB_EVENT_NAME"] == "push" and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    assert os.environ["GITHUB_REF"] == "refs/heads/" + CONFIG["branch"]
    assert git("rev-parse", "HEAD", cwd=SOURCE).decode().strip() == CONFIG["source_sha"]
    assert headers(CONFIG["source_sha"], SOURCE) == {
        "tree": CONFIG["source_tree"], "parents": [CONFIG["source_parent"]]}
    harness = git("rev-parse", "HEAD", cwd=HARNESS).decode().strip()
    assert harness == os.environ["GITHUB_SHA"]
    assert headers(harness, HARNESS)["parents"] == [CONFIG["original_harness_sha"]]
    assert headers(CONFIG["original_harness_sha"], HARNESS) == {
        "tree": CONFIG["original_harness_tree"], "parents": [CONFIG["source_sha"]]}
    changed = git("diff-tree", "--no-commit-id", "--name-status", "-r",
                  CONFIG["original_harness_sha"], harness, cwd=HARNESS).decode().splitlines()
    assert set(changed) == {"A\t" + name for name in CONFIG["added_paths"]}
    assert len(changed) == len(CONFIG["added_paths"])
    assert digest(ORIGINAL_BYTES)["sha256"] == CONFIG["original_config_sha256"]
    assert (HARNESS / "ci/pr2974_lsc_materialize/config.json").read_bytes() == ORIGINAL_BYTES
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
    assert len(files) == CONFIG["tracked_files"] == 4546
    assert tree_hash(files) == CONFIG["source_tree"]
    for root in (SOURCE, HARNESS):
        assert not git("status", "--porcelain", "--untracked-files=all", cwd=root).strip()
    result = {"source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"], "files": files}
    write_json(REPORT / ("source-" + label + ".json"), result)
    return result


def original_metadata() -> None:
    run = api("/actions/runs/" + str(CONFIG["original_run_id"]))
    for key, expected in {
        "id": CONFIG["original_run_id"], "run_attempt": 1, "head_sha": CONFIG["original_harness_sha"],
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
        "run_id": CONFIG["original_run_id"], "head_sha": CONFIG["original_harness_sha"],
        "status": "completed", "conclusion": "success",
    }.items():
        assert job[key] == expected, key
    artifacts = population("/actions/runs/" + str(CONFIG["original_run_id"]) + "/artifacts", "artifacts")
    assert len(artifacts) == 1
    actual, pin = artifacts[0], CONFIG["artifact"]
    assert actual["id"] == pin["id"] and actual["name"] == pin["name"]
    assert actual["size_in_bytes"] == pin["bytes"] and actual["digest"] == "sha256:" + pin["sha256"]
    assert actual["expired"] is False
    assert actual["workflow_run"]["id"] == CONFIG["original_run_id"]
    assert actual["workflow_run"]["head_sha"] == CONFIG["original_harness_sha"]
    write_json(REPORT / "original-metadata.json", {"run": run, "jobs": jobs, "artifacts": artifacts})


def original_archive() -> dict[str, bytes]:
    path = download(CONFIG["artifact"])
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        assert 0 < len(infos) <= CONFIG["limits"]["zip_members"]
        assert sum(info.file_size for info in infos) <= CONFIG["limits"]["zip_total_bytes"]
        assert all(0 <= info.file_size <= CONFIG["limits"]["zip_member_bytes"] for info in infos)
    payloads = read_zip(path, "original-lsc")
    assert digest(payloads["artifact-manifest.json"]) == CONFIG["original_manifest"]
    actual = parsed(payloads, "artifact-manifest.json")
    assert actual == PINNED_MEMBERS
    assert set(payloads) == set(actual["files"]) | {"artifact-manifest.json"}
    for name, expected in actual["files"].items():
        assert digest(payloads[name]) == expected, name
    return payloads


def validate_original(payloads: dict[str, bytes], before: dict[str, object]) -> dict[str, object]:
    outcome = parsed(payloads, "outcome.json")
    assert outcome["passed"] is True and outcome["errors"] == []
    assert outcome["source_packet_complete"] is True and outcome["source_text_inventory_complete"] is True
    assert outcome["qualification_complete"] is False
    commands = parsed(payloads, "commands.json")
    assert commands == outcome["commands"] and len(commands) == 10
    for row in commands:
        assert row["passed"] is True and row["timed_out"] is False
        assert row["returncode"] == row["expected_returncode"]
        cleanup = row["group_cleanup"]
        assert cleanup["passed"] is True and cleanup["errors"] == []
        assert cleanup["no_live_members_in_original_group"] is True
        assert digest(payloads[row["name"] + ".log"]) == {
            "bytes": row["log_bytes"], "sha256": row["log_sha256"]}
    original_before = parsed(payloads, "source/source-before.json")
    assert original_before == parsed(payloads, "source/source-after.json")
    assert original_before["sha"] == CONFIG["source_sha"] and original_before["tree"] == CONFIG["source_tree"]
    assert original_before["parents"] == [CONFIG["source_parent"]]
    assert original_before["tracked_files"] == CONFIG["tracked_files"]
    assert original_before["files"] == before["files"]
    generation = parsed(payloads, "generation/generation-receipt.json")
    assert len(generation["mapping"]) == ORIGINAL["expected_moved_functions"] == 143
    assert generation["live_facade_lookup_count"] == ORIGINAL["expected_live_facade_loads"] == 832
    packet = parsed(payloads, "complete-source-payload.json")
    assert packet["source_sha"] == CONFIG["source_sha"] and packet["source_tree"] == CONFIG["source_tree"]
    assert packet["historical_review"] == ORIGINAL["historical_review"]
    expected = {ORIGINAL["historical_review"]["path_prefix"] + name: value
                for name, value in ORIGINAL["historical_review"]["files"].items()}
    expected[ORIGINAL["test_path"]] = ORIGINAL["fresh_test_sha256"]
    assert len(expected) == len(packet["files"]) == 19 and set(expected) == set(packet["files"])
    for path, row in packet["files"].items():
        data = row["complete_text"].encode("utf-8")
        assert digest(data) == {"sha256": row["sha256"], "bytes": row["bytes"]}
        assert row["sha256"] == expected[path] and blob(data) == row["git_blob"], path
        assert row["mode"] == "100644" and data.endswith(b"\n") and b"\r\n" not in data
        assert len(data.splitlines()) == row["physical_lines"] <= 500
        assert row["historical_production_match"] is (path != ORIGINAL["test_path"])
    assert packet["production_historical_byte_matches"] == 18
    assert packet["fresh_test_unrun"] is True and packet["fresh_test_historical_match_claim"] is False
    combined = {**before["files"], **packet["files"]}
    assert len(combined) == packet["prospective_files"] == 4564
    assert tree_hash(combined) == packet["prospective_tree"]
    census = parsed(payloads, "source-text-inventory.json")
    assert census["source_sha"] == CONFIG["source_sha"] and census["source_tree"] == CONFIG["source_tree"]
    assert census["patterns"] == ORIGINAL["source_text_inventory"]
    assert census["source_scan_complete"] is True and census["errors"] == []
    expected_scanned = [{"path": path, "sha256": row["sha256"], "bytes": row["bytes"]}
                        for path, row in sorted(before["files"].items()) if path.endswith(".py")]
    assert census["scanned_files"] == expected_scanned
    assert len(expected_scanned) == census["tracked_python_files"] == 3110
    assert len(census["matched_files"]) == census["matched_file_count"]
    for path, row in census["matched_files"].items():
        data = row["complete_file_text"].encode("utf-8")
        assert data == (SOURCE / path).read_bytes()
        assert digest(data) == {"sha256": row["sha256"], "bytes": row["bytes"]}
        assert blob(data) == row["git_blob"] == before["files"][path]["git_blob"]
        lines = data.decode().splitlines()
        for matches in row["matches"].values():
            for match in matches:
                assert lines[match["line"] - 1] == match["text"]
    owned = json.loads(payloads["owned-environment.log"])
    assert owned["versions"] == {"ruff": "0.15.17"} and owned["python"].startswith("3.12.13 ")
    for name, limit in (
        ("complete-source-payload.json", 512 * 1024),
        ("source-text-inventory.json", 8 * 1024 * 1024),
        ("generation/generation-receipt.json", 512 * 1024),
        ("outcome.json", 64 * 1024), ("artifact-manifest.json", 64 * 1024),
    ):
        frame(name, payloads[name], limit=limit)
    return {"original_materializer_passed": True, "original_commands": len(commands),
            "production_historical_byte_matches": 18, "fresh_seam_test_unrun": True,
            "prospective_tree": packet["prospective_tree"], "prospective_files": len(combined),
            "tracked_python_files": census["tracked_python_files"], "matched_files": census["matched_file_count"],
            "original_members": PINNED_MEMBERS["files"], "owned_environment": owned,
            "source_and_census_bytes_recovered_from_original_artifact": True}


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    REPORT.mkdir(parents=True, exist_ok=True)
    before = None
    result = {"audit_passed": False, "qualification_complete": False,
              "scope": CONFIG["scope"], "original_run_id": CONFIG["original_run_id"]}
    try:
        assert sys.version_info[:3] == (3, 12, 13)
        before = source_witness("before")
        original_metadata()
        payloads = original_archive()
        result.update(validate_original(payloads, before), audit_passed=True)
    except BaseException as error:
        result["error"] = failure(error)
    finally:
        try:
            assert before is not None and source_witness("after") == before
        except BaseException as error:
            result["audit_passed"] = False
            result["source_finalizer_error"] = failure(error)
        write_json(REPORT / "readout-outcome.json", result)
        frame("readout-outcome.json", (REPORT / "readout-outcome.json").read_bytes(), limit=256 * 1024)
    return 0 if result["audit_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
