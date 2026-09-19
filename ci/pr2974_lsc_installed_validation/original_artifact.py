"""Read the single pinned failed-run artifact before admitting any new test work."""

from __future__ import annotations

import json
from pathlib import Path
import zipfile

# This import removes AUDIT_TOKEN before any child environment is copied.
from download import api, download, population, read_zip
from artifact_common import digest, parsed
from common import CONFIG, REPORT, write_json
from packages import verify_packages

ORIGINAL = CONFIG["original"]


def metadata() -> None:
    pin = ORIGINAL["run"]
    actual = api("/actions/runs/" + str(pin["id"]) + "/attempts/1")
    assert all(actual.get(key) == value for key, value in pin.items()), "Original run identity changed"
    jobs = population("/actions/runs/" + str(pin["id"]) + "/attempts/1/jobs", "jobs")
    assert len(jobs) == 1 and all(
        jobs[0].get(key) == value for key, value in ORIGINAL["job"].items()), "Original job population changed"
    steps = [{key: step[key] for key in ("name", "number", "status", "conclusion")} for step in jobs[0]["steps"]]
    assert steps == ORIGINAL["job_steps"], "Original step outcomes changed"
    artifacts = population("/actions/runs/" + str(pin["id"]) + "/artifacts", "artifacts")
    artifact = ORIGINAL["artifact"]
    assert len(artifacts) == 1, "Original artifact population changed"
    actual_artifact = artifacts[0]
    assert all(actual_artifact.get(key) == artifact[key] for key in ("id", "name"))
    assert actual_artifact["size_in_bytes"] == artifact["bytes"] and actual_artifact["expired"] is False
    assert actual_artifact["digest"] == "sha256:" + artifact["sha256"]
    assert actual_artifact["workflow_run"]["id"] == pin["id"]
    assert actual_artifact["workflow_run"]["head_sha"] == pin["head_sha"]
    write_json(REPORT / "original-metadata-admission.json", {
        "original_run": pin, "original_job": ORIGINAL["job"], "original_steps": steps,
        "artifact": artifact, "original_overall_failure_preserved": True,
        "new_execution_performed": False, "qualification_complete": False})


def archive_input(run) -> dict[str, bytes]:
    metadata()
    archive = download(ORIGINAL["artifact"])
    # Retain the actual central directory before any generic size/name/CRC refusal.
    with zipfile.ZipFile(archive) as stream:
        infos = stream.infolist()
        write_json(REPORT / "original-central-directory.json", {
            "archive": digest(archive.read_bytes()), "count": len(infos),
            "expanded_bytes": sum(item.file_size for item in infos),
            "maximum_member_bytes": max((item.file_size for item in infos), default=0),
            "original_reader_limits": {"members": 256, "expanded_bytes": 64 * 1024 * 1024,
                                       "member_bytes": 16 * 1024 * 1024},
            "members": [{"name": item.filename, "bytes": item.file_size,
                         "compressed_bytes": item.compress_size, "crc32": item.CRC,
                         "flags": item.flag_bits, "external_attr": item.external_attr}
                        for item in infos],
            "member_contents_read": False, "qualification_complete": False})
    payloads = read_zip(archive, "original-lsc")
    manifest = parsed(payloads, "artifact-manifest.json")
    assert isinstance(manifest, dict)
    extras = {"artifact-manifest.json", "job-outcome.json", "package-summary.json"}
    assert set(payloads) == set(manifest) | extras, "Original manifest member coverage changed"
    assert not set(manifest) & extras
    for name, expected in manifest.items():
        assert digest(payloads[name]) == expected, "Original manifest mismatch: " + name
    for name, expected in ORIGINAL["frames"].items():
        assert digest(payloads[name]) == expected, "Original projected bytes differ: " + name
    for name in ORIGINAL["absence_required"]:
        assert name not in payloads, "Unexpected original post-failure result: " + name
    # Copy original evidence before schema interpretation. The complete ZIP also remains retained.
    names = {
        "artifact-manifest.json", "job-outcome.json", "package-summary.json",
        "installed-before.json", "installed-seam-collection.json", "installed-seam-collection.log",
        "installed-seam-execution.json", "installed-seam-execution.log",
        "installed-seam-execution-junit.xml", "package-members.json",
        "source-before.json", "source-after.json", "finite-results.json",
    }
    for name in names:
        target = REPORT / "original" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payloads[name])
    before = parsed(payloads, "source-before.json")
    after = parsed(payloads, "source-after.json")
    assert before == after
    assert before["source_sha"] == CONFIG["source_sha"] and before["source_tree"] == CONFIG["source_tree"]
    assert before["harness_sha"] == ORIGINAL["run"]["head_sha"]
    assert before["harness_files"] == ORIGINAL["helper_hashes"]
    assert before["files"] == run.before["files"] and before["baseline_files"] == run.before["baseline_files"]
    outcome = parsed(payloads, "job-outcome.json")
    assert outcome["passed"] is False and outcome["source_unchanged"] is True
    assert outcome["qualification_complete"] is False and outcome["all_original_owned_groups_retired"] is True
    assert outcome["error"] == ORIGINAL["driver_error"]
    assert len(outcome["steps"]) == 31 and all(step["passed"] is True for step in outcome["steps"])
    observed = {
        "artifact_id": ORIGINAL["artifact"]["id"], "manifest_members": len(manifest),
        "all_actual_zip_members_crc_and_hash_verified": True, "all_manifest_entries_verified": True,
        "all_eight_projected_files_equal_original_archive": True,
        "source_and_original_harness_binding_verified": True,
        "original_overall_passed": False, "original_error": outcome["error"],
        "original_absent_results": ORIGINAL["absence_required"],
        "fresh_installed_result": "not_run", "qualification_complete": False,
    }
    write_json(REPORT / "original-artifact-admission.json", observed)
    return payloads


def original_packages(run, payloads: dict[str, bytes]) -> Path:
    paths = {}
    for role in ("wheel", "sdist"):
        pin = ORIGINAL["packages"][role]
        name = "packages/" + pin["name"]
        assert digest(payloads[name]) == {key: pin[key] for key in ("sha256", "bytes")}, role
        output = REPORT / "original" / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payloads[name])
        paths[role] = output
    # This unchanged verifier reads each actual package member and every wheel RECORD row.
    # It neither invokes the builder nor repeats the original capability tests.
    verify_packages(run, paths["wheel"], paths["sdist"])
    current = json.loads((REPORT / "package-members.json").read_bytes())
    original = parsed(payloads, "package-members.json")
    assert current == original, "Reverified actual package members differ from the original receipt"
    write_json(REPORT / "original-package-admission.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "wheel": ORIGINAL["packages"]["wheel"], "sdist": ORIGINAL["packages"]["sdist"],
        "original_complete_package_receipt_equal": True, "actual_members_reverified": True,
        "build_executed": False, "capability_tests_repeated": False, "qualification_complete": False,
    })
    return paths["wheel"]
