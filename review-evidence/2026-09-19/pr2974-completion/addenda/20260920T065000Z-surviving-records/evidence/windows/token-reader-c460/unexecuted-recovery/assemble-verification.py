"""Verify the original Windows held-reader attempt; retain its failed predicate."""
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).parent
SOURCE = ROOT.parent / "token-reader-prep"
MANIFEST = json.loads((ROOT.parent / "token-reader-validation/manifest.json").read_text())
ARTIFACT = ROOT / "artifact"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_text())


archive = load(ROOT / "archive-verification.json")
metadata = load(ROOT / "github-artifact-metadata.json")
assert archive["bytes"] == metadata["size_in_bytes"] == 3345
assert digest((ROOT / "10599398431.zip").read_bytes()) == archive["sha256"] == metadata["digest"][7:]
for member in archive["members"]:
    data = (ARTIFACT / member["name"]).read_bytes()
    assert len(data) == member["bytes"] and digest(data) == member["sha256"]
jobs = load(ROOT / "github-jobs-terminal.json")["jobs"]
assert len(jobs) == 1 and jobs[0]["id"] == 106033540943
assert jobs[0]["status"] == "completed" and jobs[0]["conclusion"] == "failure"
source_commit = load(ROOT / "github-source-terminal.json")
driver_commit = load(ROOT / "github-driver-terminal.json")
assert source_commit["sha"] == "c460271fb977a2c52cc0ce985a73e431672e1e02"
assert source_commit["tree"]["sha"] == "024c20eeaa3b9ee7e58e97b419d1110e1fbbc491"
assert [p["sha"] for p in source_commit["parents"]] == ["8f15b37b4a1bd054ef486148610e518b1be05cfc"]
assert driver_commit["sha"] == "ed1330a0e84b01ae0612beca52f929701a2a442f"
assert driver_commit["tree"]["sha"] == "88028512aadc3b36027341a7508bc200f2a97b5f"
assert [p["sha"] for p in driver_commit["parents"]] == [source_commit["sha"]]
bindings = {}
for phase in ("before", "after"):
    state = load(ARTIFACT / f"source-{phase}.json")
    assert state["phase"] == phase
    assert state["source_sha"] == source_commit["sha"] and state["source_tree"] == source_commit["tree"]["sha"]
    assert state["driver_sha"] == driver_commit["sha"] and state["driver_tree"] == driver_commit["tree"]["sha"]
    assert state["product_sha"] == MANIFEST["source_parent_sha"] and state["product_tree"] == MANIFEST["source_parent_tree"]
    assert state["workflow_run"] == "35493953456" and state["workflow_attempt"] == "1"
    assert state["python"] == "3.12.10" and state["platform"] == "Windows"
    assert all(state[k] for k in ("source_clean", "driver_clean", "only_two_test_files_added", "imports_from_pinned_source"))
    assert state["installed_artifact_qualification"] is False
    for record, expected in zip(state["source_controls"], MANIFEST["source_files"], strict=True):
        assert record["path"] == expected["path"]
        data = (SOURCE / record["path"]).read_bytes()
        assert digest(data) == expected["sha256"] == record["git_blob_sha256"]
        assert digest(data.replace(b"\n", b"\r\n")) == record["checkout_sha256"]
    bindings[phase] = state

report = load(ARTIFACT / "token-result.json")
process = load(ARTIFACT / "process-result.json")
stdout = (ARTIFACT / "controls.log").read_bytes()
assert len(stdout) == process["stdout_bytes"] and digest(stdout) == process["stdout_sha256"]
assert [json.loads(line) for line in stdout.splitlines()] == report["cases"]
assert process["return_code"] == 1 and process["timed_out"] is False
assert process["child_attempt_count"] == 1 and process["stderr_bytes"] == 0
assert report["case_count"] == report["declared_case_count"] == 6
expected_cases = [(route, phase) for route in ("bounded_manager", "codex_path_read_text")
                  for phase in ("no_reader", "held_reader", "released_reader")]
assert [(case["route"], case["phase"]) for case in report["cases"]] == expected_cases
assert report["control_complete"] is False and report["observed_replace_failure_count"] == 2
assert report["compatibility_failure_observed"] is True
for case in report["cases"]:
    assert case["writer_calls"] == case["replace_calls"] == 1
    assert all(case[key] for key in ("reader_ready", "writer_lock_acquired", "reader_thread_finished",
                                    "writer_thread_finished", "temporary_siblings_removed", "fixture_directory_removed"))
    assert all(case[key] is None for key in ("reader_error", "control_error", "cleanup_error"))
    if case["phase"] == "held_reader":
        assert case["control_complete"] is False and case["expected_windows_sharing_failure"] is True
        assert case["reader_open_count"] == case["reader_pause_count"] == 1
        assert case["reader_open_before_writer"] and case["reader_closed"] and case["writer_finished_before_release"]
        assert case["original_replace_error_retained"]
        assert case["writer_error"] == case["replace_error"] == {"errno": 13, "kind": "PermissionError", "winerror": 5}
        assert case["reader_value"] == case["final_value"] == "old"
    else:
        assert case["control_complete"] is True and case["replace_error"] is None and case["writer_error"] is None
        assert case["final_value"] == "new"
        if case["phase"] == "released_reader":
            assert case["reader_closed_before_writer"] and case["reader_closed"] and case["reader_value"] == "old"
assert not report["actual_failed_job_handle_attributed"]
assert not report["installed_artifact_qualification"]
assert not report["runtime_deadlines_or_retries_changed"]
verification = {
    "schema": 1,
    "scope": "original once-only actual Windows source controls of exact8f token readers and writer",
    "run_id": 35493953456, "job_id": 106033540943, "attempt": 1,
    "job_conclusion": "failure",
    "artifact": archive,
    "bindings": bindings,
    "original_report": report,
    "original_process": process,
    "declared_controls": 6,
    "executed_cases": 6,
    "complete_controls": 4,
    "incomplete_controls": 2,
    "original_replace_failures": 2,
    "strict_expected_winerror": 32,
    "observed_held_winerror": 5,
    "all_declared_cases_have_one_original_replace_attempt": True,
    "all_original_errors_and_failure_flags_preserved": True,
    "all_handles_threads_and_fixture_cleanup_confirmed": True,
    "reader_overlap_compatibility_gap_demonstrated": True,
    "original_normal_job_winerror32_reproduced": False,
    "original_normal_job_conflicting_handle_attributed": False,
    "acl_or_access_rights_defect_attributed": False,
    "full_corpus_run": False,
    "installed_qualification": False,
    "gate_rewritten_or_attempt_repeated": False,
    "interpretation": [
        "Both actual held-reader routes prevent the original replacement; fresh no-reader and separately released-reader cases permit it.",
        "The control's expected WinError32 predicate is false for both observed WinError5 errors; all original failure flags and exit1 remain intact.",
        "Error5 is the observed numeric OS code; it does not establish an ACL defect or identify the handle in the original normal8f Error32 job.",
        "The unchanged original writer ran under its original serialization lock, with each synthetic fixture receiving one replace attempt.",
        "This source experiment exercises manager.load_guard_daemon_auth_token and Codex _private_file_text/Path.read_text, not a full authenticated daemon startup or installed qualification corpus.",
        "No gate edit, retry, permission change, product mutation, or PR movement is part of this verification.",
    ],
}
path = ROOT / "verification.json"
path.write_text(json.dumps(verification, indent=2, sort_keys=True)+"\n")
print(json.dumps({"bytes": path.stat().st_size, "sha256": digest(path.read_bytes()), "complete": 4, "incomplete": 2}))
