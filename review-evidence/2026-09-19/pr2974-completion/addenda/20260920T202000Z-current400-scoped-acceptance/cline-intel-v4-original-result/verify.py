"""Data-only verification of the original Cline Intel nested-call artifact."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).parent
RAW = ROOT / "10611496593/raw"
CASES = [
    "cline/PreToolUse/benign/small",
    "cline/PreToolUse/dangerous/small",
    "cline/PostToolUse/benign/1k",
    "cline/PostToolUse/block/1k",
]


def read(path: str) -> object:
    return json.loads((RAW / path).read_bytes())


def image(data: bytes) -> dict[str, object]:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def verify() -> dict[str, object]:
    archive = ROOT / "10611496593/artifact.zip"
    original = archive.read_bytes()
    assert image(original) == {"bytes": 51194, "sha256": "3e05470112497fba424d16633fb2c4b6893e1b9e915fc4002765a2d074219418"}
    members = []
    with zipfile.ZipFile(archive) as bundle:
        assert len(bundle.namelist()) == len(set(bundle.namelist())) == 32
        for name in bundle.namelist():
            data = bundle.read(name)
            assert data == (RAW / name).read_bytes()
            members.append({"path": name, **image(data)})
    before, after, run = (read(name) for name in ("before.json", "after.json", "run.json"))
    assert before["binding"] == after["binding"] == run["binding"]
    assert {k: v for k, v in before.items() if k != "operation"} == {k: v for k, v in after.items() if k != "operation"}
    binding = run["binding"]
    expected_ids = {
        "candidate_source": "14ac7d491b14af267c933f9b1de668ec8135ba35",
        "candidate_tree": "5fef707b44f63edf7fca574c6c993b6fe8406f6a",
        "driver_source": "edb75675005bf3a221250f51f81e68f59632be2c",
        "driver_tree": "985dbfc90514db95a46ebd179257d06dc131a205",
        "product_source": "e44008445630aad28ccc291ec234f55a14892e6d",
        "product_tree": "addf0c1daf8ceb6313d6805ee4d05e216d6fdac8",
        "cell": "mac-x64", "platform": "Darwin", "machine": "x86_64",
    }
    for key, expected in expected_ids.items():
        assert binding[key] == expected
    assert len(binding["candidate_files"]) == 10
    for path, expected in binding["candidate_files"].items():
        assert image((ROOT.parent / "cline-intel-subprocess-v4" / path).read_bytes()) == expected
    assert binding["artifact_source"]["build_source"] == "be612a3e562a2041b3732a33c158eeae4f1dad40"
    assert binding["artifact_source"]["build_tree"] == "19977465d6e419f1276d75fb6bd1b3477f5c9720"
    assert binding["original_archive_provenance"]["artifact_id"] == 10606991867
    assert binding["archive_bytes_rehashed_in_this_run"] is False
    assert run["installation_unchanged"] is True
    assert run["installed_before"] == run["installed_after"]
    assert run["installed_before"]["wheel_entries_verified"] == 1499
    assert run["installed_before"]["record_entries_verified"] == 1508
    report = read("cline-witness/result.json")
    assert report["identity"] == run["installed_before"]["identity"]
    assert report["declared_cases"] == CASES
    assert len(report["attempts"]) == 4 and report["passed"] is True
    assert report["performance_qualified"] is False
    assert report["external_host_application_executed"] is False
    assert report["historical_failed_run_reclassified"] is False
    rows = []
    for index, row in enumerate(report["attempts"]):
        assert row["index"] == index and row["case_id"] == CASES[index]
        assert row["passed"] is True and row["original_setup_validated"] is True
        assert row["cleanup_faults"] == []
        assert row["original_delivery"] == {"exit_checked": True, "stdout_checked": True}
        assert row["fixture_daemon_routes_before"] == row["fixture_daemon_routes_after"] == {}
        worker, nested, child = row["worker"], row["nested_run"], row["child"]
        for name, value in (("worker", worker), ("nested-run", nested), ("child", child)):
            assert read(f"cline-witness/case-{index}/{name}.json") == value
        assert nested["configuration_sha256"] == worker["configuration_sha256"] == child["configuration_sha256"] == row["observer_installation"]["configuration_sha256"]
        assert nested["pid"] == worker["pid"] == child["parent_pid"]
        assert nested["parent_pid"] == worker["parent_pid"]
        assert type(nested["selected_calls"]) is int and nested["selected_calls"] == 1
        assert nested["original_timeout_seconds"] == 9
        assert nested["run_installed"] is nested["run_restored"] is nested["observation_complete"] is True
        assert nested["count_saturated"] is nested["original_call_changed"] is nested["performance_qualified"] is nested["raw_arguments_or_output_exported"] is False
        assert nested["faults"] == [] and nested["errno"] is None
        assert nested["outcome"] == ("timeout" if index < 2 else "returned")
        assert nested["returncode"] == (None if index < 2 else 0)
        assert child["observation_complete"] is child["profile_restored"] is child["original_values_stable"] is True
        assert child["faults"] == [] and child["open_frames"] == 0
        assert child["counts"] == {"edge_call": 1, "edge_return_or_unwind": 1, "worker_call": 1, "worker_return_or_unwind": 1}
        assert child["callbacks"] == child["maximum_counted_callbacks"] == 2000000 and child["callbacks_saturated"] is True
        assert child["headline_timing_eligible"] is False and child["return_events_prove_success"] is False
        edge = child["original_edge"]
        for key in ("complete", "edge_shape_valid", "original_native_validation_passed", "original_validator_called", "payload_equal", "policy_binding_valid", "python_oracle_disabled", "receipt_accepted_by_original_worker", "receipt_matches_original_edge", "receipt_workspace_binding_matches_source", "request_context_equal"):
            assert edge[key] is True
        assert edge["receipt_workspace_bound"] is False
        assert edge["original_worker_route"] == "native_resident"
        assert edge["original_worker_routes"] == {"native_resident": 1}
        assert edge["original_payload_sha256"] == edge["declared_payload_sha256"]
        assert all(value is True for value in edge["request_context_fields"].values())
        assert all(value["same_type_and_value"] is True for value in edge["semantic_fields"].values())
        rows.append({"case_id": row["case_id"], "nested_outcome": nested["outcome"], "nested_returncode": nested["returncode"], "selected_calls": 1, "original_timeout_seconds": 9, "child_native_validation": True, "receipt_accepted": True, "workspace_bound": False, "outer_stdout_and_exit_checked": True, "cleanup_faults": [], "callbacks_saturated": True})
    ledger = [json.loads(line) for line in (RAW / "cline-witness/original-attempts.jsonl").read_text().splitlines()]
    assert len(ledger) == 8
    for index, name in enumerate(CASES):
        offer, done = ledger[index * 2:index * 2 + 2]
        assert offer["case_id"] == done["case_id"] == "global/" + name
        assert offer["stage"] == offer["status"] == "offered"
        assert done["stage"] == "complete" and done["status"] == "completed"
        assert done["attempted_exit"] == 0 and done["route"] == "native_resident"
    terminal = read("cline-witness-terminal.json")
    assert run["stages"] == [terminal]
    assert terminal["population"] == {"declared_attempts": 4, "validated_cases": 4}
    assert terminal["passed"] is terminal["reported_passed"] is terminal["offered"] is terminal["returned"] is True
    assert terminal["timed_out"] is terminal["containment_failed"] is terminal["output_limit_exceeded"] is False
    assert terminal["return_code"] == 0
    for key, path in (("report", "cline-witness/result.json"), ("stdout", "cline-witness.stdout"), ("stderr", "cline-witness.stderr")):
        assert terminal[key] == image((RAW / path).read_bytes())
    junit = ET.parse(RAW / "source-controls.xml").getroot()
    cases = list(junit.iter("testcase"))
    identities = [(case.attrib.get("classname"), case.attrib["name"]) for case in cases]
    assert len(cases) == len(set(identities)) == 181
    assert all(not any(case.find(tag) is not None for tag in ("failure", "error", "skipped")) for case in cases)
    local = ET.parse(ROOT.parent / "cline-intel-subprocess-v4-validation/peer-corrected-controls.xml").getroot()
    assert identities == [(case.attrib.get("classname"), case.attrib["name"]) for case in local.iter("testcase")]
    types = read("types.json")["summary"]
    assert types["filesAnalyzed"] == 12 and types["errorCount"] == 0 and types["warningCount"] == 887
    jobs = json.loads((ROOT / "cline_jobs.json").read_text())["jobs"]
    assert len(jobs) == 1 and jobs[0]["id"] == 106133194433 and jobs[0]["conclusion"] == "success"
    return {"schema": "pr2974.cline-intel-nested-result-verification.v1", "run_id": 35531647232, "artifact_id": 10611496593, "archive": image(original), "members_verified": len(members), "members": members, "source_driver": expected_ids, "historical_wheel_binding": binding["original_archive_provenance"], "wheel_build_source": binding["artifact_source"], "source_binding_before_after_equal": True, "installed_before_after_equal": True, "controls": {"unique_passed": 181, "ordered_identity_matches_local_frozen_controls": True, "errors": 0, "skips": 0}, "type_summary": types, "cases": rows, "original_ledger_rows": 8, "top_level_result_passed": True, "instrumented_functional_evidence": True, "all_nested_calls_completed_normally": False, "historical_missing_sidecar_cause_established": False, "performance_qualified": False, "external_host_application_executed": False, "windows_or_current400_runtime_qualification": False, "scope": "One original Intel four-case population on unchanged historical be612 wheel; no Linux/ARM replay. Two original PreToolUse subprocess calls raised TimeoutExpired at the unchanged nine-second limit; both PostToolUse calls returned zero. All four child native/context/receipt oracles and outer output/exit checks passed. Saturating all-event profile callbacks and observer export cost prevent uninstrumented timing claims. The prior missing sidecar remains an unresolved historical failure; this result does not retroactively attribute its cause."}


if __name__ == "__main__":
    value = verify()
    with (ROOT / "VERIFIED-RESULT.json").open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
    print(json.dumps({key: value[key] for key in ("run_id", "members_verified", "controls", "cases", "all_nested_calls_completed_normally")}))
