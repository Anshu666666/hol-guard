"""Data-only verification of original Cline diagnostic artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).parent
SOURCE = ROOT.parent / "cline-witness-v3"
SOURCE_SHA = "156646a6a72f6b90dbcf45ff0c1e42d0dc2258df"
DRIVER_SHA = "9a6f20c7f019a1000828adad0925436e5725c643"


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def read(folder: Path, name: str) -> dict:
    return json.loads((folder / "raw" / name).read_bytes())


def verify(folder: Path) -> dict:
    metadata = json.loads((folder / "metadata.json").read_bytes())
    archive = (folder / "artifact.zip").read_bytes()
    assert len(archive) == metadata["size_in_bytes"]
    assert "sha256:" + digest(archive) == metadata["digest"]
    members = []
    with zipfile.ZipFile(folder / "artifact.zip") as zipped:
        assert len(zipped.namelist()) == len(set(zipped.namelist()))
        for name in zipped.namelist():
            original = zipped.read(name)
            assert original == (folder / "raw" / name).read_bytes()
            members.append({"path": name, "bytes": len(original), "sha256": digest(original)})
    before, after = read(folder, "before.json"), read(folder, "after.json")
    assert before["passed"] is True and after["passed"] is True
    assert before["binding"] == after["binding"]
    binding = before["binding"]
    assert binding["candidate_source"] == SOURCE_SHA
    assert binding["driver_source"] == DRIVER_SHA
    for name, identity in binding["candidate_files"].items():
        body = (SOURCE / name).read_bytes()
        assert identity == {"bytes": len(body), "sha256": digest(body)}
    cases = list(ET.parse(folder / "raw" / "source-controls.xml").iter("testcase"))
    identities = [(case.get("classname"), case.get("name")) for case in cases]
    assert len(identities) == len(set(identities)) == 134
    assert not any(case.find(tag) is not None for case in cases for tag in ("failure", "error", "skipped"))
    types = read(folder, "types.json")["summary"]
    assert types["errorCount"] == 0
    provision, run = read(folder, "provision.json"), read(folder, "run.json")
    assert provision["passed"] is True
    assert provision["installed_before"] == provision["installed_after"]
    assert run["installed_before"] == run["installed_after"]
    assert run["installation_unchanged"] is True
    assert run["passed"] is (binding["cell"] != "mac-x64")
    assert provision["installed_after"] == run["installed_before"]
    result = read(folder, "cline-witness/result.json")
    terminal = read(folder, "cline-witness-terminal.json")
    observed = []
    if binding["cell"] == "mac-x64":
        assert result["passed"] is False and len(result["attempts"]) == 1
        attempt = result["attempts"][0]
        assert attempt["case_id"] == "cline/PreToolUse/benign/small" and attempt["passed"] is False
        assert attempt["child_unavailable"] is True and "child" not in attempt
        assert not (folder / "raw/cline-witness/case-0/child.json").exists()
        worker = read(folder, "cline-witness/case-0/worker.json")
        assert worker == attempt["worker"] and worker["schema"] == "hol-guard.cline-worker-start.v1"
        assert worker["configuration_sha256"] == attempt["observer_installation"]["configuration_sha256"]
        assert worker["isolated"] is True and worker["no_user_site"] is True
        assert attempt["original_delivery"] == {"exit_checked": True, "stdout_checked": True}
        assert "original_setup_validated" not in attempt
        assert attempt["cleanup_faults"] == [] and attempt["owned_sidecars_retained"] is False
        failure = result["failure"]
        assert failure["category"] == "FileNotFoundError" and failure["errno"] == 2
        assert failure["origin"] == "profile_runtime.private_read" and failure["line"] == 62
        assert terminal["return_code"] == 1 and terminal["passed"] is False
        observed.append({"case_id": attempt["case_id"], "worker": worker, "child_unavailable": True,
            "original_delivery_validated": True, "original_native_oracle_observed": False,
            "cleanup_faults": [], "owned_sidecars_retained": False, "failure": failure})
    else:
        expected_cases = ["cline/PreToolUse/benign/small", "cline/PreToolUse/dangerous/small", "cline/PostToolUse/benign/1k", "cline/PostToolUse/block/1k"]
        assert result["declared_cases"] == expected_cases
        assert result["passed"] is True and [a["case_id"] for a in result["attempts"]] == expected_cases
        assert result["performance_qualified"] is False and result["external_host_application_executed"] is False
        assert result["historical_failed_run_reclassified"] is False
        for index, attempt in enumerate(result["attempts"]):
            assert attempt["original_delivery"] == {"exit_checked": True, "stdout_checked": True}
            assert attempt["original_setup_validated"] is True
            child, worker = read(folder, f"cline-witness/case-{index}/child.json"), read(folder, f"cline-witness/case-{index}/worker.json")
            assert child == attempt["child"] and worker == attempt["worker"]
            assert child["parent_pid"] == worker["pid"]
            assert child["configuration_sha256"] == worker["configuration_sha256"] == attempt["observer_installation"]["configuration_sha256"]
            assert child["isolated"] is True and child["no_user_site"] is True
            assert worker["isolated"] is True and worker["no_user_site"] is True
            assert child["faults"] == []
            assert child["callbacks"] == 2_000_000 and child["callbacks_saturated"] is True and set(child["counts"].values()) == {1}
            assert child["maximum_counted_callbacks"] == 2_000_000 and child["callback_count_scope"] == "all_profile_events_saturating"
            assert child["schema"] == "hol-guard.cline-child-edge.v2"
            assert child["profile_restored"] is True and child["open_frames"] == 0
            assert child["observation_complete"] is True and "validation_fault" not in child
            assert child["original_values_stable"] is True
            edge = child["original_edge"]
            assert edge["complete"] is True and edge["request_context_equal"] is True
            for key in ("original_validator_called", "original_native_validation_passed", "payload_equal", "edge_shape_valid", "receipt_matches_original_edge", "receipt_accepted_by_original_worker", "python_oracle_disabled", "policy_binding_valid"):
                assert edge[key] is True
            assert edge["original_worker_route"] == "native_resident" and edge["original_worker_routes"] == {"native_resident": 1}
            assert edge["original_payload_sha256"] == edge["declared_payload_sha256"]
            assert all(v["same_type_and_value"] is True and v["present"] == v["expected_present"] for v in edge["semantic_fields"].values())
            assert attempt["cleanup_faults"] == [] and "owned_sidecars_retained" not in attempt
            assert attempt["passed"] is True
            assert edge["receipt_workspace_bound"] is False and edge["receipt_workspace_binding_matches_source"] is True
            fields = edge["request_context_fields"]
            assert set(fields) == {"harness", "event", "cwd", "home_dir", "guard_home", "source_ref_external_allowed", "observe_mode"}
            assert all(value is True for value in fields.values())
            assert attempt["fixture_daemon_routes_before"] == attempt["fixture_daemon_routes_after"] == {}
            observed.append({"case_id": attempt["case_id"], "worker": worker, "child": child, "cleanup_faults": [], "original_delivery_and_setup_validated": True})
    assert terminal["returned"] is True
    assert terminal["return_code"] == (1 if binding["cell"] == "mac-x64" else 0)
    assert terminal["timed_out"] is False and terminal["containment_failed"] is False
    assert terminal["output_limit_exceeded"] is False
    for name, descriptor in (("cline-witness/result.json", terminal["report"]), ("cline-witness.stdout", terminal["stdout"]), ("cline-witness.stderr", terminal["stderr"])):
        body = (folder / "raw" / name).read_bytes()
        assert descriptor == {"bytes": len(body), "sha256": digest(body)}
    passed = binding["cell"] != "mac-x64"
    if passed:
        assert terminal["passed"] is True and terminal["population"] == {"declared_attempts": 4, "validated_cases": 4}
    return {
        "cell": binding["cell"], "artifact_id": metadata["id"],
        "archive_bytes": len(archive), "archive_sha256": digest(archive), "members": members,
        "source_and_installed_bindings_unchanged": True, "eight_source_members_rehashed": True,
        "controls": {"passed": 134, "failed": 0, "skipped": 0}, "types": types,
        "original_cases_offered": len(result["attempts"]), "original_cases_declared": 4,
        "first_original_delivery_validated": True, "first_original_setup_validated": passed,
        "observations": observed, "invocation_preflight": result["invocation_preflight"],
        "original_selected_edge_observed": passed, "original_native_oracle_passed": passed, "native_route_reported": "native_resident" if passed else None, "request_context_equal": True if passed else None, "total_case_gate_passed": passed,
        "owned_sidecars_cleaned": True, "child_profile_restoration_observed": passed, "outer_timeout_or_containment_failure": False,
        "prior_failures_reclassified": False, "performance_qualified": False,
    }


if __name__ == "__main__":
    rows = [verify(path) for path in sorted(ROOT.iterdir()) if (path / "artifact.zip").is_file()]
    report = {"schema": "pr2974.cline-child-witness-result.v3", "run_id": 35528246240, "source": SOURCE_SHA, "driver": DRIVER_SHA, "cells": rows,
        "finding": "Linux and Mac ARM each complete four original Cline cases; Intel fails at the first missing CLI child report after original delivery succeeds, leaving three cases unoffered and native attribution unavailable.",
        "limits": ["Instrumented functional correctness only; no uninstrumented timing or external host application proof.", "Intel missing CLI report is not attributed to timeout, import, native failure or profiling overhead by these records; no rerun performed.", "The exact no--workspace CLI forwards cwd None and actual receipt workspace_bound remains false; request-specific workspace policy and source-reference authority are not qualified.", "Native receipt joins the existing authenticated merged snapshot generation/digest/runtime/rule identity; it does not create an absent workspace binding.", "No replay or budget change by this data-only reader. All prior failed runs remain separate and failed."]}
    (ROOT / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"cells": [{"cell": r["cell"], "artifact_id": r["artifact_id"], "controls": r["controls"], "cases": r["original_cases_offered"]} for r in rows]}))
