"""Data-only verification of original Cline diagnostic artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).parent
SOURCE = ROOT.parent / "cline-witness-v2"
SOURCE_SHA = "c0a14ed4c99f0120667147ab78e30702c9eaf7db"
DRIVER_SHA = "ef21ce398463fd71baf03858dc811d5c7a86aa49"


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
    assert len(identities) == len(set(identities)) == 113
    assert not any(case.find(tag) is not None for case in cases for tag in ("failure", "error", "skipped"))
    types = read(folder, "types.json")["summary"]
    assert types["errorCount"] == 0
    provision, run = read(folder, "provision.json"), read(folder, "run.json")
    assert provision["passed"] is True
    assert provision["installed_before"] == provision["installed_after"]
    assert run["installed_before"] == run["installed_after"]
    assert run["installation_unchanged"] is True and run["passed"] is False
    assert provision["installed_after"] == run["installed_before"]
    result = read(folder, "cline-witness/result.json")
    terminal = read(folder, "cline-witness-terminal.json")
    assert len(result["attempts"]) == 1 and result["passed"] is False
    attempt = result["attempts"][0]
    assert attempt["case_id"] == "cline/PreToolUse/benign/small"
    assert attempt["original_delivery"] == {"exit_checked": True, "stdout_checked": True}
    assert attempt["original_setup_validated"] is True
    child, worker = read(folder, "cline-witness/case-0/child.json"), read(folder, "cline-witness/case-0/worker.json")
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
    assert child["observation_complete"] is False and "validation_fault" not in child
    assert child["original_values_stable"] is True
    edge = child["original_edge"]
    assert edge["complete"] is False and edge["request_context_equal"] is False
    for key in ("original_validator_called", "original_native_validation_passed", "payload_equal", "edge_shape_valid", "receipt_matches_original_edge", "receipt_accepted_by_original_worker", "python_oracle_disabled", "policy_binding_valid"):
        assert edge[key] is True
    assert edge["original_worker_route"] == "native_resident" and edge["original_worker_routes"] == {"native_resident": 1}
    assert edge["original_payload_sha256"] == edge["declared_payload_sha256"]
    assert all(v["same_type_and_value"] is True and v["present"] == v["expected_present"] for v in edge["semantic_fields"].values())
    assert attempt["cleanup_faults"] == [] and attempt["owned_sidecars_retained"] is False
    assert terminal["return_code"] == 1 and terminal["returned"] is True
    assert terminal["timed_out"] is False and terminal["containment_failed"] is False
    assert terminal["output_limit_exceeded"] is False
    for name, descriptor in (("cline-witness/result.json", terminal["report"]), ("cline-witness.stdout", terminal["stdout"]), ("cline-witness.stderr", terminal["stderr"])):
        body = (folder / "raw" / name).read_bytes()
        assert descriptor == {"bytes": len(body), "sha256": digest(body)}
    return {
        "cell": binding["cell"], "artifact_id": metadata["id"],
        "archive_bytes": len(archive), "archive_sha256": digest(archive), "members": members,
        "source_and_installed_bindings_unchanged": True, "eight_source_members_rehashed": True,
        "controls": {"passed": 113, "failed": 0, "skipped": 0}, "types": types,
        "original_cases_offered": 1, "original_cases_declared": 4,
        "first_original_delivery_and_setup_validated": True,
        "observer": child, "worker": worker, "invocation_preflight": result["invocation_preflight"],
        "original_selected_edge_observed": True, "original_native_oracle_passed": True, "native_route_reported": "native_resident", "request_context_equal": False, "total_case_gate_passed": False,
        "profile_and_owned_sidecars_cleaned": True, "outer_timeout_or_containment_failure": False,
        "original_failure_preserved": True, "performance_qualified": False,
    }


if __name__ == "__main__":
    rows = [verify(path) for path in sorted(ROOT.iterdir()) if (path / "artifact.zip").is_file()]
    report = {
        "schema": "pr2974.cline-child-witness-result.v1", "run_id": 35526812732,
        "source": SOURCE_SHA, "driver": DRIVER_SHA, "cells": rows,
        "finding": "Selected original child/native oracle/receipt are observed; aggregate request_context_equal is false, so total case gate remains failed.",
        "limits": ["Total diagnostic gate failed on request context; this is not a native semantic failure.", "Only first benign case was offered; original native oracle/delivery/receipt pass while context attribution remains failed and three cases remain unoffered.", "No replay or budget change was performed by this data-only reader.", "Prior alias failures remain failed and are not reclassified."]}
    (ROOT / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"cells": [{"cell": r["cell"], "artifact_id": r["artifact_id"], "controls": r["controls"], "callbacks": r["observer"]["callbacks"]} for r in rows]}))
