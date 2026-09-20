"""Data-only verification of original Pi/OMP installed results; no replay."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
ARTIFACTS = json.loads((ROOT / "artifacts.json").read_text())["artifacts"]
EXPECTED = {
    "pre-allow": ("allow", "warn", "native_policy_warning"),
    "pre-block": ("deny", "block", "native_destructive_command"),
    "source-clean": ("allow", "warn", "native_policy_warning"),
    "source-tail-secret": ("deny", "block", "source_secret_match"),
    "source-changed": ("deny", "block", "no_output_to_review"),
}
LABELS = [harness + "-" + suffix for harness in ("pi", "omp") for suffix in EXPECTED]
RESULTS = []
for artifact in ARTIFACTS:
    folder = ROOT / str(artifact["id"])
    raw = folder / "raw"
    archive = (folder / "artifact.zip").read_bytes()
    assert len(archive) == artifact["size_in_bytes"]
    assert hashlib.sha256(archive).hexdigest() == artifact["digest"].removeprefix("sha256:")
    verification = json.loads((folder / "verification.json").read_text())
    for member in verification["members"]:
        body = (raw / member["path"]).read_bytes()
        assert len(body) == member["bytes"] and hashlib.sha256(body).hexdigest() == member["sha256"]
    cases = ET.parse(raw / "source-controls.xml").findall(".//testcase")
    assert len(cases) == 162 and len({(x.get("classname"), x.get("name")) for x in cases}) == 162
    assert not any(x.find(kind) is not None for x in cases for kind in ("failure", "error", "skipped"))
    assert len([x for x in cases if x.get("classname") == "tests.test_native_slo_pi_default_policy"]) == 15
    report = json.loads((raw / "pi-sources.json").read_text())
    run = json.loads((raw / "run.json").read_text())
    before, after = (json.loads((raw / (name + ".json")).read_text()) for name in ("before", "after"))
    assert before["passed"] and after["passed"] and before["binding"] == after["binding"] == run["binding"]
    binding = before["binding"]
    assert binding["candidate_source"] == "4f3d200ef3350725dad06c1f5a920a550c5146e9"
    assert binding["candidate_tree"] == "316f43a3c74c6e856a1cbbb41818e31711b4f3b4"
    assert binding["driver_source"] == "cf663ff128e92baa851c22563c516c74fe8839e8"
    assert binding["driver_tree"] == "40bab5bcf9d5bedef1a6530c98ccf318a7e5d151"
    assert binding["product_source"] == "4001185e4f39cad51fd5eab314bf02b86b8a1674"
    assert binding["artifact_source"]["build_source"] == "37fd05b37685d0f4b37f836608820cf577a06602"
    assert binding["artifact_source"]["build_tree"] == binding["product_tree"] == "7a328609488ffefecd3cdd12a9c7adba6a591e97"
    contract = json.loads((raw / "input-contract.json").read_text())
    assert binding["candidate_files"] == {row["path"]: {key: row[key] for key in ("bytes", "sha256")} for row in contract["candidate_files"]}
    assert run["passed"] is True and run["installation_unchanged"] is True
    assert run["installed_before"] == run["installed_after"]
    assert run["installed_before"]["record_entries_verified"] >= 1500
    assert run["performance_claim"] is False and run["qualification_complete"] is False
    assert report["passed"] is True and report["offered_harnesses"] == ["pi", "omp"]
    assert report["cleanup"] == {"contained": True, "failures": []}
    assert report["export_privacy"]["declared_markers_absent"] is True
    assert report["export_privacy"]["all_exporters_qualified"] is False
    assert report["http_native_reference_join"] is True
    assert report["native_route_metrics"] == {"native_resident": 10}
    assert [row["id"] for row in report["callback_rows"]] == [label for label in LABELS for _ in range(2)]
    assert all(row["offered"] is True and row["returned"] is False for row in report["callback_rows"][::2])
    rows = report["receipts"]["rows"]
    assert report["receipts"]["complete"] is True and report["receipts"]["writer_drained"] is True
    assert report["receipts"]["extra_calls"] == report["receipts"]["active_calls"] == 0
    assert set(rows) == set(LABELS) and len({v["receipt"]["decision_id"] for v in rows.values()}) == 10
    summaries = []
    for callback in report["callback_rows"][1::2]:
        label = callback["id"]
        harness, suffix = label.split("-", 1)
        native = rows[label]
        receipt = native["receipt"]
        assert native["committed_receipt"] == receipt
        assert all(native[field] is True for field in ("returned", "ack_binding_valid", "edge_binding_valid", "request_binding_valid", "installed_rule_binding_valid", "entry_payload_unchanged", "writer_admitted", "receipt_checks"))
        assert callback["returned"] is True and callback["input_unchanged"] is True
        assert len(callback["fetches"]) == 1
        fetch = callback["fetches"][0]
        assert (fetch["method"], fetch["pathname"], fetch["status"]) == ("POST", "/v1/hooks/" + harness, 200)
        assert tuple(fetch[k] for k in ("decision", "policy_action", "reason_code")) == EXPECTED[suffix]
        assert tuple(receipt[k] for k in ("decision", "policy_action", "reason_code")) == EXPECTED[suffix]
        assert receipt["harness"] == harness and receipt["observe_mode"] is False
        encrypted = suffix.startswith("source-")
        assert fetch["encrypted_payload_ref_present"] is encrypted
        if encrypted:
            assert receipt["payload_kind"] == native["source_payload_kind"] == "encrypted_payload_ref"
            assert fetch["encrypted_payload_sha256"] == native["entry_encrypted_payload_sha256"]
        if EXPECTED[suffix][0] == "allow":
            assert callback["preserved"] is True
            if encrypted:
                assert fetch["model_output_action"] == receipt["model_output_action"] == "allow_original"
                assert fetch["reviewed_output_sha256"] == receipt["reviewed_output_sha256"] == "5c4c9f1b6008c49a73914d84267e50de7e18fbeba615b982967e058327d932ae"
        else:
            assert callback["preserved"] is False and callback["blocked"] is True
            if encrypted:
                assert callback["model_blocked"] is True and fetch["model_output_action"] == receipt["model_output_action"] == "block"
        summaries.append({"label": label, "decision": receipt["decision"], "policy_action": receipt["policy_action"], "reason_code": receipt["reason_code"], "payload_kind": receipt["payload_kind"], "receipt_checks": True, "committed_equal": True, "strong_binding_fields_passed": True})
    assert len(report["processes"]) == 2
    assert all(p["returncode"] == 0 and not any(p[k] for k in ("timed_out", "containment_failed", "output_limit_exceeded")) for p in report["processes"])
    coverage = report["encrypted_post_coverage"]
    assert coverage["complete"] and coverage["encrypted_posts"] == 6 and coverage["distinct_durable_native_receipts"] == 10
    assert coverage["windows_encrypted_reference_supported"] is False and coverage["native_requests_replayed"] is False
    RESULTS.append({"artifact_id": artifact["id"], "name": artifact["name"], "archive_bytes": len(archive), "archive_sha256": hashlib.sha256(archive).hexdigest(), "members_verified": len(verification["members"]), "controls": {"passed": 162, "failed": 0, "skipped": 0}, "identity": report["identity"], "binding": binding, "callback_offers": 10, "callback_returns": 10, "encrypted_native_posts": 6, "committed_receipts": 10, "rows": summaries, "cleanup": report["cleanup"], "passed": True})
assert len(RESULTS) == 3
output = {"schema": "hol-guard.pi-installed-original-result-readback.v2", "run_id": 35535394779, "original_failed_run": 35533876624, "overall_passed": True, "cells": RESULTS, "scope": "Actual current400/build37fd three-POSIX registered generated adapter continuation. No external host application, Windows encrypted support, strict four-platform artifact set, performance, native approval consumption or release qualification claim."}
(ROOT / "VERIFIED-RESULT.json").write_text(json.dumps(output, indent=2) + "\n")
print(json.dumps({"verified_cells": len(RESULTS), "overall_passed": True, "callbacks_per_cell": 10, "encrypted_posts_per_cell": 6}))
