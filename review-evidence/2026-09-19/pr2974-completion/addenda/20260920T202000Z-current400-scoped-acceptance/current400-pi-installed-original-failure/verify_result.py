"""Data-only readback of original installed Pi failures; no workload execution."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
JOBS = json.loads((ROOT / "jobs.json").read_text())["jobs"]
ARTIFACTS = json.loads((ROOT / "artifacts.json").read_text())["artifacts"]
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
    assert len(cases) == 147 and len({(x.get("classname"), x.get("name")) for x in cases}) == 147
    assert not any(x.find(kind) is not None for x in cases for kind in ("failure", "error", "skipped"))
    report = json.loads((raw / "pi-sources.json").read_text())
    run = json.loads((raw / "run.json").read_text())
    before, after = (json.loads((raw / (name + ".json")).read_text()) for name in ("before", "after"))
    assert before["passed"] and after["passed"] and run["installation_unchanged"]
    assert report["passed"] is False and report["offered_harnesses"] == ["pi"]
    assert report["cleanup"] == {"contained": True, "failures": []}
    assert report["export_privacy"]["declared_markers_absent"] is True
    assert len(report["callback_rows"]) == 10
    rows = report["receipts"]["rows"]
    assert len(rows) == 5 and len({v["receipt"]["decision_id"] for v in rows.values()}) == 5
    summaries = []
    for callback in report["callback_rows"][1::2]:
        label = callback["id"]
        native = rows[label]
        receipt = native["receipt"]
        assert native["committed_receipt"] == receipt
        assert all(native[field] is True for field in ("returned", "ack_binding_valid", "edge_binding_valid", "request_binding_valid", "installed_rule_binding_valid", "entry_payload_unchanged", "writer_admitted"))
        fetch = callback["fetches"][0]
        assert fetch["decision"] == receipt["decision"]
        assert fetch["policy_action"] == receipt["policy_action"]
        assert fetch["reason_code"] == receipt["reason_code"]
        encrypted = label.startswith("pi-source-")
        assert fetch["encrypted_payload_ref_present"] is encrypted
        if encrypted:
            assert receipt["payload_kind"] == "encrypted_payload_ref"
            assert fetch["encrypted_payload_sha256"] == native["entry_encrypted_payload_sha256"]
        summaries.append({"label": label, "decision": receipt["decision"], "policy_action": receipt["policy_action"], "reason_code": receipt["reason_code"], "payload_kind": receipt["payload_kind"], "receipt_checks": native["receipt_checks"], "committed_equal": True, "strong_binding_fields_passed": True})
    assert report["failure"]["origin"] == "native_slo_pi_sources.validate_delivery" and report["failure"]["line"] == 139
    assert report["processes"][0]["returncode"] == 0
    assert not any(report["processes"][0][k] for k in ("timed_out", "containment_failed", "output_limit_exceeded"))
    RESULTS.append({"artifact_id": artifact["id"], "name": artifact["name"], "archive_bytes": len(archive), "archive_sha256": hashlib.sha256(archive).hexdigest(), "members_verified": len(verification["members"]), "controls": {"passed": 147, "failed": 0, "skipped": 0}, "identity": report["identity"], "callback_offers": 5, "callback_returns": 5, "encrypted_native_posts": 3, "committed_receipts": 5, "omp_offered": False, "rows": summaries, "failure": report["failure"], "cleanup": report["cleanup"], "passed": False})
output = {"schema": "hol-guard.pi-installed-original-result-readback.v1", "run_id": 35533876624, "driver": "a9b51e6ddd80e8975d9e16c050cd2fd78d074560", "source": "4cf6509fd6cfc357d3e46764f9f4c243d7a6a044", "product": "4001185e4f39cad51fd5eab314bf02b86b8a1674", "build": "37fd05b37685d0f4b37f836608820cf577a06602", "overall_passed": False, "cells": RESULTS, "scope": "Original source/install admission passed; all three installed original runs failed the exact clean-output reason oracle. No replay, no OMP execution, no performance or all-platform qualification."}
(ROOT / "VERIFIED-RESULT.json").write_text(json.dumps(output, indent=2) + "\n")
print(json.dumps({"verified_cells": len(RESULTS), "overall_passed": False}))
