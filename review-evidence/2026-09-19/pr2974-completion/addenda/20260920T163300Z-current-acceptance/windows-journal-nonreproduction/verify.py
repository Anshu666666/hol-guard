"""Data-only verification of the single retained-wheel diagnostic result."""

import hashlib
import json
import resource
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
ROOT = Path(__file__).resolve().parent
RAW = ROOT / "10607348736/raw"
SOURCE = ROOT.parent / "windows-journal-diagnostic-ad9d"


def unique(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, "duplicate_json_key"
        result[key] = value
    return result


def read(name):
    return json.loads((RAW / name).read_text(encoding="utf-8-sig"), object_pairs_hook=unique)


def digest(body):
    return hashlib.sha256(body).hexdigest()


verification = json.loads((ROOT / "10607348736/verification.json").read_text())
assert verification["archive_bytes"] == 16996
assert digest((ROOT / "10607348736/artifact.zip").read_bytes()) == verification["archive_sha256"] == "6db9b7d65f32551f6bfd9b7dab96d3008b1a02e313bb52267ff3771ad492b17a"
for member in verification["members"]:
    body = (RAW / member["path"]).read_bytes()
    assert len(body) == member["bytes"] and digest(body) == member["sha256"]
before, after = read("binding-before.json"), read("binding-after.json")
assert before == after and read("binding-comparison.json") == {"equal": True}
assert before["diagnostic_source"] == "7aa7858ffbc57bb7e87cb83131e4e119d34896c1"
assert before["diagnostic_tree"] == "ce1e1c63c03ed026867ace846bfae670717e8787"
assert before["product_source"] == "ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d"
assert before["product_tree"] == "19977465d6e419f1276d75fb6bd1b3477f5c9720"
assert before["build_sha"] == "be612a3e562a2041b3732a33c158eeae4f1dad40"
assert before["runtime_sha256"] == "09142ea9fa88542db7bca04dd6cb568f4b389fea2c5b4ed2709de905931b3e7c"
assert before["manifest_sha256"] == "d65a148a4e8d2920b72f33ea892e75171502f079d640a4b99547aa6d1e1b4ad8"
assert before["python"].startswith("3.12.10 ")
assert "\\.venv\\Lib\\site-packages\\" in before["installed_package"]
assert len(before["sources"]) == 8
for row in before["sources"]:
    body = subprocess.check_output(["git", "-C", str(SOURCE), "show", before["product_source"] + ":" + row["source"]], timeout=10)
    assert digest(body) == row["lf_sha256"]
    checkout = body.replace(b"\n", b"\r\n")
    assert len(checkout) == row["bytes"] and digest(checkout) == row["actual_sha256"]
checkouts = read("checkouts-before.json")
end_checkouts = read("checkouts-after.json")
assert end_checkouts.pop("tracked_changes") == [] and end_checkouts == checkouts
assert checkouts == {"source": before["diagnostic_source"], "source_tree": before["diagnostic_tree"], "driver": "f4ae20180af3ae86cb46c6acda5885dcce3f0430", "driver_tree": "27d7fef70399b8b30842f1792dc2cf11ec512a5e"}
artifact = read("artifact-binding.json")
assert artifact["artifact_id"] == 10606624387 and artifact["archive_bytes"] == 8255943
assert artifact["archive_sha256"] == "62e2fd5230a00341a49827106b8e0f0ca074745f245fe4e242e85cb8ca57bc60"
original_members = json.loads((ROOT.parent / "windows-normal-ad9d/10606624387/verification.json").read_text())["members"]
assert [{"path": item["member"], "bytes": item["bytes"], "sha256": item["sha256"]} for item in artifact["members"]] == original_members
xml = (RAW / "controls.xml").read_bytes()
assert b"<!DOCTYPE" not in xml and b"<!ENTITY" not in xml
cases = ET.fromstring(xml).findall(".//testcase")
assert len(cases) == len({(case.attrib["classname"], case.attrib["name"]) for case in cases}) == 33
assert all(case.find(kind) is None for case in cases for kind in ("failure", "error", "skipped"))
assert read("types.json")["summary"]["errorCount"] == 0
assert read("types.json")["summary"]["warningCount"] == 322
report = read("journal-origin.json")
assert report["events"] == [] and report["end_return_event_count"] == 0
assert report["original_snapshot_permission_count"] == report["events_through_end_return_with_permission_errno"] == 0
assert report["snapshot_calls"] == report["original_probe_invocations"] == 1
assert all(report[key] is True for key in ("callbacks_restored", "observation_complete", "snapshot_permission_count_reconciled"))
assert all(report[key] is False for key in ("failure_reproduced", "lost", "overflow", "recording_failed", "qualification", "individual_event_snapshot_membership_proven"))
probe = read("native-default-auto.json")
assert probe["receipt_metrics"] == {"accepted": 21, "deduped": 0, "dropped": 0, "durable_pending": 0, "failures": 0, "processed": 21}
assert probe["resident_decisions"] == probe["corpus_decisions"] == 21
assert probe["evidence_failure_diagnostics"] == {"all_evidence": {"command_activity_persistence/sqlite_busy": 1}, "native_receipts": {}}
assert json.loads((RAW / "original-probe.log").read_text(encoding="utf-8-sig")) == probe
exit_record = read("original-probe-exit.json")
assert exit_record == {"returncode": 0, "instrumented_cause_diagnostic": True, "timing_qualification": False, "driver_invocations": 1}
result = {"schema": "pr2974.journal-origin-result.v1", "run": 35519440142, "job": 106100857760, "archive": verification, "binding": before, "source_and_dependencies_unchanged": True, "source_controls": {"passed": 33, "failed": 0, "skipped": 0, "type_errors": 0, "type_warnings": 322}, "journal_origin": report, "original_probe": probe, "original_exit": exit_record, "qualification": False, "limits": ["One original workload, no replay: journal permission failure was not reproduced.", "The observed command_activity_persistence/sqlite_busy:1 is outside this journal-only collector and remains unexplained.", "Earlier ordinary ad9d/f8 journal_checkpoint/os_permission:1 outcomes remain failed persistence evidence; no historical cause is resolved.", "No performance, zero-error persistence or cause-specific product repair follows."]}
(ROOT / "verified-result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"controls_passed": 33, "source_guards": 8, "journal_reproduced": False, "all_evidence": probe["evidence_failure_diagnostics"]["all_evidence"], "original_exit": 0}))
