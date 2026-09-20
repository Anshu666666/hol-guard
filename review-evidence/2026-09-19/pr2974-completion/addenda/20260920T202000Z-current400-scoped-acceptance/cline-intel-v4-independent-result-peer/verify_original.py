"""Independent data-only joins; does not import product or execute a workload."""

import hashlib
import json
import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
ORIGINAL = ROOT / "cline-intel-run35531647232"
RAW = ORIGINAL / "10611496593/raw"


def image(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def read(name):
    return json.loads((RAW / name).read_bytes())


archive = ORIGINAL / "10611496593/artifact.zip"
assert image(archive.read_bytes()) == {
    "bytes": 51194,
    "sha256": "3e05470112497fba424d16633fb2c4b6893e1b9e915fc4002765a2d074219418",
}
members = []
with zipfile.ZipFile(archive) as bundle:
    assert len(bundle.namelist()) == len(set(bundle.namelist())) == 32
    assert set(bundle.namelist()) == {p.relative_to(RAW).as_posix() for p in RAW.rglob("*") if p.is_file()}
    for name in bundle.namelist():
        body = bundle.read(name)
        assert body == (RAW / name).read_bytes()
        members.append({"path": name, **image(body)})

before, after, run, provision = (read(name + ".json") for name in ("before", "after", "run", "provision"))
assert all(x["passed"] is True for x in (before, after, run, provision))
assert before["binding"] == after["binding"] == run["binding"] == provision["binding"]
assert run["installation_unchanged"] is True
assert run["installed_before"] == run["installed_after"] == provision["installed_before"] == provision["installed_after"]
binding = before["binding"]
assert binding["candidate_source"] == "14ac7d491b14af267c933f9b1de668ec8135ba35"
assert binding["driver_source"] == "edb75675005bf3a221250f51f81e68f59632be2c"
assert binding["product_source"] == "e44008445630aad28ccc291ec234f55a14892e6d"
assert binding["artifact_source"]["build_source"] == "be612a3e562a2041b3732a33c158eeae4f1dad40"
assert binding["platform"] == "Darwin" and binding["machine"] == "x86_64"
for path, descriptor in binding["candidate_files"].items():
    assert image((ROOT / "cline-intel-subprocess-v4" / path).read_bytes()) == descriptor

result = read("cline-witness/result.json")
assert result["passed"] is True
assert result["identity"] == run["installed_before"]["identity"]
assert result["historical_failed_run_reclassified"] is False and result["performance_qualified"] is False
assert result["external_host_application_executed"] is False
assert result["instrumented_functional_evidence"] is True
expected = ["cline/PreToolUse/benign/small", "cline/PreToolUse/dangerous/small", "cline/PostToolUse/benign/1k", "cline/PostToolUse/block/1k"]
assert result["declared_cases"] == expected
assert [row["case_id"] for row in result["attempts"]] == expected
cases = []
for index, row in enumerate(result["attempts"]):
    assert row["passed"] is True and row["original_setup_validated"] is True and row["cleanup_faults"] == []
    assert row["original_delivery"] == {"exit_checked": True, "stdout_checked": True}
    child, worker, nested = row["child"], row["worker"], row["nested_run"]
    for name, report in (("child", child), ("worker", worker), ("nested-run", nested)):
        assert report == read(f"cline-witness/case-{index}/{name}.json")
    assert child["parent_pid"] == nested["pid"] == worker["pid"]
    assert child["pid"] != worker["pid"]
    assert child["configuration_sha256"] == worker["configuration_sha256"] == nested["configuration_sha256"]
    assert child["observation_complete"] is True and child["profile_restored"] is True and child["faults"] == []
    assert child["open_frames"] == 0 and child["original_values_stable"] is True
    assert child["counts"] == {"edge_call": 1, "edge_return_or_unwind": 1, "worker_call": 1, "worker_return_or_unwind": 1}
    assert child["callbacks"] == child["maximum_counted_callbacks"] == 2_000_000 and child["callbacks_saturated"] is True
    assert child["headline_timing_eligible"] is False
    edge = child["original_edge"]
    for name in ("complete", "original_validator_called", "original_native_validation_passed", "payload_equal", "edge_shape_valid", "receipt_matches_original_edge", "receipt_accepted_by_original_worker", "python_oracle_disabled", "request_context_equal", "receipt_workspace_binding_matches_source", "policy_binding_valid"):
        assert edge[name] is True
    assert edge["receipt_workspace_bound"] is False
    assert edge["original_worker_routes"] == {"native_resident": 1}
    assert edge["original_payload_sha256"] == edge["declared_payload_sha256"]
    assert all(x is True for x in edge["request_context_fields"].values())
    assert all(x["same_type_and_value"] is True for x in edge["semantic_fields"].values())
    assert nested["selected_calls"] == 1 and nested["original_timeout_seconds"] == 9
    assert nested["faults"] == [] and nested["observation_complete"] is True
    assert nested["original_call_changed"] is False and nested["run_restored"] is True
    assert nested["outcome"] == ("timeout" if index < 2 else "returned")
    assert nested["returncode"] == (None if index < 2 else 0)
    cases.append({"case_id": expected[index], "nested_outcome": nested["outcome"], "nested_returncode": nested["returncode"], "original_timeout_seconds": 9, "counter_saturated_at": 2_000_000, "native_and_outer_projection_checks_passed": True})

ledger = [json.loads(line) for line in (RAW / "cline-witness/original-attempts.jsonl").read_text().splitlines()]
assert len(ledger) == 8
for index, case in enumerate(expected):
    offer, terminal = ledger[2 * index:2 * index + 2]
    assert offer["case_id"] == terminal["case_id"] == "global/" + case
    assert offer["status"] == "offered" and terminal["status"] == "completed" and terminal["attempted_exit"] == 0
terminal = read("cline-witness-terminal.json")
assert run["stages"] == [terminal] and terminal["return_code"] == 0 and terminal["passed"] is True
assert terminal["timed_out"] is False and terminal["containment_failed"] is False and terminal["output_limit_exceeded"] is False
for name, path in (("report", "cline-witness/result.json"), ("stdout", "cline-witness.stdout"), ("stderr", "cline-witness.stderr")):
    assert terminal[name] == image((RAW / path).read_bytes())
junit = list(ET.parse(RAW / "source-controls.xml").iter("testcase"))
identities = [(x.get("classname"), x.get("name")) for x in junit]
assert len(identities) == len(set(identities)) == 181
assert not any(x.find(tag) is not None for x in junit for tag in ("failure", "error", "skipped"))
assert identities == [(x.get("classname"), x.get("name")) for x in ET.parse(ROOT / "cline-intel-subprocess-v4-validation/peer-corrected-controls.xml").iter("testcase")]
types = read("types.json")["summary"]
assert (types["errorCount"], types["warningCount"]) == (0, 887)
proof = {"archive": image(archive.read_bytes()), "members": members, "cases": cases, "controls_passed": len(junit), "type_summary": types, "source_bindings_equal": True, "installation_before_after_equal": True, "workload_runs_by_peer": 0, "downloads_by_peer": 0}
(Path(__file__).parent / "independent-readback.json").write_text(json.dumps(proof, indent=2) + "\n")
print(json.dumps({"verified_members": len(members), "controls": len(junit), "cases": cases}))
