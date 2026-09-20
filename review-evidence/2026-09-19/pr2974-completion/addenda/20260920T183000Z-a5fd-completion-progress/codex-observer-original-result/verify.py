"""Data-only verification of the one original Codex executed-guard run."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent


def identity(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def verify():
    metadata = json.loads((ROOT / "artifact-metadata.json").read_bytes())["artifacts"][0]
    archive = (ROOT / "artifact.zip").read_bytes()
    assert identity(archive) == {"bytes": metadata["size_in_bytes"], "sha256": metadata["digest"][7:]}
    assert metadata["id"] == 10609304300
    assert metadata["workflow_run"]["head_sha"] == "cd064483f5d25d2a0bc45a343605ed8dad356efb"
    raw = ROOT / "raw"
    members = {}
    with zipfile.ZipFile(ROOT / "artifact.zip") as zipped:
        infos = zipped.infolist()
        assert len(infos) == len({row.filename for row in infos}) == 18
        for info in infos:
            path = Path(info.filename)
            assert not path.is_absolute() and ".." not in path.parts and info.file_size < 2_000_000
            body = zipped.read(info)
            assert body == (raw / path).read_bytes()
            members[info.filename] = identity(body)
    load = lambda name: json.loads((raw / name).read_bytes())
    run = load("run.json")
    binding = run["binding"]
    for key, value in {
        "driver_source": "cd064483f5d25d2a0bc45a343605ed8dad356efb",
        "driver_tree": "baa56a07b2f0060821d389e55261f15ddf8b3a6b",
        "candidate_source": "b76d9027a80304ebfd0841ebe56847feeab72022",
        "candidate_tree": "5fbbed173e7f05a7cef4a787b5a61730a3459a9e",
        "product_source": "f8f190a286159b46bf14a624a62ba52b5d2371a3",
        "cell": "linux-x64",
    }.items():
        assert binding[key] == value
    assert binding["artifact_source"]["build_source"] == "be612a3e562a2041b3732a33c158eeae4f1dad40"
    for label in ("before", "provision", "after"):
        item = load(label + ".json")
        assert item["binding"] == binding and item["passed"] is True
    assert run["passed"] is True and run["installation_unchanged"] is True
    assert run["installed_before"] == run["installed_after"]
    assert len(run["stages"]) == 1
    terminal = load("codex-guard-terminal.json")
    assert run["stages"][0] == terminal
    assert terminal["population"] == {"declared_attempts": 1, "validated_cases": 0}
    assert terminal["report"] == members["codex-guard.json"]
    assert terminal["return_code"] == 0 and terminal["passed"] is True
    assert terminal["returned"] is terminal["offered"] is True
    assert not any(terminal[k] for k in ("containment_failed", "timed_out", "output_limit_exceeded"))
    for name in ("stdout", "stderr"):
        assert terminal[name] == members["codex-guard." + name]
    report, observer = load("codex-guard.json"), load("codex-guard.guards.json")
    assert report["observer"] == observer and report["observer_sha256"] == members["codex-guard.guards.json"]["sha256"]
    assert report["case_ledger_sha256"] == members["codex-guard.jsonl"]["sha256"]
    assert report["passed"] is True and report["original"]["original_passed"] is False
    assert report["original"]["fixture_closed"] is True and report["original"]["fixture_spawns"] == 1
    assert all(report[k] is False for k in ("qualification_complete", "native_approval_consume_qualified", "performance_qualified"))
    ledger = [json.loads(row) for row in (raw / "codex-guard.jsonl").read_bytes().splitlines()]
    assert len(ledger) == 2 and [row["status"] for row in ledger] == ["offered", "failed"]
    assert ledger[0]["case_digest"] == ledger[1]["case_digest"]
    assert ledger[1]["failure"] == report["original"]["original_failure"]
    approval = ledger[1]["approval"]
    assert approval["approval_durable"] is True and approval["state"] == "resolved" and approval["resolution"] == "allow"
    assert approval["live_decision"] == [] and approval["continuation_status"] == "pending"
    guards, native = observer["guards"], observer["native_returns"]
    for item in (guards, native):
        assert item["complete"] is True and item["active_calls"] == 0 and item["overflow"] is False
    assert guards["source_bound"] is True and guards["instrumented_deadline_unchanged"] is True
    assert guards["latency_qualified"] is False and len(guards["calls"]) == 1
    call = guards["calls"][0]
    assert call["return_statement_line"] == 196 and call["return_event_line"] == 144
    assert call["return_group"] == "stored_request_digest_mismatch"
    assert call["returned"] is call["trace_restored"] is call["complete"] is True
    helpers = [row for row in call["events"] if row["event"] == "helper_return"]
    assert helpers == [{"event": "helper_return", "helper": "_original_hook_is_live", "value": True}, {"event": "helper_return", "helper": "native_review_binding_matches", "value": True}]
    assert len(native["rows"]) == 2
    old, new = [row["receipt_identity"] for row in native["rows"]]
    for row in native["rows"]:
        assert all(row[k] is True for k in ("entered", "returned", "captured", "edge_present"))
        assert row["entry_snapshot"]["snapshot_generation"] == 1
    for name in ("receipt_generation", "receipt_policy_digest", "receipt_runtime_identity"):
        assert old[name] == new[name]
    assert old["receipt_generation"] == 1
    projection = call["projection"]
    assert old["fresh_request_digest"] == projection["stored_request_digest"] == projection["artifact_digest"]
    assert new["fresh_request_digest"] == projection["fresh_request_digest"] != old["fresh_request_digest"]
    assert projection["request_matches_stored"] is projection["request_matches_artifact"] is False
    cases = list(ET.parse(raw / "source-controls.xml").iter("testcase"))
    assert len(cases) == 55 and not any(row.find(k) is not None for row in cases for k in ("failure", "error", "skipped"))
    return {"artifact_id": metadata["id"], "archive": identity(archive), "members": members, "source_controls_passed": 55,
            "declared_attempts": 1, "original_validated_cases": 0, "original_failure": report["original"]["original_failure"],
            "diagnostic_complete": True, "installation_unchanged": True, "call": call, "native_returns": native["rows"],
            "scope": "Data-only original-byte readback; no test, product import, or native workload repeated. The exact changed digest input is not observed by this diagnostic."}


if __name__ == "__main__":
    result = verify()
    (ROOT / "verified-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in {"members", "call", "native_returns"}}))
