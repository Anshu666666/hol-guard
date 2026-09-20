"""Read retained original bytes only; never import or rerun the product."""
import hashlib
import json
from pathlib import Path
import resource
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent
RUN = 35528764054
SOURCE = "89d1b21fc30f7eb91e1f999486793ba6b72a8943"
DRIVER = "b348add2bfcc4ea05e39467e5c17707a1bac9644"
CELLS = {10609873805: "linux-x64", 10609364746: "mac-arm64", 10610582284: "mac-x64"}
CONTRACT_BLOB = "5ab41dc6939b59f2871be0dedfeddd284362d043"


def identity(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def blob(body):
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()


def verify_cell(metadata):
    artifact_id = metadata["id"]
    cell = CELLS[artifact_id]
    folder = ROOT / str(artifact_id)
    raw = folder / "raw"
    archive = (folder / "artifact.zip").read_bytes()
    assert identity(archive) == {"bytes": metadata["size_in_bytes"], "sha256": metadata["digest"][7:]}
    assert metadata["workflow_run"]["id"] == RUN
    assert metadata["workflow_run"]["head_sha"] == DRIVER
    assert metadata["name"] == f"codex-corrected-{cell}-{RUN}"
    members = {}
    with zipfile.ZipFile(folder / "artifact.zip") as zipped:
        infos = zipped.infolist()
        assert len(infos) == len({i.filename for i in infos}) == 17
        for info in infos:
            path = Path(info.filename)
            assert not path.is_absolute() and ".." not in path.parts and info.file_size < 2_000_000
            assert not info.is_dir() and (info.external_attr >> 16) & 0o170000 != 0o120000
            body = zipped.read(info)
            assert body == (raw / path).read_bytes()
            members[info.filename] = identity(body)
    assert {p.name for p in raw.iterdir()} == set(members)
    load = lambda name: json.loads((raw / name).read_bytes())
    contract_body = (raw / "input-contract.json").read_bytes()
    assert blob(contract_body) == CONTRACT_BLOB
    contract = json.loads(contract_body)
    assert contract["ready"] is True and contract["declared_population"] == {"codex-continuation": 1}
    selected = contract["cells"][cell]
    run = load("run.json")
    binding = run["binding"]
    for key, value in {
        "driver_source": DRIVER,
        "driver_tree": "4f33133c9eb72cfb3d1143b7c315c2dbaf62e00a",
        "candidate_source": SOURCE,
        "candidate_tree": "676dd7eefa8cb7c3d4b42e06b9113d3f9cfb0d15",
        "product_source": "a5fdde302aba2a06265c2e6e934b6ac9b76750df",
        "product_tree": "ee96f00e4e97fe38ab9e6782b35f92ab0aebb5e9",
        "cell": cell,
    }.items():
        assert binding[key] == value
    assert [binding["platform"], binding["machine"]] in selected["platform_identities"]
    assert binding["artifact_source"]["build_source"] == selected["build_source"]
    assert binding["artifact_source"]["build_tree"] == selected["build_tree"]
    assert binding["original_archive_provenance"] == selected["archive"]
    assert binding["native_manifest"] == selected["wheel"]["native_manifest"]
    assert binding["artifact_members"] == {r["name"]: {k: r[k] for k in ("bytes", "sha256")} for r in selected["artifact_members"]}
    assert binding["candidate_files"] == {r["path"]: {k: r[k] for k in ("bytes", "sha256")} for r in contract["candidate_files"]}
    assert binding["archive_bytes_rehashed_in_this_run"] is False
    for name in ("before", "provision", "after"):
        item = load(name + ".json")
        assert item["binding"] == binding and item["passed"] is True
        assert item["qualification_complete"] is item["performance_claim"] is False
    interpreter = load("provision.json")["interpreter"]
    for key in ("passed", "identical_bytes", "original_target_preserved", "managed_integrity_validated", "managed_validator_inside_venv", "pyvenv_cfg_unchanged", "runtime_compatible", "base_prefix_unchanged"):
        assert interpreter[key] is True
    assert interpreter["copied_sha256"] == interpreter["source_sha256"]
    assert interpreter["production_integrity_checks_relaxed"] is interpreter["shared_interpreter_chmodded"] is interpreter["wheel_bytes_modified"] is False
    assert interpreter["owned"]["owner_current"] is interpreter["owned"]["regular"] is True
    assert interpreter["owned"]["mode"] == 0o755
    assert interpreter["owned"]["group_writable"] is interpreter["owned"]["world_writable"] is False
    install = load("install-record.json")
    assert install["require_hashes"] is True and install["return_code"] == 0
    assert install["requirement"] == members["wheel-requirements.txt"]
    assert "--require-hashes" in install["command"] and "--no-deps" in install["command"] and "--no-index" in install["command"]
    assert ("--hash=sha256:" + selected["wheel"]["sha256"]) in (raw / "wheel-requirements.txt").read_text()
    assert run["passed"] is run["installation_unchanged"] is True
    assert run["qualification_complete"] is run["performance_claim"] is False
    assert run["installed_before"] == run["installed_after"]
    installed = run["installed_before"]
    assert installed["hash_enforced_install_input"] == install["requirement"]
    assert installed["direct_url_hash_not_assumed"] is True
    assert installed["inventory_scope"] == "original_wheel_members_and_RECORD_listed_files_not_unlisted_generated_caches"
    assert installed["wheel_entries_verified"] == 1499 and installed["record_entries_verified"] >= 1500
    assert len(installed["record_sha256"]) == 64
    actual_identity = installed["identity"]
    for key, value in {
        "build_sha": selected["build_source"], "rule_digest": selected["rule_digest"],
        "runtime_sha256": selected["wheel"]["native_manifest"]["runtime_sha256"],
        "wheel_sha256": selected["wheel"]["sha256"], "target": selected["capability_target"],
        "mode": "auto", "package_version": "3.0.1", "runtime_version": "3.0.1",
    }.items():
        assert actual_identity[key] == value
    terminal = load("codex-continuation-terminal.json")
    assert run["stages"] == [terminal]
    assert terminal["population"] == {"declared_attempts": 1, "validated_cases": 1}
    assert terminal["report"] == members["codex-continuation.json"]
    assert terminal["return_code"] == 0
    assert terminal["passed"] is terminal["reported_passed"] is terminal["returned"] is terminal["offered"] is True
    assert not any(terminal[k] for k in ("containment_failed", "timed_out", "output_limit_exceeded"))
    assert load("codex-continuation-offered.json") == {"label": "codex-continuation", "offered": True, "returned": False}
    for name in ("stdout", "stderr"):
        assert terminal[name] == members["codex-continuation." + name]
    report = load("codex-continuation.json")
    assert report["identity"] == actual_identity
    assert report["passed"] is True and report["declared_attempts"] == 1
    assert report["original"] == {"fixture_closed": True, "offered": 1, "original_passed": True}
    assert all(report[k] is False for k in ("qualification_complete", "native_approval_consume_qualified", "performance_qualified", "executed_line_observer"))
    assert report["case_ledger_sha256"] == members["codex-continuation.jsonl"]["sha256"]
    ledger = [json.loads(row) for row in (raw / "codex-continuation.jsonl").read_bytes().splitlines()]
    assert len(ledger) == 2 and [row["status"] for row in ledger] == ["offered", "validated"]
    offered, validated = ledger
    assert {k: validated[k] for k in offered if k != "status"} == {k: v for k, v in offered.items() if k != "status"}
    for key, value in {"harness": "codex", "event": "PreToolUse", "setup": "normal", "stage": "browser_wait_completion", "case_digest": "090130599e3915401f3947a6709a3a87c8166abecbeccb29a5dc06a49276b1ba"}.items():
        assert offered[key] == value
    for key in ("argv_sha256", "registration_sha256"):
        assert len(offered[key]) == 64
    assert validated["returncode"] == 0 and validated["delivery"] == "implicit_allow"
    assert validated["route"] == "native_resident" and validated["native_action"] == "review"
    assert validated["routes_before"] == {} and validated["routes_after"] == {"native_resident": 2}
    assert not any(validated[k] for k in ("timed_out", "containment_failed", "stream_limit_exceeded"))
    approval = validated["approval"]
    for key, value in {"state": "resolved", "resolution": "allow", "scope": "artifact", "authority": "ordinary_local_review", "matching": "exact_identity_and_new_row", "continuation_status": "sent", "continuation_capability": "suspended-response"}.items():
        assert approval[key] == value
    assert approval["approval_durable"] is approval["binding_present"] is True
    assert approval["routes"] == {"native_resident": 1} and approval["revalidation_routes"] == {}
    assert approval["live_decision"] == [{"request_id": approval["request_id"], "completed": True, "action": "allow", "replayed": False, "error": None, "fresh_allow_authorized": True}]
    assert approval["native_evaluations"] == [{"decision": "deny", "policy_action": "review", "minimum_action": "review", "reason_code": "native_sensitive_access_review"}] * 2
    cases = list(ET.parse(raw / "source-controls.xml").iter("testcase"))
    assert len(cases) == 90 and not any(row.find(k) is not None for row in cases for k in ("failure", "error", "skipped"))
    nodes = [{"classname": row.get("classname"), "name": row.get("name")} for row in cases]
    assert len({(r["classname"], r["name"]) for r in nodes}) == 90
    return {"artifact_id": artifact_id, "cell": cell, "archive": identity(archive), "members": members,
            "source_controls_passed": 90, "source_control_nodes": nodes, "original_offered": 1,
            "original_validated": 1, "native_evaluations": 2, "fresh_completed_allow": 1,
            "continuation_status": "sent", "delivery": "implicit_allow", "installation_unchanged": True,
            "installed_identity": actual_identity, "approval": approval, "ledger_sha256": report["case_ledger_sha256"]}


def verify():
    metadata = json.loads((ROOT / "metadata.json").read_bytes())
    assert metadata["total_count"] == 3 and {row["id"] for row in metadata["artifacts"]} == set(CELLS)
    jobs = json.loads((ROOT / "jobs.json").read_bytes())
    assert jobs["total_count"] == 3
    assert all(j["run_id"] == RUN and j["head_sha"] == DRIVER and j["status"] == "completed" and j["conclusion"] == "success" for j in jobs["jobs"])
    cells = [verify_cell(row) for row in sorted(metadata["artifacts"], key=lambda r: r["id"])]
    return {"schema": "rsp136.corrected-codex-original-result.v1", "run_id": RUN, "source_commit": SOURCE,
            "driver_commit": DRIVER, "cells": cells, "original_offered_total": 3, "original_validated_total": 3,
            "scope": "Three fresh a5fd package POSIX cells, one original registered Codex continuation each. Data-only original-byte verification; no workload, product import, or tests repeated.",
            "limits": ["No Windows installed credit.", "No replay of Claude, Pi, Ollama, aliases or earlier timing populations.", "Retained witness asserts durable approval and exact binding; full SQLite/receipt objects are not exported by this original corpus.", "Native decisions remain Review; fresh browser continuation delivery is distinct from native approval consumption.", "Installed identity covers original wheel members and RECORD-listed files, not unlisted generated caches.", "No performance, general RSP080, or whole RSP136 qualification claim."]}


if __name__ == "__main__":
    resource.setrlimit(resource.RLIMIT_AS, (192 * 1024 * 1024, 192 * 1024 * 1024))
    result = verify()
    (ROOT / "verified-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"run_id": RUN, "cells": [{k: v for k, v in row.items() if k in {"cell", "artifact_id", "source_controls_passed", "original_offered", "original_validated", "native_evaluations", "fresh_completed_allow", "continuation_status", "delivery", "installation_unchanged"}} for row in result["cells"]]}, sort_keys=True))
