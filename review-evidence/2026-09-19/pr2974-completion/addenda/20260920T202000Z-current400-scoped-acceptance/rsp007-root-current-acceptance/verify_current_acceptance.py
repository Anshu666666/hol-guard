"""Read retained original data and exact API source bodies; invoke no workload."""
import ast
import collections
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def read(name):
    return json.loads((ROOT / name).read_text())


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "git_blob": blob(raw)}


assessment = read("rsp007-current-assessment.json")
providers = read("rsp007-current-providers.json")
raws = read("rsp007-provider-api-readbacks.json")
support = read("rsp007-supporting-api-raw.json")
current = json.loads(read("encrypted-lazy-source-api-readbacks.json")[0]["value"]["structuredContent"]["content"])
previous = read("encrypted-lazy-base-api-tree.json")
observed = read("rsp007-be612-api-tree.json")
assert current["sha"] == providers["tree"] == "7a328609488ffefecd3cdd12a9c7adba6a591e97"
assert previous["sha"] == "ee96f00e4e97fe38ab9e6782b35f92ab0aebb5e9"
assert observed["sha"] == "19977465d6e419f1276d75fb6bd1b3477f5c9720"
assert all(t["truncated"] is False for t in [current, previous, observed])
indices = [{x["path"]: x for x in t["tree"] if x["type"] == "blob"} for t in [current, previous, observed]]
bodies = {x["path"]: x for x in raws}
assert len(bodies) == len(providers["providers"]) == 13
provider_results = []
for p in providers["providers"]:
    raw = bodies[p["path"]]["raw"].encode()
    actual = identity(raw)
    assert all(actual[k] == p[k] for k in actual)
    for index in indices[:2]:
        assert index[p["path"]]["sha"] == p["git_blob"]
        assert index[p["path"]]["mode"] == "100644"
    old = indices[2][p["path"]]
    equal = old["sha"] == p["git_blob"]
    assert equal is p["same_as_observed_be612"]
    if not equal:
        assert p["path"] == "scripts/native_slo_contract.py"
        old_body = support["old_contract"]["raw"]
        assert blob(old_body.encode()) == old["sha"]
        assert ast.dump(ast.parse(old_body)) == ast.dump(ast.parse(raw))
    provider_results.append({"path": p["path"], **actual, "current_and_a5fd_exact": True, "historical_bytes_exact": equal, "historical_AST_exact": True})

evidence = assessment["existing_actual_evidence"]
for key, expected in [("result", evidence["raw_result"]), ("observation", evidence["original_observation"]), ("input", evidence["input_contract"]), ("dependency", assessment["dependency"]["root_record"])]:
    assert identity(support[key].encode()) == expected
result = json.loads(support["result"])
observation = json.loads(support["observation"])
contract = json.loads(support["input"])
assert result["run"] == evidence["run"] == 35517987547
assert result["source_sha"] == evidence["actual_build_source"] == contract["selected_build_source"]
assert result["source_tree"] == contract["selected_tree"] == observed["sha"]
assert result["driver_sha"] == observation["driver_before"]["sha"] == observation["driver_after"]["sha"]
assert result["archive_sha256"] == evidence["archive_sha256"]
assert observation["driver_before"] == observation["driver_after"]
assert observation["source_before"] == observation["source_after"]
assert observation["installed_before"] == observation["installed_after"]
block = observation["block"]
assert block["producer_invocations"] == contract["workload"]["producer_invocations"] == 1
assert block["producer_completed"] is True
assert block["expected_launches"] == result["original_launches"] == 88
parents = block["parent"]["rows"]
joins = block["joins"]["rows"]
assert len(parents) == len(joins) == 88
coordinates = lambda row: tuple(sorted(row["coordinate"].items()))
assert len({coordinates(p) for p in parents}) == 88
assert {coordinates(p) for p in parents} == {coordinates(j) for j in joins}
assert all(not block["joins"][k] for k in ["duplicate_daemon_coordinates", "duplicate_parent_coordinates", "unknown_daemon_coordinates", "unknown_parent_coordinates"])
registrations = collections.Counter()
verdicts = collections.Counter()
for p in parents:
    assert p["completed"] is True and p["outcome"] == "return"
    facts = p["facts"]
    assert facts["error_kind"] is None and len(facts["process_calls"]) == 1
    call = facts["process_calls"][0]
    assert call["returncode"] == 0
    assert call["stdout_available"] is True and call["stdout_bytes"] > 0
    assert call["stderr_available"] is True
    assert call["projection_valid"] is True
    assert all(call[k] is False for k in ["exception", "containment_failed", "timed_out", "output_limit_exceeded"])
    stages = {s["stage"]: s for s in p["stages"]}
    assert len(stages) == 5 and set(stages) == {"spawn", "io_setup", "wait_and_reap", "io_join_and_containment", "contained_process_call"}
    outer = stages["contained_process_call"]
    assert facts["launcher_latency_ms"] >= outer["duration_ms"] >= 0
    for s in stages.values():
        assert s["outcome"] == "return" and s["error_kind"] is None
        assert outer["start_ns"] <= s["start_ns"] <= s["end_ns"] <= outer["end_ns"]
        assert abs(s["duration_ms"] - (s["end_ns"] - s["start_ns"]) / 1_000_000) < 1e-9
    registrations[facts["registration_sha256"]] += 1
    verdicts[facts["original_allowed"]] += 1
for j in joins:
    assert j["complete"] is True
    assert j["checks"]["native_edge_returned_none"] is False
    assert all(v is True for k, v in j["checks"].items() if k != "native_edge_returned_none")
    assert coordinates(j) == coordinates(parents[j["parent_row"]])
assert verdicts == {True: 84, False: 4}
assert len(registrations) == 4 and set(registrations.values()) == {22}
m = block["measurements"]
assert m["boundary"] == "INSTALLED_LAUNCHER"
assert all(m[k] is True for k in ["process_startup_included", "stdout_and_exit_checked", "contracts_passed"])
assert m["resident_cold_measured"] is False and m["cold_state"] == "fresh_launcher_process_resident_prepared"
assert {x["registration_sha256"] for x in m["routes"]} == set(registrations)
assert all(x["serial"]["count"] == x["cold_launcher"]["count"] == 2 and x["c16"]["count"] == 16 for x in m["routes"])
assert all(x["serial"]["p95_ms"] > 50 and x["serial"]["p99_ms"] > 100 and x["c16"]["p99_ms"] > 200 for x in m["routes"])
assert len(block["raw_samples_ms"]) == 12
assert all(k.startswith("INSTALLED_LAUNCHER.") for k in block["raw_samples_ms"])
assert result["original_sample_minima_met"] is False and result["qualification_eligible"] is False
assert m["qualification_complete"] is False
task = next(t for t in read("a5fd-progress-docs/task-status-overlay.json")["tasks"] if t["id"] == "RSP-007")
assert task["original_object_sha256"] == assessment["original_task"]["original_object_sha256"]
assert task["original_acceptance"] == assessment["original_task"]["original_acceptance"]
assert task["parsed_dependency_ids"] == ["RSP-003"] and task["archived_status"] == "OPEN"
out = {
    "schema": "pr2974.rsp007-root-current-acceptance.v1",
    "recorded_at": datetime.now(timezone.utc).isoformat(),
    "source": providers["source"], "source_tree": providers["tree"],
    "task": task["id"], "original_task_object_sha256": task["original_object_sha256"],
    "original_acceptance": task["original_acceptance"], "original_dependencies": task["parsed_dependency_ids"],
    "archived_status": "OPEN", "archived_objects_mutated": False,
    "decision": "DONE", "scope": "installed_launcher_measurement_implementation",
    "remaining_own_scope_clause": None,
    "independent_assessment": {"tree": "9f6cd72414d5078bb48492f80df1c44042da2497", "blob": "247427cf35e1df8acfd32462ea2f50f91ed6f198"},
    "dependency_acceptance": assessment["dependency"],
    "root_source_checks": [
        "All13 provider byte counts, SHA256 and Git blobs matched exact400 and a5fd API trees;12 matched historical be612 bytes and the sole contract-comment change has identical AST.",
        "Read installed adapter installation and independent config argv/env reconstruction; managed registration must be unique, active and lossless.",
        "Read observe_priority_launcher original perf_counter before actual registered-argv invocation through return, including spawn, IO, wait/reap, containment and stdout/exit semantic validation.",
        "Read AdapterSession.observe timer around HTTP _request and reporting/qualification callers: normalized DAEMON_INGRESS and actual INSTALLED_LAUNCHER remain separately named series."
    ],
    "providers": provider_results,
    "retained_actual_evidence": evidence,
    "root_data_checks": {"original_producer_invocations": 1, "parent_rows": 88, "unique_coordinates": 88, "one_process_call_each": True, "zero_exit_nonempty_stdout": 88, "original_allow": 84, "original_deny": 4, "nested_stage_geometry": "all88", "complete_strict_joins": 88, "registration_digests": dict(registrations), "source_installed_driver_before_after_unchanged": True, "existing_independent_full_join_recomputation_reused": True, "workload_rerun": False},
    "limitations": assessment["separate_open_limits"] + [
        "Original record measures instrumented inclusive launcher time; separate internal interpreter/import or Rust CPU phases are unmeasured. Actual startup is included in the outer clock.",
        "RSP007 acceptance does not promote incomplete original latency populations, fresh400 installed results, full descendants/resources, signing or release."
    ]
}
(ROOT / "rsp007-root-current-acceptance.json").write_text(json.dumps(out, indent=2) + "\n")
print(json.dumps({"task": out["task"], "decision": out["decision"], "providers": len(provider_results), "original_rows": 88, "latency_ceilings_still_failed": True, "artifact": identity((ROOT / "rsp007-root-current-acceptance.json").read_bytes())}, indent=2))
