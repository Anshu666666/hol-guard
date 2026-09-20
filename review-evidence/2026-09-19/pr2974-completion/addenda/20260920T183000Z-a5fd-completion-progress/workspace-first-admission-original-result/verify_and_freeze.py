"""Read only the already-retained original result; execute no producer."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).parent
A = ROOT / "archive"

def read(name):
    return json.loads((A / name).read_text())

def identity(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + bytes([0]) + raw).hexdigest()}

def dump(name, value):
    (ROOT / name).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")

result = read("validation-result.json")
original = read("original-invocation.json")
report = read("workspace-lifecycle.json")
cells = read("reconstructed-cells.json")
assert len(cells) == 1 and cells[0]["scenario"] == "first_admission_fault"
cell = cells[0]
ledger_bytes = (A / "workspace-lifecycle.jsonl").read_bytes()
ledger = [json.loads(row) for row in ledger_bytes.splitlines()]
assert len(ledger) == 5 and ledger[0]["kind"] == "lifecycle_cell_offer"
parts = ledger[1:]
assert [x["part"] for x in parts] == list(range(4))
encoded = "".join(x["content"] for x in parts).encode()
assert {x["parts"] for x in parts} == {4}
assert {x["result_sha256"] for x in parts} == {hashlib.sha256(encoded).hexdigest()}
decoded = json.loads(encoded)
assert {**decoded["summary"], **decoded["proof"]} == cell
assert decoded["summary"] == {k:v for k,v in report["cells"][0].items() if k != "evidence"}
assert report["ledger"]["sha256"] == hashlib.sha256(ledger_bytes).hexdigest()
controls = read("reader-controls-result.json")
nodes = ET.parse(A / "reader-controls.xml").getroot().findall(".//testcase")
junit = [x.attrib["classname"].replace(".", "/") + ".py::" + x.attrib["name"] for x in nodes]
assert len(nodes) == len(set(junit)) == 110
assert not any(x.find(tag) is not None for x in nodes for tag in ("failure", "error", "skipped"))
assert junit == controls["collected"] == controls["executed"]
assert controls["passed"] == 110 and controls["skipped"] == 0
assert result["original_command_attempts"] == original["original_main_calls"] == 1
assert original["scenarios"] == ["first_admission_fault"] and original["counts"] == [100]
assert result["original_exit"] == original["original_main_return"] == 1
assert result["original_readiness_ms"] == original["original_readiness_ms"] == 400
assert result["source_driver_installed_preserved"] is True
assert (A / "binding-before.json").read_bytes() == (A / "binding-after.json").read_bytes()
assert (A / "installed-before.json").read_bytes() == (A / "installed-after.json").read_bytes()
assert not result["passed"] and not report["implemented_checks_passed"]
assert not report["complete_lifecycle_matrix_visited"]
assert read("original-invocation.json")["workload_retries"] == 0
assert (A / "commands/types.stdout").read_text().splitlines()[-1] == "0 errors, 1333 warnings, 0 notes"
record = read("predicates/00.json")
observation = record["observation"]
rows = observation["rows"]
assert len(rows) == 272 and [x["id"] for x in rows] == list(range(272))
assert observation["lost"] is True and observation["observation_complete"] is False
assert not observation["overflow"] and observation["active_calls"] == 0
assert not any(x.get("site") == "unknown" for x in rows)
missing = [(x["id"], key) for x in rows for key in ("before", "after") if key in x and x[key] is None]
assert missing == [(245, "before"), (246, "before")]
assert rows[245]["stage"] == "request_publish" and rows[246]["stage"] == "wait_ready"
assert rows[244]["original_monotonic"] + .4 == rows[257]["arguments"]["deadline"]
assert rows[269]["original_monotonic"] > rows[257]["arguments"]["deadline"]
assert rows[268]["returned"]["kind"] == "dict" and rows[267]["returned"] == {"kind":"bool", "value":True}
fault = cell["fault"]
assert fault["real_client_calls"] == 2
assert all(fault[k] is True for k in ("first_error_withheld_ack", "production_ack_error_observed", "real_accepted_reply_discarded", "subsequent_transport_forwarded"))
assert fault["successful_ack_fabricated"] is False
assert cell["publisher_contained"] is True and not cell["secondary_workspace_probed"]
assert cell["receipt_witness"]["native_receipts"] == cell["receipt_witness"]["committed"] == 0
clocks = cell["lifecycle_clocks"]["boundaries_ms"]
archive = json.loads((ROOT / "archive-verification.json").read_text())
summary = {
    "schema":"hol-guard.first-admission-original-result-review.v1",
    "run":35527492687, "job":106122101381, "driver":"177036f13e60e8d0f7d4b2ef46b641b86868a179",
    "driver_tree":"3ed0c8ff1cfdf5f599239cf89b5ba540bc0642d2", "sole_parent_and_source":"e44008445630aad28ccc291ec234f55a14892e6d",
    "archive":archive, "log":identity(ROOT / "job.log"),
    "original_controls":{"passed":110,"skipped":0,"exact_ordered_junit_collection_join":True,"types_errors":0,"types_warnings":1333},
    "original_result":{"scenario":"first_admission_fault","workspaces":100,"readiness_ms":400,"calls":1,"exit":1,"passed":False,"fault":fault,"failure":cell["failure"],"recovered_requests":0,"observed_native_receipts":0,"committed_receipts":0,"publisher_contained":True},
    "capture":{"rows":272,"unknown_sites":0,"missing_states":[{"id":245,"side":"before","stage":"request_publish"},{"id":246,"side":"before","stage":"wait_ready"}],"lost":True,"overflow":False,"active":0,"admitted":False,"original_refusal":"observation_incomplete"},
    "clocks":{"origins_remain_distinct":True,"lifecycle":clocks,"accepted_absolute":rows[244]["original_monotonic"],"original_deadline_absolute":rows[257]["arguments"]["deadline"],"final_original_clock_absolute":rows[269]["original_monotonic"],"final_clock_late_ms":(rows[269]["original_monotonic"]-rows[257]["arguments"]["deadline"])*1000,"constructor_return_after_acceptance_lower_bound_ms":clocks["server_constructor_return"]-clocks["cold_registrations_return"],"recovered_await_entry_after_acceptance_lower_bound_ms":clocks["recovered_ack_enter"]-clocks["cold_registrations_return"]},
    "source_driver_installed_before_after_equal":True,"full_matrix_passed":False,"headline_timing_eligible":False,"qualification_complete":False,
    "limits":["Lost predicate state samples prevent complete-capture admission; no retrospective repair.","Original fault and publication rows remain original finite evidence, not a full strict current receipt success.","Publication barrier timestamps are observation times, not exact internal commit instants.","Constructor and wait spans are inclusive Python observations and do not isolate native CPU or transport cause.","Full daemon.start and recovered request were not reached; no SQL persistence loss inferred from zero offered recovered requests.","No original workload replay, extra native probe, or changed deadline was performed."]
}
dump("VERIFIED-RESULT.json", summary)
dump("SELECTED-ORIGINAL-ROWS.json", {"selection_scope":"finite original rows; not complete capture admission", "rows":[rows[i] for i in [37,244,245,246,257,267,268,269,270,271]],"cell":cell})
print(json.dumps({"verified":True,"controls":110,"rows":272,"archive_members":len(archive["members"]),"late_ms":summary["clocks"]["final_clock_late_ms"]}))
