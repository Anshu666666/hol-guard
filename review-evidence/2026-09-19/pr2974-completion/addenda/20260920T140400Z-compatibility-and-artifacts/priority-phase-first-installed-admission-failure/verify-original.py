"""Verify the first installed attempt's retained data without executing source."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "phase-installed-35514338927-read2"
def pairs(rows):
    result = {}
    for key, value in rows:
        assert key not in result
        result[key] = value
    return result
def read(name):
    return json.loads((ROOT / name).read_bytes(), object_pairs_hook=pairs)
def digest(raw):
    return hashlib.sha256(raw).hexdigest()

receipt = read("READBACK.json")
assert receipt["complete"] and receipt["archive_bytes"] == 19655
assert digest((ROOT / "original.zip").read_bytes()) == receipt["archive_sha256"]
for row in receipt["members"]:
    raw = (ROOT / row["name"]).read_bytes()
    assert len(raw) == row["bytes"] and digest(raw) == row["sha256"]
before, after = read("input-before.json"), read("input-after.json")
assert before == after and before["passed"] is True
observation = read("observation.json")
assert observation["driver_before"] == observation["driver_after"]
assert observation["source_before"] == observation["source_after"]
assert observation["installed_before"] == observation["installed_after"]
assert observation["driver_before"]["sha"] == "ecdab397f256f857e6e1d1d6dba2cbfe2206ba8c"
assert observation["source_before"]["sha"] == "50b39d7e7a4722c2773d94da0ea4c2482f055ef5"
assert observation["installed_before"]["native_build_sha"] == observation["source_before"]["sha"]
block = observation["block"]
assert block["producer_invocations"] == 1 and block["producer_completed"] is False
assert block["parent"]["rows"] == block["daemon"]["rows"] == block["joins"]["rows"] == []
assert block["parent"]["started"] == block["daemon"]["started"] == 0
assert block["fixture_redirect_count"] == block["daemon"]["session_attachments"] == 1
assert block["daemon"] == read("observation-daemon.json")
failure = block["original_failure"]
message = "The Codex hook interpreter is writable by another user; repair the installation."
assert failure == {"kind":"runtime_error", "message_bytes":len(message.encode()), "message_sha256":digest(message.encode())}
assert block["fixture_cleanup_returned"] and block["direct_fixture_child_reaped"]
assert block["fixture_reader_threads_stopped"] and block["authenticated_stop_observed"]
assert not block["stop_failure_observed"] and not observation["observation_complete"]
assert not observation["qualification_eligible"] and not observation["original_sample_minima_met"]
assert observation["original_thresholds_ms"] == {"serial_p95":50,"serial_p99":100,"c16_p99":200}
result = {
    "schema":"priority-phase-first-installed-admission-result.v1",
    "run":35514338927,"job":106087617259,"artifact":10606616064,
    "driver":"ecdab397f256f857e6e1d1d6dba2cbfe2206ba8c",
    "source_build":"50b39d7e7a4722c2773d94da0ea4c2482f055ef5",
    "equal_tree_product":"124472b8949805e0dd36052df6894b335d8b519d",
    "archive":receipt,"before_after_equal":True,"producer_invocations":1,
    "producer_completed":False,"actual_launcher_rows":0,"daemon_rows":0,
    "failure":failure,"source_message_match":message,
    "source_match_scope":"Exact length/SHA match to source-defined interpreter integrity message; raw exception class, stack and host file mode/owner were not retained by this observer.",
    "cleanup":{"authenticated_stop_observed":True,"direct_fixture_child_reaped":True,"reader_threads_stopped":True,"escaped_descendant_certificate":False},
    "latency_population_available":False,"qualification_eligible":False,
    "first_download_reader_failure":"Closed exec stdin produced empty reference/ValueError before network bytes. Preserved separate receipt; bounded data-only read2 succeeded. No source workload was retried.",
    "original_scope":"One original producer invocation failed before its first launcher; no88 timing samples or performance attribution."
}
with (ROOT / "VERIFIED-RESULT.json").open("x") as stream:
    json.dump(result, stream, indent=2)
    stream.write("\n")
print(json.dumps({"verified":True,"rows":0,"producer_invocations":1,"matched_source_message":message}))
