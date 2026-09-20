"""Reconcile retained original bytes only; import no product or workload."""
import base64
import hashlib
import io
import json
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).parent
A = ROOT / "archive"
MANIFEST = ROOT.parent / "native-workspace-constructor-tail-e440-prep/workspace-constructor-validation/MANIFEST.json"


def read(name):
    return json.loads((A / name).read_text())


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def dump(name, value):
    (ROOT / name).write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n")


archive_record = json.loads((ROOT / "archive-verification.json").read_text())
metadata = json.loads((ROOT / "artifact-metadata.json").read_text())["artifacts"][0]
raw_zip = (ROOT / "artifact.zip").read_bytes()
assert len(raw_zip) == metadata["size_in_bytes"] == archive_record["archive_bytes"]
assert "sha256:" + hashlib.sha256(raw_zip).hexdigest() == metadata["digest"]
with zipfile.ZipFile(io.BytesIO(raw_zip)) as archive:
    assert len(archive.namelist()) == len(set(archive.namelist())) == 41
    assert archive.namelist() == [row["path"] for row in archive_record["members"]]
    for row in archive_record["members"]:
        data = archive.read(row["path"])
        assert identity(data) == {k:row[k] for k in ("bytes", "sha256", "git_blob")}
        assert data == (A / row["path"]).read_bytes()

manifest = json.loads(MANIFEST.read_text())
assert identity(MANIFEST.read_bytes())["git_blob"] == "02ac7ba778506bf360e422831abc07c806e27a1c"
frames = json.loads((ROOT / "frames.json").read_text())
groups = {}
for frame in frames:
    assert frame["kind"] == "part"
    groups.setdefault(frame["path"], []).append(frame)
projected = {}
for name, parts in groups.items():
    assert [p["part"] for p in parts] == list(range(len(parts)))
    assert {p["parts"] for p in parts} == {len(parts)}
    raw = b"".join(base64.b64decode(p["base64"], validate=True) for p in parts)
    info = identity(raw)
    assert all(all(p[k] == info[k] for k in info) for p in parts)
    projected[name] = raw
    target = ROOT / "projection" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
index = json.loads(projected.pop("projection-index.json"))
assert index["unavailable"] == []
assert {row["path"] for row in index["admitted"]} == set(projected)
assert index["total_source_bytes"] == sum(map(len, projected.values()))
for row in index["admitted"]:
    assert {k: row[k] for k in ("bytes", "sha256", "git_blob")} == identity(projected[row["path"]])
for name, raw in projected.items():
    assert (A / name).read_bytes() == raw
dump("projection-verification.json", {"frames": len(frames), "original_files": len(projected),
    "all_hashes_and_archive_bytes_equal": True, "index": index})

result = read("validation-result.json")
invocation = read("original-invocation.json")
report = read("workspace-lifecycle.json")
cell = read("reconstructed-cells.json")[0]
record = read("constructors/00.json")
observation = record["observation"]
admission = read("constructor-admission.json")
assert result["driver_sha"] == "858fb5c6b7daa35c1bab38674e6987a446417962"
assert result["source_sha"] == manifest["source_sha"] == "e44008445630aad28ccc291ec234f55a14892e6d"
assert result["source_tree"] == manifest["source_tree"]
assert result["failure"] is None and result["passed"] is True
assert result["original_command_attempts"] == invocation["original_main_calls"] == 1
assert result["original_exit"] == invocation["original_main_return"] == 1
assert not invocation["original_main_raised"] and invocation["workload_retries"] == 0
assert invocation["counts"] == report["counts"] == [100]
assert invocation["scenarios"] == report["scenarios"] == ["first_admission_fault"]
assert result["original_readiness_ms"] == invocation["original_readiness_ms"] == cell["readiness_deadline_ms"] == 400
assert report["declared_cells_visited"] is True
assert not report["complete_lifecycle_matrix_visited"] and not report["implemented_checks_passed"]
assert result["source_driver_installed_preserved"] is True
for before, after in (("binding-before.json", "binding-after.json"), ("installed-before.json", "installed-after.json")):
    assert (A / before).read_bytes() == (A / after).read_bytes()
bindings = read("binding-before.json")
assert bindings["source_files"] and bindings["files"]
assert bindings["source_files"] == manifest["source_files"]
assert bindings["files"] == manifest["driver_files"]
assert len(bindings["source_files"]) == 25
assert bindings["driver"]["head"] == result["driver_sha"]
assert bindings["driver"]["tree"] == "b4aa07da610c8be9dde2a2b1e0534bee85c0dd42"
assert bindings["driver"]["tracked_status"] == bindings["source"]["tracked_status"] == ""
assert bindings["source"]["head"] == manifest["source_sha"] and bindings["source"]["tree"] == manifest["source_tree"]
for descriptor in manifest["driver_files"]:
    data = (MANIFEST.parent.parent / descriptor["path"]).read_bytes()
    assert identity(data) == {k:descriptor[k] for k in ("bytes", "sha256", "git_blob")}


ledger_raw = (A / "workspace-lifecycle.jsonl").read_bytes()
ledger = [json.loads(row) for row in ledger_raw.splitlines()]
assert len(ledger) == 5 and ledger[0]["kind"] == "lifecycle_cell_offer"
parts = ledger[1:]
assert [x["part"] for x in parts] == list(range(4)) and {x["parts"] for x in parts} == {4}
encoded = "".join(x["content"] for x in parts).encode()
assert {x["result_sha256"] for x in parts} == {hashlib.sha256(encoded).hexdigest()}
decoded = json.loads(encoded)
assert {**decoded["summary"], **decoded["proof"]} == cell
assert decoded["summary"] == {k: v for k, v in report["cells"][0].items() if k != "evidence"}
assert report["ledger"]["sha256"] == hashlib.sha256(ledger_raw).hexdigest()

controls = read("reader-controls-result.json")
cases = list(ET.parse(A / "reader-controls.xml").getroot().iter("testcase"))
nodes = [c.attrib["classname"].replace(".", "/") + ".py::" + c.attrib["name"] for c in cases]
assert len(nodes) == len(set(nodes)) == 109
assert not any(list(c.iter(tag)) for c in cases for tag in ("failure", "error", "skipped"))
assert nodes == controls["collected"] == controls["executed"] == manifest["expected_reader_nodes"]
assert controls["passed"] == 109 and controls["skipped"] == 0
types_summary = (A / "commands/types.stdout").read_text().splitlines()[-1]
assert types_summary == "0 errors, 1131 warnings, 0 notes"
for command in result["commands"]:
    for stream in ("stdout", "stderr"):
        info = identity((A / "commands" / (command["name"] + "." + stream)).read_bytes())
        assert command[stream] == {k: info[k] for k in ("bytes", "sha256")}
    assert not command["timed_out"] and command["direct_child_exited"]
    assert command["returncode"] == (1 if command["name"] == "original-first-admission" else 0)

wheel = A / manifest["retained_wheel"]["wheel_name"]
assert {k: identity(wheel.read_bytes())[k] for k in ("bytes", "sha256")} == manifest["retained_wheel"]["wheel_identity"]
expected = read("expected-installed.json")
with zipfile.ZipFile(wheel) as z:
    for name, info in expected["package_entries"].items():
        actual = identity(z.read(name))
        assert {k: actual[k] for k in ("bytes", "sha256")} == info
    runtime = identity(z.read("codex_plugin_scanner/_native/hol-guard-runtime"))
    runtime_manifest = json.loads(z.read("codex_plugin_scanner/_native/runtime-manifest.json"))
assert runtime_manifest == manifest["retained_wheel"]["runtime_manifest"]
assert {k: runtime[k] for k in ("bytes", "sha256")} == manifest["retained_wheel"]["runtime_identity"]
assert read("installed-before.json")["runtime"] == runtime_manifest

assert admission["diagnostic_complete"] and not admission["original_all_selected_passed"]
assert observation["observation_complete"] and not observation["lost"] and not observation["overflow"]
assert observation["active_calls"] == 0
assert observation["factory_handoffs"] == observation["acceptance_calls"] == observation["replacement_calls"] == 1
assert all(record[k] is True for k in ("hooks_restored", "dispatch_patch_restored", "original_result_or_exception_preserved"))
assert record["original_dispatch_calls"] == record["matching_dispatch_calls"] == 1
assert cell["publisher_contained"] and not cell["passed"] and "requests" not in cell
assert cell["failure"]["origin"] == "native_slo_workspace_lifecycle.await_ack" and cell["failure"]["line"] == 73
assert cell["receipt_witness"]["native_receipts"] == cell["receipt_witness"]["committed"] == 0
fault = cell["fault"]
assert fault["real_client_calls"] == 2 and fault["successful_ack_fabricated"] is False
assert all(fault[k] is True for k in ("first_error_withheld_ack", "production_ack_error_observed", "real_accepted_reply_discarded", "subsequent_transport_forwarded"))
rows = observation["rows"]
stages = ["service_constructor", "http_constructor", "request_services", "hook_worker_constructor", "publisher_wait"]
assert [r["stage"] for r in rows] == stages
assert [r["parent"] for r in rows] == [None, 0, 1, 2, 3]
assert [r["returned"] for r in rows] == ["none"] * 4 + ["true"]
assert all(r["outcome"] == "return" and r["error"] is None for r in rows)
origin, accepted = observation["origin_monotonic"], observation["accepted_monotonic"]
offset = accepted - origin
return_ms = {r["stage"]: (r["exit_seconds"] - offset) * 1000 for r in rows}
tails = {"worker_after_wait": (rows[3]["exit_seconds"] - rows[4]["exit_seconds"]) * 1000,
         "services_after_worker": (rows[2]["exit_seconds"] - rows[3]["exit_seconds"]) * 1000,
         "http_after_services": (rows[1]["exit_seconds"] - rows[2]["exit_seconds"]) * 1000,
         "service_after_http": (rows[0]["exit_seconds"] - rows[1]["exit_seconds"]) * 1000}
assert return_ms == admission["original_cells"][0]["acceptance_to_successful_returns_ms"]
assert tails == admission["original_cells"][0]["matched_exit_regions_ms"]
assert return_ms["hook_worker_constructor"] < 400 < return_ms["request_services"]
tail_rows = observation["tail_rows"]
assert observation["schema"] == "hol-guard.workspace-constructor-phases.v2"
assert observation["active_tail_calls"] == 0
assert [r["stage"] for r in tail_rows] == ["authority_read", "general_executor", "control_executor"]
assert [r["parent"] for r in tail_rows] == [2, 2, 2]
assert [r["workers"] for r in tail_rows] == [None, 32, 8]
assert [r["queue_limit"] for r in tail_rows] == [None, 128, 128]
assert [r["returned"] for r in tail_rows] == ["opaque", "none", "none"]
assert all(r["outcome"] == "return" and r["error"] is None for r in tail_rows)
assert rows[3]["exit_seconds"] <= tail_rows[0]["entry_seconds"] <= tail_rows[0]["exit_seconds"] <= tail_rows[1]["entry_seconds"] <= tail_rows[1]["exit_seconds"] <= tail_rows[2]["entry_seconds"] <= tail_rows[2]["exit_seconds"] <= rows[2]["exit_seconds"]
tail_spans = {r["stage"]:(r["exit_seconds"]-r["entry_seconds"])*1000 for r in tail_rows}
tail_gaps = {
 "worker_return_to_authority_entry": (tail_rows[0]["entry_seconds"]-rows[3]["exit_seconds"])*1000,
 "authority_return_to_general_entry": (tail_rows[1]["entry_seconds"]-tail_rows[0]["exit_seconds"])*1000,
 "general_return_to_control_entry": (tail_rows[2]["entry_seconds"]-tail_rows[1]["exit_seconds"])*1000,
 "control_return_to_services_return": (rows[2]["exit_seconds"]-tail_rows[2]["exit_seconds"])*1000,
}
assert admission["original_cells"][0]["tail_inclusive_spans_ms"] == tail_spans
assert admission["original_cells"][0]["matched_tail_gaps_ms"] == tail_gaps
assert admission["original_cells"][0]["all_three_tail_returned"] is True
publication = [{k: r[k] for k in ("kind", "publication", "finished_ms")}
               | {"acceptance_relative_finished_ms": r["finished_ms"] - cell["accepted_ms"]}
               | {k: r[k] for k in ("ready", "validated") if k in r}
               for r in cell["publication_rows"] if r["kind"] in ("transport_ack", "barrier")]
summary = {"schema": "hol-guard.constructor-terminal-review.v1", "run": 35536922548, "job": 106147493587,
    "driver": result["driver_sha"], "source": result["source_sha"], "source_tree": result["source_tree"],
    "archive": json.loads((ROOT / "archive-verification.json").read_text()), "log": identity((ROOT / "job.log").read_bytes()),
    "projection": {"frames": len(frames), "original_files": len(projected), "all_archive_joins": True},
    "controls": {"passed": 109, "skipped": 0, "exact_ordered_nodes": True, "types": types_summary},
    "source_driver_installed_before_after_equal": True, "wheel": identity(wheel.read_bytes()), "runtime": runtime,
    "actual_build_identity": runtime_manifest, "verified_package_entries": len(expected["package_entries"]),
    "original_result": {"calls": 1, "scenario": "first_admission_fault", "workspaces": 100, "readiness_ms": 400,
        "exit": 1, "passed": False, "fault": fault, "failure": cell["failure"], "recovered_requests_offered": 0,
        "native_receipts": 0, "committed_receipts": 0, "publisher_contained": True},
    "diagnostic_complete": True, "constructor_phases": {"accepted_monotonic": accepted, "origin_monotonic": origin,
        "acceptance_to_successful_returns_ms": return_ms, "matched_exit_regions_ms": tails,
        "all_five_returned": True, "publisher_wait_returned": True, "rows": rows, "tail_rows": tail_rows, "tail_inclusive_spans_ms": tail_spans, "matched_tail_gaps_ms": tail_gaps},
    "publication_observations": publication, "lifecycle_clocks": cell["lifecycle_clocks"],
    "limits": ["Original first-admission still fails; diagnostic admission is a separate result.",
        "Actual three tail spans are inclusive wall intervals with observer/scheduling overhead; authority-read internals and CPU/Rust/SQLite leaf costs are not proven. No historical run cause is inferred.",
        "Publication timestamps are observed states/transport returns, not exact commit instants. Publication and constructor/lifecycle origins remain separate.",
        "Recovered daemon start and recovered request were not reached; zero receipts do not imply SQLite loss.",
        "Full15-cell matrix, headline timing, all-platform performance and qualification remain false. No retry beyond this one authorized successor or budget change."],
    "source_providers_verified": 25, "original_installed_runtime_matches_cell_flag": cell["installed_runtime_matches"],
    "qualification_complete": False, "full_matrix_passed": False, "headline_timing_eligible": False}
dump("VERIFIED-RESULT.json", summary)
print(json.dumps({"verified": True, "members": len(summary["archive"]["members"]), "projection": len(projected),
    "controls": len(nodes), "diagnostic_complete": True, "original_passed": False, "tails_ms": tails}))
