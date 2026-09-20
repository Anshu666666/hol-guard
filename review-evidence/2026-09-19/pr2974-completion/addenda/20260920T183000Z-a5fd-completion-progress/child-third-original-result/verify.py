"""Read only the retained 35526804206 artifact; never run its workload."""

import collections
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def coordinate(row):
    return tuple(row[key] for key in ("harness", "event", "sample", "case"))


def verify():
    raw = ROOT / "raw"
    metadata = json.loads((ROOT / "metadata.json").read_bytes())
    artifact = metadata["artifact"]
    archive = (ROOT / "original.zip").read_bytes()
    assert len(archive) == artifact["size_in_bytes"] == 504203
    assert "sha256:" + hashlib.sha256(archive).hexdigest() == artifact["digest"]
    manifest = json.loads((ROOT / "member-manifest.json").read_bytes())
    assert len(manifest) == 10 and len({row["name"] for row in manifest}) == 10
    with zipfile.ZipFile(ROOT / "original.zip") as packed:
        assert set(packed.namelist()) == {row["name"] for row in manifest}
        for row in manifest:
            body = (raw / row["name"]).read_bytes()
            assert body == packed.read(row["name"])
            assert len(body) == row["bytes"]
            assert hashlib.sha256(body).hexdigest() == row["sha256"]
            assert hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() == row["git_blob"]
    report = json.loads((raw / "observation.json").read_bytes())
    block = report["block"]
    contract = json.loads((raw / "input-contract.json").read_bytes())
    assert contract["observer_source"] == metadata["source"]
    assert contract["observer_tree"] == "0a6e132191d0f7a19ae1080f3f6b498428f33c92"
    cases = ET.parse(raw / "child-controls.xml").getroot().findall(".//testcase")
    identities = [{"classname": row.attrib["classname"], "name": row.attrib["name"]} for row in cases]
    assert len(cases) == 120 and len({tuple(x.values()) for x in identities}) == 120
    assert identities == contract["child_controls"]["ordered_case_identities"]
    assert all(row.find("failure") is row.find("error") is row.find("skipped") is None for row in cases)
    types = json.loads((raw / "child-types.json").read_bytes())["summary"]
    assert types["errorCount"] == 0 and types["warningCount"] == 1156
    assert (raw / "input-before.json").read_bytes() == (raw / "input-after.json").read_bytes()
    for domain in ("source", "driver", "installed"):
        assert report[domain + "_before"] == report[domain + "_after"]
    assert report["driver_before"]["sha"] == metadata["driver"]
    assert report["driver_before"]["tree"] == "23d16a474ca10325e1d0bd99f7da2ba220b8e8cb"
    assert metadata["run_id"] == 35526804206 and metadata["job_id"] == 106120280950
    assert metadata["source"] == "6de1ffd84f345bdf5e44f682b87b83353accf75a"
    assert metadata["driver"] == "fa70591189d2cde3a0d158821ce081a315ac0850"
    assert report["source_before"]["sha"] == "753850955c33eb15f992d1fe7ca375dd26c3a070"
    assert report["source_before"]["tree"] == "341d2c02c79b0c510544df5297600d5a3a47f211"
    bindings = json.loads((raw / "run-source-bindings.json").read_bytes())
    assert len(bindings["files"]) == 44
    assert {row["path"]: row["sha256"] for row in bindings["files"]} == report["source_before"]["files_sha256"]
    assert bindings["source_sha"] == report["source_before"]["sha"]
    checks = [json.loads((raw / name).read_bytes()) for name in ("input-before.json", "input-after.json", "input-controls.json", "input-provision.json")]
    assert all(check["passed"] is True for check in checks)
    assert all(check["binding"] == checks[0]["binding"] for check in checks)
    assert checks[0]["binding"]["driver_sha"] == metadata["driver"]
    assert checks[0]["binding"]["source_sha"] == report["source_before"]["sha"]
    assert block["frame_source_bindings"] == block["frame_source_bindings_after"]
    assert block["subset_invocations"] == 1 and block["subset_completed"] is True
    assert block["measurements"]["preflight_count"] == 8
    assert block["measurements"]["concurrent_count"] == 16
    assert block["measurements"]["concurrent_helper_invocations"] == 1
    parent, daemon, joins = block["parent"], block["daemon"], block["joins"]
    assert len(parent["rows"]) == len(daemon["rows"]) == len(joins["rows"]) == 24
    wanted = collections.Counter(tuple(x[k] for k in ("harness", "event", "sample", "case")) for x in joins["declared_coordinates"])
    for rows in (parent["rows"], daemon["rows"], joins["rows"]):
        actual = collections.Counter(tuple(x["coordinate"][k] for k in ("harness", "event", "sample", "case")) for x in rows)
        assert actual == wanted and len(actual) == 24
    assert joins["observation_complete"] is True and joins["exact_24_population"] is True
    assert joins["original_88_population_complete"] is False
    assert parent["observation_complete"] is True and daemon["observation_complete"] is True
    for row in joins["rows"]:
        assert row["complete"] is True
        assert row["checks"]["native_edge_returned_none"] is False
        assert all(value is True for key, value in row["checks"].items() if key != "native_edge_returned_none")
    allowed = collections.Counter(row["facts"]["original_allowed"] for row in parent["rows"])
    assert allowed == {True: 20, False: 4}
    children = block["children"]
    assert len(children["rows"]) == 24 and children["failures"] == []
    assert children["offered_children"] == 24 and children["unexpected_sidecars"] == 0
    assert children["observation_complete"] is True
    child_coordinates = collections.Counter(coordinate(row["coordinate"]) for row in children["rows"])
    assert child_coordinates == wanted
    parents = {coordinate(row["coordinate"]): row for row in parent["rows"]}
    frame_ids = {row["id"] for row in block["frame_source_bindings"]["frames"]}
    module_ids = {("codex_plugin_scanner." + name.removesuffix(".py").replace("/", ".")).removesuffix(".__init__")
                  for name in block["frame_source_bindings"]["modules"]}
    allowed = frame_ids | {prefix + name for name in module_ids for prefix in ("import:", "module:")} | {"module:dynamic_string_module"}
    statistics = []
    pids = set()
    for wrapped in children["rows"]:
        child = wrapped["report"]
        parent_row = parents[coordinate(wrapped["coordinate"])]
        process = parent_row["facts"]["children"]
        assert len(process) == 1 and process[0]["pid"] == child["pid"]
        assert child["pid"] not in pids
        pids.add(child["pid"])
        assert child["configuration_sha256"] == block["startup_observer"]["configuration_sha256"]
        assert child["isolated_flag"] is (wrapped["coordinate"]["harness"] == "codex")
        body = canonical(child) + b"\n"
        assert len(body) == wrapped["report_bytes"] <= 524288
        assert hashlib.sha256(body).hexdigest() == wrapped["report_sha256"] == wrapped["footer"]["report_sha256"]
        assert wrapped["footer"]["pid"] == child["pid"] and wrapped["source_stage_coverage"] is True
        assert child["observation_complete"] is child["profile_restored"] is child["thread_census_complete"] is True
        assert child["qualification_eligible"] is child["return_events_prove_success"] is False
        assert child["faults"] == []
        assert all(child[key] == 0 for key in ("open_spans", "callbacks_in_flight_at_snapshot", "worker_hooks_not_retired", "current_worker_threads_at_snapshot"))
        assert 0 < child["callback_count"] <= 2000000 and child["callback_ns"] >= 0
        records = child["records"]
        assert len(records) <= 4096
        siblings = {}
        kinds = {}
        durations = collections.defaultdict(list)
        for index, row in enumerate(records):
            assert set(row) == {"index", "stage", "thread", "thread_kind", "parent", "start_ns", "end_ns", "termination"}
            assert type(row["index"]) is int and row["index"] == index and row["stage"] in allowed
            assert type(row["thread"]) is int and 0 <= row["thread"] < 16
            assert row["thread_kind"] in {"main", "worker"}
            assert kinds.setdefault(row["thread"], row["thread_kind"]) == row["thread_kind"]
            assert 0 < row["start_ns"] <= row["end_ns"]
            assert row["termination"] == "profile_return_or_unwind"
            if row["parent"] is not None:
                assert type(row["parent"]) is int and 0 <= row["parent"] < index
                above = records[row["parent"]]
                assert above["thread"] == row["thread"]
                assert above["start_ns"] <= row["start_ns"] <= row["end_ns"] <= above["end_ns"]
            key = row["thread"], row["parent"]
            if key in siblings:
                assert siblings[key] <= row["start_ns"]
            siblings[key] = row["end_ns"]
            durations[row["stage"]].append((row["end_ns"] - row["start_ns"]) / 1000000)
        assert set(kinds) == set(range(len(kinds))) and list(kinds.values()).count("main") == 1
        statistics.append({"coordinate": wrapped["coordinate"], "pid": child["pid"],
            "registered_argv_sha256": child["registered_argv_sha256"], "observed_argv_sha256": child["argv_sha256"],
            "callback_count": child["callback_count"], "callback_body_ms": child["callback_ns"] / 1000000,
            "observer_setup_ms": child["setup_ns"] / 1000000,
            "finish_through_report_export_ms": wrapped["footer"]["finish_through_report_export_ns"] / 1000000,
            "record_count": len(records),
            "stage_inclusive_ms": {key: {"count": len(values), "sum": sum(values), "max": max(values)}
                                   for key, values in sorted(durations.items()) if key != "module:dynamic_string_module"},
            "ambiguous_dynamic_string_records": len(durations["module:dynamic_string_module"])})
    assert len({row["report"]["parent_pid"] for row in children["rows"]}) == 1
    cleanup = {key: block[key] for key in ("observer_cleanup_complete", "private_sidecars_removed", "registered_children_reaped", "fixture_cleanup_returned", "direct_fixture_child_reaped", "fixture_reader_threads_stopped", "authenticated_stop_observed")}
    assert all(value is True for value in cleanup.values())
    assert block["observer_cleanup_faults"] == [] and block["stop_failure_observed"] is False
    assert report["observation_complete"] is block["observation_complete"] is True
    for key in ("qualification_eligible", "original_sample_minima_met"):
        assert report[key] is False
    body = (raw / "observation-daemon.json").read_bytes()
    assert hashlib.sha256(body).hexdigest() == block["daemon_report_original_bytes"]["sha256"]
    assert len(body) == block["daemon_report_original_bytes"]["bytes"]
    assert json.loads(body) == daemon
    invocation = block["interpreter_invocation_preflight"]
    assert invocation["argv0_transform"] == "darwin_framework_argv0"
    assert invocation["all_arguments_after_argv0_exact"] is True
    assert invocation["original_launcher_invoked"] is False
    assert invocation["python"] == [3, 12, 10]
    serial = [row["latency_ms"] for row in block["measurements"]["preflights"]]
    concurrent = block["raw_samples_ms"]["claude_post_c16"]
    assert len(serial) == 8 and len(concurrent) == 16
    return {
        "run_id": 35526804206,
        "job_id": 106120280950,
        "source_commit": metadata["source"],
        "driver_commit": metadata["driver"],
        "artifact": artifact,
        "all_10_original_members_verified": True,
        "untimed_controls": {"passed": 120, "failed": 0, "skipped": 0, "types": types},
        "original_launcher_calls": 24,
        "parent_daemon_native_receipt_joined_calls": 24,
        "allow": 20,
        "deny": 4,
        "child_reports_admitted": 24,
        "child_reports_rejected": 0,
        "observation_complete": True,
        "child_statistics": statistics,
        "actual_framework_representation": invocation,
        "source_driver_installed_before_after_unchanged": True,
        "cleanup": cleanup,
        "instrumented_serial_range_ms": [min(serial), max(serial)],
        "instrumented_concurrent_range_ms": [min(concurrent), max(concurrent)],
        "all_eight_serial_over_100ms": all(value > 100 for value in serial),
        "all_sixteen_concurrent_over_200ms": all(value > 200 for value in concurrent),
        "qualification_eligible": False,
        "limits": [
            "Selected source-bound child intervals are inclusive and instrumented; nested stages cannot be added. Return events alone do not prove product success.",
            "Private config and literal argv were deliberately not exported; this independent reader verifies retained hashes/PID joins and relies on original bound strict reader for private argv/config admission.",
            "Callback body time excludes some dispatch/locking/bookkeeping cost; it must not be subtracted from wall time to estimate clean product latency. Preactivation interpreter/sitecustomize work is unmeasured.",
            "Dynamic string module frames have unresolved origin, not proven registered-command identity. Codex bridge module top-level includes its main execution.",
            "No clean timing comparison, original sample-minimum completion, current-head transfer, release or task promotion.",
            "Receipt evidence is original native/validated-submission linkage; this reader does not reopen hosted SQL.",
            "Cleanup is the recorded owned-process and fixture scope, not all escaped descendants.",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
