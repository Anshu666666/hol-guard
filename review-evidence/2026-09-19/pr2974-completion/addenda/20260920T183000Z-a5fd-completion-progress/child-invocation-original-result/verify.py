"""Read only the retained 35525153035 artifact; never run its workload."""

import collections
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parent


def verify():
    raw = ROOT / "raw"
    metadata = json.loads((ROOT / "metadata.json").read_bytes())
    artifact = metadata["artifact"]
    archive = (ROOT / "original.zip").read_bytes()
    assert len(archive) == artifact["size_in_bytes"] == 244094
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
    assert contract["observer_source"] == metadata["source_commit"]
    assert contract["observer_tree"] == metadata["source_tree"]
    cases = ET.parse(raw / "child-controls.xml").getroot().findall(".//testcase")
    identities = [{"classname": row.attrib["classname"], "name": row.attrib["name"]} for row in cases]
    assert len(cases) == 105 and len({tuple(x.values()) for x in identities}) == 105
    assert identities == contract["child_controls"]["ordered_case_identities"]
    assert all(row.find("failure") is row.find("error") is row.find("skipped") is None for row in cases)
    types = json.loads((raw / "child-types.json").read_bytes())["summary"]
    assert types["errorCount"] == 0 and types["warningCount"] == 1024
    assert (raw / "input-before.json").read_bytes() == (raw / "input-after.json").read_bytes()
    for domain in ("source", "driver", "installed"):
        assert report[domain + "_before"] == report[domain + "_after"]
    assert report["driver_before"]["sha"] == metadata["driver_commit"]
    assert report["driver_before"]["tree"] == metadata["driver_tree"]
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
    assert children["rows"] == [] and len(children["failures"]) == 24
    assert children["offered_children"] == 24 and children["unexpected_sidecars"] == 0
    assert all(row["category"] == "child_evidence_rejected" for row in children["failures"])
    assert children["observation_complete"] is False
    assert {row["pid"] for row in children["failures"]} == {row["facts"]["children"][0]["pid"] for row in parent["rows"]}
    cleanup = {key: block[key] for key in ("observer_cleanup_complete", "private_sidecars_removed", "registered_children_reaped", "fixture_cleanup_returned", "direct_fixture_child_reaped", "fixture_reader_threads_stopped", "authenticated_stop_observed")}
    assert all(value is True for value in cleanup.values())
    assert block["observer_cleanup_faults"] == [] and block["stop_failure_observed"] is False
    for key in ("qualification_eligible", "original_sample_minima_met", "observation_complete"):
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
        "run_id": 35525153035,
        "job_id": 106115905003,
        "source_commit": metadata["source_commit"],
        "driver_commit": metadata["driver_commit"],
        "artifact": artifact,
        "all_10_original_members_verified": True,
        "untimed_controls": {"passed": 105, "failed": 0, "skipped": 0, "types": types},
        "original_launcher_calls": 24,
        "parent_daemon_native_receipt_joined_calls": 24,
        "allow": 20,
        "deny": 4,
        "child_reports_admitted": 0,
        "child_reports_rejected": 24,
        "observation_complete": False,
        "actual_framework_representation": invocation,
        "source_driver_installed_before_after_unchanged": True,
        "cleanup": cleanup,
        "instrumented_serial_range_ms": [min(serial), max(serial)],
        "instrumented_concurrent_range_ms": [min(concurrent), max(concurrent)],
        "all_eight_serial_over_100ms": all(value > 100 for value in serial),
        "all_sixteen_concurrent_over_200ms": all(value > 200 for value in concurrent),
        "qualification_eligible": False,
        "limits": [
            "No child phase interval was admitted; startup/import/auth/HTTP attribution remains unavailable.",
            "Child rejection categories do not preserve individual refusal leaves or sidecar presence. Private sidecars were removed after cleanup; raw reports and footers are absent from the artifact.",
            "Complete parent/daemon joins do not retroactively admit rejected child reports.",
            "No clean timing comparison, original sample-minimum completion, current-head transfer, release or task promotion.",
            "Receipt evidence is original native/validated-submission linkage; this reader does not reopen hosted SQL.",
            "Cleanup is the recorded owned-process and fixture scope, not all escaped descendants.",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
