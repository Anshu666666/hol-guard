"""Read only the original failed observer artifact; no product imports or runs."""
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).with_name("phase-installed-35515446609")


def pairs(items):
    result = {}
    for key, value in items:
        assert key not in result
        result[key] = value
    return result


def read(name):
    return json.loads((ROOT / name).read_bytes(), object_pairs_hook=pairs)


def verify():
    admission = read("READBACK.json")
    assert admission["complete"] is True
    for row in admission["members"]:
        raw = (ROOT / row["name"]).read_bytes()
        assert len(raw) == row["bytes"]
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]
    archive = (ROOT / "original.zip").read_bytes()
    assert len(archive) == 152541
    assert hashlib.sha256(archive).hexdigest() == "d6801f2d23e31470f20b613807cb2be0902dec670ecc687b6a3731d0f7a537cc"
    before, after = read("input-before.json"), read("input-after.json")
    assert before == after
    report, daemon = read("observation.json"), read("observation-daemon.json")
    block = report["block"]
    assert block["daemon"] == daemon
    for field in ("driver", "source", "installed"):
        assert report[field + "_before"] == report[field + "_after"]
    assert report["source_before"]["sha"] == "50b39d7e7a4722c2773d94da0ea4c2482f055ef5"
    assert report["source_before"]["tree"] == "a0c139c4e02535545c5b0e602c240a38affde5fe"
    assert report["driver_before"]["sha"] == "65aeb291d8dfffbd23a1c80a96baad2403703b08"
    assert report["installed_before"]["native_runtime_sha256"] == "3a59a8cf2c9875e3b8e4c4c79c518ccfea2c4e857405800a0d4d5a2bfbced264"
    assert report["original_thresholds_ms"] == {"c16_p99": 200, "serial_p95": 50, "serial_p99": 100}
    assert report["qualification_eligible"] is report["original_sample_minima_met"] is False
    assert block["producer_invocations"] == 1 and block["producer_completed"] is True
    assert block["measurements"]["contracts_passed"] is True
    parent = block["parent"]
    assert parent["started"] == parent["completed"] == daemon["started"] == daemon["completed"] == 88
    assert parent["capture_faults"] == 0 and daemon["capture_faults"] == 88
    assert parent["observation_complete"] is True and daemon["observation_complete"] is False
    assert report["observation_complete"] is block["observation_complete"] is False
    for side in (parent, daemon):
        assert all(side[key] == 0 for key in ("in_flight", "row_overflow", "stage_overflow", "restore_failures"))
        assert side["tail_complete"] is True
    joins = block["joins"]
    assert joins["observation_complete"] is False and len(joins["rows"]) == 88
    failed = Counter()
    for row in joins["rows"]:
        assert row["complete"] is False
        for name, value in row["checks"].items():
            if value is False and name != "native_edge_returned_none":
                failed[name] += 1
    assert dict(failed) == {"input_unchanged_within_handler": 88, "worker_entry_match": 88}
    equal = [row for row in daemon["rows"] if row["facts"]["exit_projection_sha256"] == row["facts"]["semantic_sha256"]]
    assert len(equal) == 66
    remaining = [row for row in daemon["rows"] if row not in equal]
    assert len(remaining) == 22
    assert all(row["coordinate"]["harness"] == "codex" and row["coordinate"]["event"] == "PreToolUse" and row["facts"]["browser_fields_present"] is True for row in remaining)
    clean_keys = ("authenticated_stop_observed", "direct_fixture_child_reaped", "fixture_cleanup_returned", "fixture_reader_threads_stopped")
    assert all(block[key] is True for key in clean_keys)
    assert block["stop_failure_observed"] is False
    population = Counter((row["coordinate"]["harness"], row["coordinate"]["event"]) for row in parent["rows"])
    assert len(population) == 4 and set(population.values()) == {22}
    assert sum(row["facts"]["original_allowed"] is True for row in parent["rows"]) == 84
    assert sum(row["facts"]["original_allowed"] is False for row in parent["rows"]) == 4
    return {
        "schema": "priority-phase-installed-v2-original-data-verification.v1",
        "run": 35515446609, "job": 106090496910, "artifact": 10606906557,
        "archive_sha256": admission["archive_sha256"],
        "raw_tree": "73f220d045133b6b63f9007935ed0e05eeeb7308",
        "independent_data_checks_passed": True,
        "source_sha": report["source_before"]["sha"],
        "driver_sha": report["driver_before"]["sha"],
        "producer_completed": True, "original_launches": 88, "allow": 84, "deny": 4,
        "failed_observer_checks": dict(failed), "daemon_capture_faults": 88,
        "observation_complete": False, "qualification_eligible": False,
        "original_sample_minima_met": False,
        "original_thresholds_ms": report["original_thresholds_ms"],
        "original_route_measurements": block["measurements"]["routes"],
        "cleanup": {**{key: block[key] for key in clean_keys}, "escaped_descendant_coverage": "not_established"},
        "cause": "The selected handler's original _runtime_hook_remaining_hint consumes top-level guard_remaining_ms. The observer incorrectly required that field again at worker/exit. This is an observer projection failure; the original 88 returned contracts remain distinct.",
        "cause_helper_git_blob": "7f2c92ae9f262ab90737d79d9946e44146dc5bf6",
        "cause_helper_sha256": "b6f0f2c9f3efb4f114d1d8bf49626b862b0fe62e66fd55f6d180e98a11cfc293",
        "cause_peer_tree": "ca3b8b19459689abff1d3db37c19be01c81e85a1",
        "limitations": ["No original operation replayed by this reader.", "Old rows are not retroactively admitted as complete joins.", "Inclusive instrumented phase durations are not causal attribution or a cross-process residual.", "Two serial and sixteen concurrent samples per route are diagnostic, below original qualification minima.", "All four routes' original serial 50/100 and c16 200 ms ceilings remain missed.", "Physical I/O, asynchronous SQLite, child imports and discovery/auth are unmeasured."],
    }


if __name__ == "__main__":
    value = verify()
    destination = ROOT / "VERIFIED-RESULT.json"
    with destination.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"checked": True, "original_launches": value["original_launches"], "observation_complete": False}))
