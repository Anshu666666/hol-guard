"""Run one original native fixture and six separately counted Python cases."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import traceback

from common import CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, sha256, write_json
from finite_controls import admitted, junit, read_capture, reconcile
from native_unit_protocol import decode_record, original_log, scan_evidence
from rust_environment import file_record

MARKER = b"HOL_GUARD_NONCOMMAND_RECEIPTS="
CASE_NAMES = ["network", "network_url", "ollama", "read", "mcp", "mcp_command"]


def admit_producer(raw: bytes, specification: dict, evidence: dict) -> dict:
    assert 0 < len(raw) < 1_000_000 and raw.endswith(b"\n")
    assert b"\r" not in raw and b"\x1b" not in raw
    original_three, three = scan_evidence(raw, evidence)
    assert three["complete"] is True and three["record_count"] == 3
    lines = raw.splitlines()
    assert lines[:2] == [b"", b"running 1 test"]
    expected_prefix = ("test " + specification["producer_test"] + " ... ").encode("ascii")
    evidence_tag = evidence["tag"].encode("ascii")
    assert len(lines) == 10 and lines[2].startswith(expected_prefix + evidence_tag)
    assert all(lines[index].startswith(evidence_tag) for index in (3, 4))
    assert lines[5].startswith(MARKER) and raw.count(MARKER) == 1
    assert lines[6:8] == [b"ok", b""]
    summary = re.fullmatch(
        rb"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
        rb"([0-9]+) filtered out; finished in ([0-9]+\.[0-9]+)s", lines[8],
    )
    assert summary is not None and lines[9] == b""
    payload = lines[5][len(MARKER):]
    assert 0 < len(payload) <= 6 * 65536
    # Strict duplicate-field and nonfinite rejection is shared with the main
    # three-record protocol; wrapping admits this one original JSON array.
    values = decode_record(b'{"cases":' + payload + b"}")["cases"]
    assert type(values) is list and [row["case"] for row in values] == CASE_NAMES
    for row in values:
        assert set(row) == {"case", "edge", "payload", "source", "snapshot"}
        assert all(type(row[key]) is dict for key in ("edge", "payload", "source", "snapshot"))
        assert row["edge"]["authority"] == "rust"
    selected = {row["case"]: row for row in values}
    for record_raw, name in zip(original_three.splitlines(), ("network_url", "read", "mcp"), strict=True):
        record = decode_record(record_raw)
        case = selected[name]
        assert decode_record(record["edge_json"].encode("utf-8")) == case["edge"]
        assert record["envelope"]["raw_payload"] == case["payload"]
        assert record["envelope"]["source"] == case["source"]
        assert all(record["active_snapshot"][key] == value for key, value in case["snapshot"].items())
    path = REPORT / "native-fixture-six-cases.original.json"
    assert not path.exists() and not path.is_symlink()
    path.write_bytes(payload + b"\n")
    assert path.read_bytes() == payload + b"\n"
    return {
        "native_test_entries_passed": 1, "producer_case_count": 6,
        "case_names": CASE_NAMES, "payload_path": path.name,
        "payload_bytes": len(payload) + 1, "payload_sha256": sha256(payload + b"\n"),
        "three_record_crosscheck": three, "filtered_out": int(summary[1]),
        "libtest_elapsed_seconds": summary[2].decode("ascii"), "passed": True,
    }


def run_native_fixture(run: Run, env: dict[str, str], primary: Path, units: dict) -> dict:
    expected = CONFIG["native_fixture_cohort"]
    state = {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "native_producer_entries_planned": 1, "python_cases_planned": 6,
        "python_phases_planned": 18, "producer_attempted": False,
        "collection_attempted": False, "python_body_attempted": False,
        "passed": False, "errors": [], "qualification_complete": False,
        "main24_or_three_consumer_credit": False, "installed_qualification": False,
    }
    output = REPORT / "native-fixture-admission.json"
    write_json(output, state)
    binary = None
    try:
        assert __debug__ and units["passed"] is True and units["errors"] == []
        specification = CONFIG["native_fixture"]
        assert specification["producer_timeout_seconds"] == expected["timeout"] == 60
        assert expected["name"] == "native-fixture" and expected["expected_cases"] == 6
        assert "HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE" not in env
        assert "HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE_LOG" not in env
        plan = json.loads((HERE / "native-unit-plan.json").read_bytes())
        assert sha256((HERE / "native-unit-plan.json").read_bytes()) == CONFIG["native_unit_plan_sha256"]
        assert specification["producer_test"] == plan["evidence"]["emitting_test"]
        binary = units["binaries"]["runtime"]["retained_binary"]
        executable = Path(binary["path"])
        assert file_record(executable) == binary
        state["retained_unit_binary"] = binary
        producer_env = dict(env)
        producer_env["HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE"] = "1"
        state["producer_attempted"] = True
        write_json(output, state)
        name = "native-single-producer-fixture"
        passed = run.command(name, [
            str(executable), specification["producer_test"], "--exact",
            "--format", "pretty", "--color", "never", "--test-threads=1", "--nocapture",
        ], cwd=SCRATCH, timeout=60, env=producer_env)
        raw, log = original_log(name, run.steps)
        state["original_producer_command"] = log
        state["producer_command_passed"] = passed
        write_json(output, state)
        run.require(passed, "Original native fixture producer or owned cleanup failed")
        state["producer"] = admit_producer(raw, specification, plan["evidence"])
        gate = REPORT / "native-unit-gate.json"
        bridge = {
            "schema": "pr2974.native-producer-fixture-bridge.v1",
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "producer_test": specification["producer_test"],
            "native_test_entries_passed": 1, "producer_case_count": 6,
            "producer_command_passed": True, "retained_unit_binary": binary,
            "native_unit_gate": {"path": gate.name, "bytes": gate.stat().st_size,
                                 "sha256": sha256(gate.read_bytes())},
            "producer_log": {"path": log["path"], "bytes": log["bytes"], "sha256": log["sha256"]},
            "producer_admission": state["producer"], "qualification_complete": False,
        }
        bridge_path = REPORT / "native-fixture-bridge.json"
        assert not bridge_path.exists() and not bridge_path.is_symlink()
        write_json(bridge_path, bridge)
        fixture_env = dict(env)
        fixture_env.update(
            VALIDATION_NATIVE_FIXTURE_BRIDGE=str(bridge_path),
            VALIDATION_NATIVE_FIXTURE_BRIDGE_SHA256=sha256(bridge_path.read_bytes()),
            HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE_LOG=str(REPORT / log["path"]),
        )
        temporary = Path(env["VALIDATION_TEST_TMP"]).resolve(strict=True)
        directory = REPORT / "controls" / "native-fixture"
        directory.mkdir(parents=True, exist_ok=False)
        collect, execute = directory / "collect.json", directory / "run.json"
        arguments = [str(primary), "-I", "-B", str(HERE / "collect_controls.py"),
                     "--cohort", "native-fixture"]
        state["collection_attempted"] = True
        write_json(output, state)
        passed = run.command("native-fixture-python-collect", [
            *arguments, "--mode", "collect", "--output", str(collect),
            "--basetemp", str(temporary / "native-fixture-collect"),
        ], cwd=SOURCE, timeout=60, env=fixture_env)
        prior = read_capture(collect)
        admitted(prior, expected, "collect")
        _, cases = junit(collect.with_suffix(".xml"))
        assert cases == []
        run.require(passed, "Original native fixture Python collection failed")
        state["python_body_attempted"] = True
        write_json(output, state)
        passed = run.command("native-fixture-python-run", [
            *arguments, "--mode", "run", "--output", str(execute),
            "--basetemp", str(temporary / "native-fixture-run"), "--prior", str(collect),
        ], cwd=SOURCE, timeout=60, env=fixture_env)
        actual = read_capture(execute)
        state["reconciliation"] = reconcile(prior, actual, expected, execute.with_suffix(".xml"))
        run.require(passed, "Original native fixture Python bodies or owned cleanup failed")
        assert state["reconciliation"]["cases_passed"] == 6
        assert state["reconciliation"]["phases_passed"] == 18
        state["passed"] = True
    except BaseException:
        state["errors"].append({"scope": "native_fixture", "traceback": traceback.format_exc()})
        raise
    finally:
        pending = sys.exc_info()[0] is not None
        if binary is not None:
            try:
                assert file_record(Path(binary["path"])) == binary
                state["retained_binary_unchanged"] = True
            except BaseException:
                state["errors"].append({"scope": "native_fixture_binary_final",
                                        "traceback": traceback.format_exc()})
        state["passed"] = state["passed"] and not state["errors"]
        write_json(output, state)
        if not pending:
            run.require(state["passed"], "Original fixture gate or final identity did not pass")
    return state
