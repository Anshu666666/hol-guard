"""Run fresh native-control collections and reconcile every actual body outcome."""

from __future__ import annotations

import hashlib
import os
import sys
import traceback
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from common import CONFIG, REPORT, SCRATCH, SOURCE, command, write_json  # noqa: E402
from control_capture_evidence import read_capture_file  # noqa: E402


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def selection_matches(node: str, selector: str) -> bool:
    if "::" not in selector:
        return node.startswith(selector + "::")
    return node == selector or ("[" not in selector and node.startswith(selector + "["))


def read_capture(path: Path) -> dict:
    return read_capture_file(path)


def admitted(value: dict, expected: dict, mode: str) -> list[dict]:
    assert value["mode"] == mode and value["cohort"] == expected["name"]
    assert value["capture_retention"]["complete"] is True
    assert value["source_sha"] == CONFIG["source_sha"] and value["source_tree"] == CONFIG["source_tree"]
    assert value["pytest_exit_code"] == 0 and value["error"] is None and value["evidence_error"] is None
    assert value["source_unchanged"] is value["binary_unchanged"] is value["collection_admitted"] is True
    assert value["qualification_complete"] is False
    contract = value["contract"]
    assert contract["selectors"] == expected["selectors"] and contract["cohort"] == expected["name"]
    assert contract["source_sha"] == CONFIG["source_sha"] and contract["source_tree"] == CONFIG["source_tree"]
    items = contract["collection"]
    nodes = [row["nodeid"] for row in items]
    assert len(nodes) == len(set(nodes)) == expected["expected_cases"]
    assert [item["junit"]["name"] for item in items] == [node.rsplit("::", 1)[1] for node in nodes]
    covered = []
    for selection in expected["selection_counts"]:
        matching = [node for node in nodes if selection_matches(node, selection["selector"])]
        assert len(matching) == selection["expected_cases"]
        covered.extend(matching)
    assert covered == nodes
    for key, source in contract["definitions"].items():
        assert digest(source.encode()) == key
    for row in contract["providers"].values():
        raw = row["content"].encode("utf-8")
        assert digest(raw) == row["sha256"] and len(raw) == row["bytes"]
    if mode == "collect":
        assert value["reports"] == [] and value["execution_collection_matches_prior"] is False
    else:
        assert value["execution_collection_matches_prior"] is True
    return items


def junit(path: Path) -> tuple[list, list]:
    raw = path.read_bytes()
    assert len(raw) <= 16 * 1024 * 1024 and b"<!DOCTYPE" not in raw and b"<!ENTITY" not in raw
    root = ET.fromstring(raw)
    assert root.tag in {"testsuite", "testsuites"}
    suites = [root] if root.tag == "testsuite" else list(root)
    assert all(suite.tag == "testsuite" for suite in suites)
    cases = [case for suite in suites for case in suite.findall("testcase")]
    return suites, cases


def reconcile(prior: dict, actual: dict, expected: dict, xml_path: Path) -> dict:
    prior_items = admitted(prior, expected, "collect")
    items = admitted(actual, expected, "run")
    assert prior["contract"] == actual["contract"], "Fresh execution collection changed"
    assert items == prior_items
    nodes = [row["nodeid"] for row in items]
    phases = actual["reports"]
    assert [(row["nodeid"], row["when"]) for row in phases] == [
        (node, when) for node in nodes for when in ("setup", "call", "teardown")
    ]
    assert all(row["outcome"] == "passed" and row["wasxfail"] is None for row in phases)
    assert all(row["failure_file"] is None and row["longrepr_bytes"] == 0 for row in phases)
    suites, cases = junit(xml_path)
    assert len(cases) == expected["expected_cases"]
    assert sum(int(suite.attrib["tests"]) for suite in suites) == len(cases)
    assert all(int(suite.attrib.get(name, "0")) == 0
               for suite in suites for name in ("errors", "failures", "skipped"))
    identities = [(row.attrib["classname"], row.attrib["name"]) for row in cases]
    expected_identities = [(row["junit"]["classname"], row["junit"]["name"]) for row in items]
    assert identities == expected_identities and len(set(identities)) == len(identities)
    retained = []
    for index, (node, case) in enumerate(zip(nodes, cases, strict=True)):
        assert case.find("failure") is None and case.find("error") is None and case.find("skipped") is None
        properties = [[row.attrib["name"], row.attrib["value"]] for row in case.findall("properties/property")]
        teardown_properties = phases[index * 3 + 2]["user_properties"]
        assert properties == teardown_properties, (node, "ordered JUnit property mismatch")
        retained.append({"nodeid": node, "user_properties": properties})
    return {
        "source_sha": CONFIG["source_sha"], "cohort": expected["name"],
        "cases_passed": len(nodes), "phases_passed": len(phases), "junit_cases": len(cases),
        "ordered_collection_equal": True, "ordered_phase_and_junit_bijection": True,
        "ordered_duplicate_user_properties": retained, "skipped": 0, "xfail_or_xpass": 0,
        "binaries": actual["contract"]["binaries"],
        "scope": "fresh_selected_control_bodies_not_installed_or_performance_qualification",
        "qualification_complete": False,
    }


def run(rows: list) -> bool:
    result = {
        "schema": "pr2974-current-combined-finite.v1",
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "cohorts": [], "passed": False, "qualification_complete": False,
        "historical_results_are_separate": True,
    }
    env = dict(os.environ)
    env.update(VALIDATION_SOURCE=str(SOURCE), VALIDATION_REPORT=str(REPORT), VALIDATION_SCRATCH=str(SCRATCH))
    python = env["VALIDATION_PYTHON"]
    temporary = Path(env["VALIDATION_TEST_TMP"]).resolve(strict=True)
    for expected in CONFIG["python_cohorts"]:
        name = expected["name"]
        output = REPORT / "controls" / name
        output.mkdir(parents=True, exist_ok=False)
        collection_path, execution_path = output / "collect.json", output / "run.json"
        entry = {
            "cohort": name, "expected_cases": expected["expected_cases"], "passed": False,
            "collection_command_passed": False, "body_command_attempted": False, "error": None,
        }
        result["cohorts"].append(entry)
        write_json(REPORT / "finite-controls.json", result)
        try:
            common = [python, "-I", "-B", str(HERE / "collect_controls.py"), "--cohort", name]
            entry["collection_command_passed"] = command(
                "controls-" + name + "-collect",
                [*common, "--mode", "collect", "--output", str(collection_path),
                 "--basetemp", str(temporary / ("controls-" + name + "-collect"))],
                SOURCE, env, expected["timeout"], rows,
            )
            prior = read_capture(collection_path)
            entry["collection_sha256"] = digest(collection_path.read_bytes())
            admitted(prior, expected, "collect")
            _, collect_cases = junit(collection_path.with_suffix(".xml"))
            assert collect_cases == [], "Collection-only command executed test cases"
            assert entry["collection_command_passed"]
            entry["body_command_attempted"] = True
            write_json(REPORT / "finite-controls.json", result)
            body_ok = command(
                "controls-" + name + "-run",
                [*common, "--mode", "run", "--output", str(execution_path),
                 "--basetemp", str(temporary / ("controls-" + name + "-run")),
                 "--prior", str(collection_path)],
                SOURCE, env, expected["timeout"], rows,
            )
            actual = read_capture(execution_path)
            entry["execution_sha256"] = digest(execution_path.read_bytes())
            entry["reconciliation"] = reconcile(prior, actual, expected, execution_path.with_suffix(".xml"))
            assert body_ok
            entry["passed"] = True
        except Exception as error:
            entry["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
        finally:
            write_json(REPORT / "finite-controls.json", result)
    result["passed"] = len(result["cohorts"]) == len(CONFIG["python_cohorts"]) and all(
        entry["passed"] for entry in result["cohorts"]
    )
    result["actual_passed_cases"] = sum(
        entry.get("reconciliation", {}).get("cases_passed", 0) for entry in result["cohorts"] if entry["passed"]
    )
    write_json(REPORT / "finite-controls.json", result)
    return result["passed"]
