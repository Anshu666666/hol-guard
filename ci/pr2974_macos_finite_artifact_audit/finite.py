"""Match every original pytest report to JUnit and retained compiled C fixture bytes."""

from __future__ import annotations

import ast
from collections import Counter
import json
import math
from pathlib import PurePosixPath
import re
import struct
import xml.etree.ElementTree as ET

from common import CONFIG, ORIGINAL, REPORT, SOURCE, digest, parsed, write_json


def junit_address(nodeid: str) -> tuple[str, str]:
    # Matches the pinned pytest 9.0.3 mangle_test_address/record_testreport contract.
    path, bracket, parameters = nodeid.partition("[")
    parts = path.split("::")
    parts[0] = re.sub(r"\.py$", "", parts[0].replace("/", "."))
    parts[-1] += bracket + parameters
    illegal = "[^\u0009\u000a\u000d\u0020-\u007e\u0080-\ud7ff\ue000-\ufffd\u10000-\u10ffff]"
    def replacement(match):
        value = ord(match.group())
        return f"#x{value:02X}" if value <= 255 else f"#x{value:04X}"
    return ".".join(parts[:-1]), re.sub(illegal, replacement, parts[-1])


def audit_finite(payloads: dict[str, bytes], witness: dict) -> dict:
    capture = parsed(payloads, "pytest-capture.json")
    nodes = capture["nodeids"]
    assert len(nodes) == len(set(nodes)) == capture["count"] == 475
    assert capture["pytest_exit_code"] == 0 and capture["error"] is None
    assert set(node.split("::", 1)[0] for node in nodes) == set(ORIGINAL["finite_modules"])
    assert len(ORIGINAL["finite_modules"]) == 13
    reports = {node: [] for node in nodes}
    for row in capture["actual_reports"]:
        assert row["nodeid"] in reports
        reports[row["nodeid"]].append(row)
    assert len(capture["actual_reports"]) == 475 * 3
    for node, rows in reports.items():
        assert [row["when"] for row in rows] == ["setup", "call", "teardown"], node
        assert all(row["outcome"] == "passed" and row["wasxfail"] is None and row["longrepr"] is None
                   for row in rows), node
        assert all(isinstance(row["duration_seconds"], (int, float)) and row["duration_seconds"] >= 0
                   and math.isfinite(row["duration_seconds"]) for row in rows), node
    xml = payloads["finite-junit.xml"]
    assert len(xml) <= 2 * 1024 * 1024
    assert b"<!DOCTYPE" not in xml and b"<!ENTITY" not in xml
    copied = parsed(payloads, "finite-junit-log-copy.json")
    assert copied == {**digest(xml), "xml": xml.decode("utf-8")}
    assert len(payloads["finite-junit-log-copy.json"]) == 1208096
    root = ET.fromstring(xml)
    suites = root.findall(".//testsuite")
    assert len(suites) == 1
    suite = suites[0]
    assert int(suite.attrib["tests"]) == 475
    assert all(int(suite.attrib[name]) == 0 for name in ("errors", "failures", "skipped"))
    cases = root.findall(".//testcase")
    assert len(cases) == 475
    expected = {}
    for node in nodes:
        key = junit_address(node)
        assert key not in expected, "Nonunique pytest-to-JUnit address"
        expected[key] = node
    actual = {}
    pairs = []
    for case in cases:
        key = (case.attrib["classname"], case.attrib["name"])
        assert key in expected and key not in actual
        assert all(case.find(tag) is None for tag in ("failure", "error", "skipped"))
        assert set(case.attrib) == {"classname", "name", "time"}
        node = expected[key]
        duration = sum(row["duration_seconds"] for row in reports[node])
        assert case.attrib["time"] == f"{duration:.3f}", node
        actual[key] = node
        pairs.append({"nodeid": node, "junit_attributes": dict(case.attrib),
                      "report_phases": [row["when"] for row in reports[node]],
                      "original_outcome": "passed", "report_duration_seconds": duration})
    assert actual == expected
    assert len(capture["source_origins"]) == 32
    for name, origin in capture["source_origins"].items():
        assert witness["files"][origin["path"]]["sha256"] == origin["sha256"], name
    forwarding = "tests/test_native_macos_dnssd_phase_forwarding.py"
    c_cases = capture["portable_c_cases"]
    assert len(c_cases) == 9 and capture["portable_c_programs"] == 1
    assert {tuple(sorted(row["parameters"].items())) for row in c_cases} == {
        tuple(sorted({"cycles": cycles, "scenario": scenario}.items()))
        for cycles in (1, 8, 17) for scenario in (0, 1, 2)}
    c_nodes = {node for node in nodes if node.split("::", 1)[0] == forwarding}
    assert {row["nodeid"] for row in c_cases} == c_nodes and len(c_nodes) == 9
    fixture = capture["portable_c_fixture_files"]
    expected_names = {"dns_sd.h", "native_macos_dnssd_phase_probe.c", "native_macos_dnssd_python_bridge.c",
                      "native_macos_python_resolver_bridge.c", "shim.c", "probe"}
    assert len(fixture) == 6
    assert {PurePosixPath(path).name for path in fixture} == expected_names
    assert len({str(PurePosixPath(path).parent) for path in fixture}) == 1
    fixture_payloads = {}
    for path, value in fixture.items():
        name = "portable-c-fixture/" + path
        assert digest(payloads[name]) == value
        fixture_payloads[PurePosixPath(path).name] = payloads[name]
    assert {name for name in payloads if name.startswith("portable-c-fixture/")} == {
        "portable-c-fixture/" + path for path in fixture}
    tree = ast.parse((SOURCE / forwarding).read_bytes(), filename=forwarding)
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in {"HEADER", "QUERY", "SHIM"}:
                constants[node.targets[0].id] = ast.literal_eval(node.value)
    assert set(constants) == {"HEADER", "QUERY", "SHIM"}
    for name, constant in (("dns_sd.h", "HEADER"), ("native_macos_python_resolver_bridge.c", "QUERY"),
                           ("shim.c", "SHIM")):
        assert fixture_payloads[name] == constants[constant].encode(), name
    for name in ("native_macos_dnssd_phase_probe.c", "native_macos_dnssd_python_bridge.c"):
        assert fixture_payloads[name] == (SOURCE / "scripts/ci" / name).read_bytes(), name
    binary = fixture_payloads["probe"]
    assert len(binary) >= 64 and binary[:7] == b"\x7fELF\x02\x01\x01"
    assert struct.unpack_from("<H", binary, 16)[0] in (2, 3)
    assert struct.unpack_from("<H", binary, 18)[0] == 62
    compiler = parsed(payloads, "portable-c-compiler.json")
    assert re.fullmatch("[0-9a-f]{64}", compiler["sha256"])
    assert compiler["version_output"].encode() == payloads["portable-c-compiler.log"]
    assert compiler["sdk"] == "deterministic dns_sd.h and C shim in the selected finite test"
    assert compiler["native_qualification_credit"] is False
    summary = parsed(payloads, "finite-results.json")
    assert summary["passed"] is True and summary["errors"] == []
    assert summary["actual_execution_counts"] == {"passed": 475, "failed": 0, "skipped": 0, "incomplete": 0}
    assert summary["actual_junit_counts"] == {"tests": 475, "passed": 475, "failed": 0, "errored": 0, "skipped": 0}
    assert summary["actual_junit_suites"] == [dict(suite.attrib)]
    assert summary["portable_c_cases"] == c_cases and summary["portable_c_programs"] == 1
    for name in ("native_qualification_credit", "installed_qualification_credit", "qualification_complete"):
        assert capture[name] is False and summary[name] is False
    write_json(REPORT / "original-junit-report-bijection.json", pairs)
    result = {"original_collected": 475, "original_passed": 475, "original_failed": 0,
              "original_errored": 0, "original_skipped": 0, "original_incomplete": 0,
              "individual_junit_report_bijections": len(pairs), "original_reports": len(capture["actual_reports"]),
              "by_module": dict(sorted(Counter(node.split("::", 1)[0] for node in nodes).items())),
              "compiled_portable_c_controls": 9, "retained_compiled_programs": 1,
              "five_fixture_source_files_bound_to_exact_test_literals_and_actual_C_source": True,
              "retained_portable_program": digest(binary), "original_compiler": compiler,
              "actual_source_origins": capture["source_origins"], "original_junit": digest(xml),
              "observer_executed_workloads": False, "native_qualification_credit": False,
              "installed_qualification_credit": False, "qualification_complete": False}
    write_json(REPORT / "original-finite-audit.json", result)
    return result
