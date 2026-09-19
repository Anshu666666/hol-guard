"""Reconcile actual per-case phases and JUnit, retaining every original failure."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import traceback
import xml.etree.ElementTree as ET

def bin_xml_escape(arg: object) -> str:
    r"""Visually escape invalid XML characters.

    For example, transforms
        'hello\aworld\b'
    into
        'hello#x07world#x08'
    Note that the #xABs are *not* XML escapes - missing the ampersand &#xAB.
    The idea is to escape visually for the user rather than for XML itself.
    """

    def repl(matchobj: re.Match[str]) -> str:
        i = ord(matchobj.group())
        if i <= 0xFF:
            return f"#x{i:02X}"
        else:
            return f"#x{i:04X}"

    # The spec range of valid chars is:
    # Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
    # For an unknown(?) reason, we disallow #x7F (DEL) as well.
    illegal_xml_re = (
        "[^\u0009\u000a\u000d\u0020-\u007e\u0080-\ud7ff\ue000-\ufffd\u10000-\u10ffff]"
    )
    return re.sub(illegal_xml_re, repl, str(arg))



def junit_address(node: str) -> tuple[str, str]:
    # Exact pytest 9.0.3 mangle_test_address protocol; node separator is "/".
    path, bracket, parameters = node.partition("[")
    names = path.split("::")
    names[0] = re.sub(r"\.py$", "", names[0].replace("/", "."))
    names[-1] += bracket + parameters
    return bin_xml_escape(".".join(names[:-1])), bin_xml_escape(names[-1])


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def summarize_cohort(report: Path, config: dict, source_files: dict) -> dict:
    folder = report / config["name"]
    result = {"cohort": config["name"], "expected_cases": config["expected_cases"], "errors": [],
              "counts": {"passed": 0, "failed": 0, "skipped": 0, "incomplete": 0},
              "cases": [], "qualification_complete": False}
    try:
        capture = json.loads((folder / "pytest-capture.json").read_bytes())
        collection = capture["collection"]
        definitions = capture["complete_definition_asts"]
        assert definitions and all(sha256(raw.encode()) == identity for identity, raw in definitions.items())
        for row in collection:
            functions = [row["function"], *(fixture["source"] for chain in row["fixtures"].values()
                                           for fixture in chain)]
            for function in functions:
                assert function["complete_definition_ast_sha256"] in definitions
                if function["origin"] == "candidate":
                    assert function["sha256"] == source_files[function["path"]]["sha256"]
        nodes = [row["nodeid"] for row in collection]
        assert len(nodes) == len(set(nodes)) == config["expected_cases"]
        assert capture["collection_admitted"] is True
        if capture["pytest_exit_code"] != 0 or capture["error"] is not None or capture.get("evidence_error"):
            result["errors"].append({"original_pytest_exit": capture["pytest_exit_code"],
                                     "error": capture["error"], "evidence_error": capture.get("evidence_error")})
        by_node = {node: [] for node in nodes}
        for row in capture["reports"]:
            assert row["nodeid"] in by_node, row["nodeid"]
            by_node[row["nodeid"]].append(row)
        for node in nodes:
            phases = by_node[node]
            if any(row["outcome"] == "failed" for row in phases):
                outcome = "failed"
            elif any(row["outcome"] == "skipped" or row["wasxfail"] is not None for row in phases):
                outcome = "skipped"
            elif [row["when"] for row in phases] == ["setup", "call", "teardown"] and all(
                    row["outcome"] == "passed" and not row["longrepr_censored"] for row in phases):
                outcome = "passed"
            else:
                outcome = "incomplete"
            result["counts"][outcome] += 1
            result["cases"].append({"nodeid": node, "outcome": outcome,
                                    "phases": [{"when": row["when"], "outcome": row["outcome"],
                                                "duration_seconds": row["duration_seconds"]}
                                               for row in phases]})
        xml = (folder / "junit.xml").read_bytes()
        assert len(xml) <= 4 * 1024 * 1024 and b"<!DOCTYPE" not in xml and b"<!ENTITY" not in xml
        root = ET.fromstring(xml)
        cases = root.findall(".//testcase")
        expected_addresses = Counter(junit_address(node) for node in nodes)
        observed_addresses = Counter((case.attrib["classname"], case.attrib["name"]) for case in cases)
        assert all(count == 1 for count in expected_addresses.values()), "JUnit address ambiguity"
        assert observed_addresses == expected_addresses, "JUnit does not bijectively cover the actual collection"
        observed = {(case.attrib["classname"], case.attrib["name"]): case for case in cases}
        junit_counts = {"passed": 0, "failed": 0, "skipped": 0}
        for row in result["cases"]:
            case = observed[junit_address(row["nodeid"])]
            failed = case.find("failure") is not None or case.find("error") is not None
            skipped = case.find("skipped") is not None
            outcome = "failed" if failed else "skipped" if skipped else "passed"
            junit_counts[outcome] += 1
            row["junit"] = {"attributes": dict(case.attrib), "outcome": outcome,
                            "children": [{"tag": child.tag, "attributes": dict(child.attrib),
                                          "text": child.text} for child in case]}
            assert row["outcome"] == outcome, (row["nodeid"], row["outcome"], outcome)
        result["junit"] = {"sha256": sha256(xml), "bytes": len(xml), "counts": junit_counts,
                           "suites": [dict(suite.attrib) for suite in root.findall(".//testsuite")],
                           "collection_phase_junit_bijection": True}
        origins = capture["source_origins"]
        assert origins, "No actual source origins"
        for name, record in origins.items():
            assert source_files[record["path"]]["sha256"] == record["sha256"], name
        result["actual_source_origins"] = origins
        if result["counts"] != {"passed": config["expected_cases"], "failed": 0, "skipped": 0, "incomplete": 0}:
            result["errors"].append("Actual failures, skips, expected failures or incomplete phases remain")
    except BaseException as error:
        result["errors"].append({"type": type(error).__name__, "traceback": traceback.format_exc()})
    result["passed"] = not result["errors"]
    return result


def compiler_evidence(report: Path, config: dict, source_files: dict) -> dict:
    capture = json.loads((report / "sqlite-vfs/pytest-capture.json").read_bytes())
    assert len(capture["compiled_build_directories"]) == 1
    directory = capture["compiled_build_directories"][0]
    root = report / "sqlite-vfs/compiled-build" / directory
    expected_names = {"guard_vfs.so", "forward_fixture", "extension.d", "fixture.d",
                      "compile-0.json", "compile-1.json", "build-receipt.json"}
    assert {path.name for path in root.iterdir()} == expected_names
    for name in expected_names:
        raw = (root / name).read_bytes()
        record = capture["compiled_build_files"][directory + "/" + name]
        assert len(raw) == record["bytes"] and sha256(raw) == record["sha256"]
    build = json.loads((root / "build-receipt.json").read_bytes())
    compiler = json.loads((report / "compiler.json").read_bytes())
    assert build["compiler_sha256"] == compiler["sha256"]
    assert sha256((root / "guard_vfs.so").read_bytes()) == build["extension_sha256"]
    assert sha256((root / "forward_fixture").read_bytes()) == build["fixture_sha256"]
    prefix = "scripts/ci/rsp131_sqlite_vfs/"
    expected_sources = {Path(path).name: row["sha256"] for path, row in source_files.items()
                        if path.startswith(prefix) and Path(path).suffix in {".c", ".h"}}
    assert build["source_sha256"] == expected_sources
    assert len(build["compilation"]) == 2
    for index, command in enumerate(build["compilation"]):
        assert command == json.loads((root / ("compile-" + str(index) + ".json")).read_bytes())
        assert command["returncode"] == 0
        assert command["argv"][0] == compiler["selected_path"]
        assert all(flag in command["argv"] for flag in ("-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread"))
        assert "-lsqlite3" not in command["argv"]
    assert all(build["dependency_files"][name] == (root / name).read_text()
               for name in ("extension.d", "fixture.d"))
    included = build["included_file_sha256"]
    assert any(Path(path).name == "sqlite3.h" for path in included)
    assert any(Path(path).name == "sqlite3ext.h" for path in included)
    callback_rows = [row for row in capture["collection"]
                     if row["function"]["qualname"] == "test_actual_compiled_callback_forwarding"]
    parameters = [dict(row["parameters"]["items"])["case"]["value"] for row in callback_rows]
    assert parameters == config["compile_controls"] and len(parameters) == 10
    return {"passed": True, "actual_callback_cases": [row["nodeid"] for row in callback_rows],
            "actual_build_receipt": build, "compiler_identity": compiler,
            "retained_files": capture["compiled_build_files"],
            "dependency_scope": "Actual compiler-emitted dependency records plus separately pinned five C/header "
                "sources; no claim that a shared -MF records every translation-unit or runtime library dependency.",
            "sqlite_semantics": "xWrite/xSync observations are logical VFS operations, not kernel or physical I/O.",
            "qualification_complete": False}


def summarize(report: Path, config: dict, source_files: dict) -> dict:
    cohorts = [summarize_cohort(report, cohort, source_files) for cohort in config["cohorts"]]
    result = {"cohorts": cohorts, "expected_cases": config["expected_total_cases"],
              "counts": {key: sum(row["counts"][key] for row in cohorts)
                         for key in ("passed", "failed", "skipped", "incomplete")},
              "errors": [], "qualification_complete": False, "installed_qualification_credit": False,
              "kernel_or_physical_io_qualification": False}
    try:
        result["compiler"] = compiler_evidence(report, config, source_files)
    except BaseException as error:
        result["errors"].append({"compiler_evidence_error": type(error).__name__,
                                 "traceback": traceback.format_exc()})
    if not all(row["passed"] for row in cohorts):
        result["errors"].append("At least one original finite cohort failed admission, execution or evidence checks")
    if result["counts"] != {"passed": 169, "failed": 0, "skipped": 0, "incomplete": 0}:
        result["errors"].append("All 169 originally selected cases have not passed")
    result["passed"] = not result["errors"]
    return result
