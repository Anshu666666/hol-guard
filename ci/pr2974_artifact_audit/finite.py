"""Derive actual original collections, results, and environment pins from retained reports."""

from __future__ import annotations

import re
import tomllib
import xml.etree.ElementTree as ET

from common import ORIGINAL, REPORT, SOURCE, digest, write_json
from reports import parsed


def origins(value: dict[str, object], source_files: dict[str, object]) -> int:
    entries = value["product_module_origins"]
    assert entries, "Original import-origin observation is empty"
    for name, row in entries.items():
        assert name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
        assert row["path"].startswith("src/codex_plugin_scanner/")
        assert row["sha256"] == source_files[row["path"]]["sha256"], name
    return len(entries)


def audit_finite(payloads: dict[str, bytes], report: dict[str, object],
                 witness: dict[str, object]) -> dict[str, object]:
    steps = report["commands"]
    source_files = witness["files"]
    counts = {}
    for family, numbered_count, width, expected_collection, expected_tests in (
        ("cli", 49, 2, 261, 6), ("runtime", 62, 3, 718, 4)
    ):
        facade = "tests/test_guard_" + family + ".py"
        pattern = re.compile(r"tests/test_guard_" + family + r"_(\d{" + str(width) + r"})_.+\.py\Z")
        numbered = sorted(path for path in source_files if pattern.fullmatch(path))
        assert [int(pattern.fullmatch(path)[1]) for path in numbered] == list(range(1, numbered_count + 1))
        selected = sorted([facade, *numbered])
        assert parsed(payloads, family + "-selected-files.json") == selected
        collection = parsed(payloads, family + "-collection.json")
        affected = parsed(payloads, family + "-affected-collection.json")
        for value, expected in ((collection, expected_collection), (affected, expected_tests)):
            assert value["pytest_exit_code"] == 0 and value["error"] is None
            assert value["count"] == len(value["nodeids"]) == expected
            assert len(set(value["nodeids"])) == expected
            assert all(node.split("::", 1)[0] in selected for node in value["nodeids"])
            origins(value, source_files)
        selectors = ORIGINAL[family + "_selectors"]
        if family == "cli":
            assert affected["nodeids"] == selectors
        else:
            assert all(node.startswith(selectors[0] + "[") for node in affected["nodeids"])
        collect_args = steps[family + "-collection"]["command"]
        assert collect_args[1] == "-I" and collect_args[2].endswith("/ci/pr2974_source_validation/pytest_capture.py")
        assert collect_args[3:8] == ["--collect-only", "-q", "-m", "", "-o"]
        assert collect_args[8].startswith("cache_dir=") and collect_args[9:] == selected
        test_args = steps[family + "-affected-tests"]["command"]
        assert test_args[1:3] == collect_args[1:3]
        assert test_args[3:8] == ["-q", "-m", "", "--tb=short", "-o"]
        assert test_args[-len(selectors):] == selectors
        assert "--junitxml" in test_args and "--basetemp" in test_args
        cases = ET.fromstring(payloads[family + "-affected-junit.xml"]).findall(".//testcase")
        actual = {"tests": len(cases), "failed": sum(case.find("failure") is not None for case in cases),
                  "errored": sum(case.find("error") is not None for case in cases),
                  "skipped": sum(case.find("skipped") is not None for case in cases)}
        assert actual == {"tests": expected_tests, "failed": 0, "errored": 0, "skipped": 0}
        actual["passed"] = expected_tests
        counts[family] = {"selected_files": len(selected), "collected": len(collection["nodeids"]),
                          "junit": actual, "actual_affected_nodeids": affected["nodeids"],
                          "collection_product_origins": len(collection["product_module_origins"]),
                          "affected_product_origins": len(affected["product_module_origins"]),
                          "ordered_nodeids_file": digest(payloads[family + "-collection.json"])}
    result = parsed(payloads, "finite-results.json")
    assert result["errors"] == [] and result["required_collection"] == {"cli": 261, "runtime": 718}
    assert result["actual_junit_results"] == {family: row["junit"] for family, row in counts.items()}
    assert result["qualification_complete"] is False
    assert payloads["environment-before.json"] == payloads["environment-after.json"]
    environment = parsed(payloads, "environment-before.json")
    backend = parsed(payloads, "build-environment.json")
    host = parsed(payloads, "host.json")
    assert host["python_version"].split()[0] == ORIGINAL["python_version"]
    for item in (environment, backend):
        assert item["python_version"].split()[0] == ORIGINAL["python_version"]
        assert item["prefix"] != item["base_prefix"] and item["platform"] == "linux"
        assert set(item["launchers"]) == {"python", "python3", "python3.12"}
        for launcher in item["launchers"].values():
            assert launcher["mode"] == "0o755" and launcher["uid"] == host["uid"]
            assert launcher["sha256"] == host["python_sha256"]
        versions = item["installed_versions"]
        assert item["installed_count"] == len(versions)
        metadata = item["distribution_metadata"]
        assert {row["name"]: row["version"] for row in metadata} == versions
        assert len(metadata) == len(versions) and all(re.fullmatch("[0-9a-f]{64}", row["metadata_sha256"]) for row in metadata)
    assert environment["backend_environment"] is False and backend["backend_environment"] is True
    assert backend["installed_versions"]["hatchling"] == "1.30.1"
    assert backend["installed_versions"]["build"] == "1.5.0"
    project = tomllib.loads((SOURCE / "pyproject.toml").read_text())
    assert backend["backend_requirement"] == project["build-system"]
    lock = tomllib.loads((SOURCE / "uv.lock").read_text())
    pinned = {}
    for package in lock["package"]:
        name = re.sub(r"[-_.]+", "-", package["name"]).lower()
        pinned.setdefault(name, set()).add(package["version"])
    versions = environment["installed_versions"]
    assert all(version in pinned.get(name, set()) for name, version in versions.items())
    assert environment["all_versions_match_frozen_lock"] is True
    assert environment["prior_69_reference_matches"] == (versions == ORIGINAL["installed_versions"])
    source_cwd = steps["frozen-project-install"]["cwd"]
    assert environment["editable_project"] == {"url": "file://" + source_cwd, "dir_info": {"editable": True}}
    expected_origin = source_cwd + "/src/codex_plugin_scanner/__init__.py"
    assert environment["package_origin"] == expected_origin
    assert environment["package_origin_sha256"] == source_files["src/codex_plugin_scanner/__init__.py"]["sha256"]
    install = steps["frozen-project-install"]["command"]
    assert install[1:-1] == ["--no-config", "sync", "--frozen", "--extra", "dev", "--python"]
    assert steps["dependency-compatibility"]["command"] == [
        install[0], "--no-config", "pip", "check", "--python", install[-1]]
    uv = parsed(payloads, "uv-binary.json")
    assert uv["version_output"] == payloads["uv-version.log"].decode().strip()
    assert uv["version_output"].split()[1] == ORIGINAL["uv_version"]
    fixed = sorted(ORIGINAL["fixed_files"])
    assert steps["ruff-five-files"]["command"][1:] == ["check", *fixed]
    assert steps["ruff-format-five-files"]["command"][1:] == ["format", "--check", *fixed]
    summary = {"actual_families": counts, "python_version": environment["python_version"],
               "installed_count": environment["installed_count"], "all_versions_match_frozen_lock": True,
               "prior_69_reference_matches": environment["prior_69_reference_matches"],
               "backend_installed_count": backend["installed_count"], "backend_versions": backend["installed_versions"],
               "source_import_hashes_verified": True, "environment_before_after_byte_equal": True,
               "five_fixture_ruff_commands_passed": True, "no_original_test_or_install_reexecuted": True}
    write_json(REPORT / "finite-audit.json", summary)
    return summary
