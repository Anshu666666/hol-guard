"""Read-only verification of the corrected accepted-stream Unix peer matrix."""
from pathlib import Path
import hashlib
import json
import re
import zipfile
import verify_result as strict


def verify(cell):
    metadata = strict.read_json(cell / "metadata.json")
    archive = (cell / "original.zip").read_bytes()
    assert len(archive) == metadata["size_in_bytes"]
    assert "sha256:" + hashlib.sha256(archive).hexdigest() == metadata["digest"]
    assert metadata["workflow_run"]["head_sha"] == strict.DRIVER
    members = []
    with zipfile.ZipFile(cell / "original.zip") as z:
        assert len(z.namelist()) == len(set(z.namelist()))
        for name in z.namelist():
            body = z.read(name)
            assert body == (cell / "raw" / name).read_bytes()
            members.append({"path": name, **strict.identity(body)})
    root = cell / "raw/rsp091-validation"
    report = strict.read_json(root / "result.json")
    if report["passed"]:
        return strict.verify(cell)
    assert report["lane"] in ("macos-x64", "macos-arm64")
    assert len(report["cases"]) == 1 and report["passed"] is False
    positive = report["cases"][0]
    assert positive["case"] == strict.CASES[0] and positive["passed"] is True
    assert positive["parent_pass_count"] == positive["owned_child_fixture_pass_count"] == 1
    positive_stdout = (root / "case-0.stdout").read_bytes().decode()
    positive_stderr = (root / "case-0.stderr").read_bytes().decode()
    assert positive_stderr == ""
    assert len(re.findall(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", positive_stdout)) == 2
    expected_positive = [{"accepted": 1, "payload_bytes": 32, "authenticated": True,
                          "request_digest_valid": True, "response_written": True}]
    actual_positive = [json.loads(line.split("RSP091_OBSERVATION=", 1)[1]) for line in positive_stdout.splitlines() if "RSP091_OBSERVATION=" in line]
    positive_cleanup = [json.loads(line.split("RSP091_CLEANUP=", 1)[1]) for line in positive_stdout.splitlines() if "RSP091_CLEANUP=" in line]
    assert actual_positive == positive["observations"] == expected_positive
    assert positive_cleanup == positive["cleanup"] == [{"negative": False, "reaped": True, "directory_removed": True}]
    assert report["bindings_unchanged"] is True and report["binary_unchanged"] is True
    before = strict.read_json(root / "binding-before.json")
    assert before == strict.read_json(root / "binding-after.json")
    assert (before["source_sha"], before["source_tree"], before["driver_sha"], before["driver_tree"]) == (
        strict.SOURCE, strict.TREE, strict.DRIVER, strict.DRIVER_TREE)
    assert before["source_clean"] is True and before["driver_clean"] is True
    binary = strict.identity((root / "hol-guard-runtime-test-binary").read_bytes())
    assert binary == report["binary_before"] == report["binary_after"]
    for name, value in before["members"].items():
        local = root / "source" / name
        if local.is_file():
            assert strict.identity(local.read_bytes()) == value
    compiler = strict.read_json(root / "compiler-artifact.json")
    assert compiler["target"]["name"] == "hol-guard-runtime"
    assert compiler["features"] in ([], ["default"]) and compiler["profile"]["test"] is True
    for label in ("rustc", "rustfmt", "build", "collection", "case-0", "case-1"):
        command = strict.read_json(root / (label + ".json"))
        assert command["returncode"] == (101 if label == "case-1" else 0)
        assert command["timed_out"] is False and command["direct_child_reaped"] is True
        for stream in ("stdout", "stderr"):
            assert strict.identity((root / f"{label}.{stream}").read_bytes()) == command[stream]
    command = strict.read_json(root / "case-1.json")
    assert command["argv"][1:] == ["--exact", strict.CASES[1], "--nocapture", "--test-threads=1"]
    assert command["timeout_seconds"] == 45
    assert report["selected_parent_cases"] == list(strict.CASES)
    assert all(not (root / f"case-{i}.json").exists() for i in (2, 3))
    stdout = (root / "case-1.stdout").read_bytes().decode()
    stderr = (root / "case-1.stderr").read_bytes().decode()
    assert len(re.findall(r"test result: FAILED\. 0 passed; 1 failed; 0 ignored;", stdout)) == 2
    assert 'Os { code: 22, kind: InvalidInput, message: "Invalid argument" }' in stderr
    assert "resident_transport_peer_identity_tests.rs:230:55" in stderr
    parent_error = "fixture_file_deadline"
    assert parent_error in stderr and "resident_transport_peer_identity_tests.rs:41:9" in stderr
    assert "RSP091_OBSERVATION=" not in stdout + stderr
    cleanup = [json.loads(line.split("RSP091_CLEANUP=", 1)[1]) for line in stdout.splitlines() if "RSP091_CLEANUP=" in line]
    assert cleanup == [{"negative": True, "reaped": True, "directory_removed": False}]
    log = (cell / "raw/rsp091-driver-controls.log").read_bytes().decode()
    assert "Ran 11 tests" in log and log.rstrip().endswith("OK")
    names = re.findall(r"^(test_\w+) \(test_driver\.Admission\.\w+\) \.\.\. ok$", log, re.M)
    assert len(names) == len(set(names)) == 11
    return {"lane": report["lane"], "passed": False, "parent_tests_passed": 1,
            "parent_tests_failed": 1, "owned_child_fixture_failures": 1,
            "later_parent_cases_unoffered": list(strict.CASES[2:]), "driver_controls_passed": 11,
            "test_binary": binary, "members": members, "source_binding": before,
            "child_error": "set_read_timeout: OS22 InvalidInput", "owned_child_fixture_passes": 1, "cases": report["cases"], "parent_error": parent_error,
            "observed_cleanup": cleanup, "drop_removal_observed": False,
            "underlying_os_error_observed": True, "negative_zero_bytes_observed": False, "installed_or_performance_claim": False}


if __name__ == "__main__":
    root = Path(__file__).parent.parent / "run35539478823"
    result = {"schema": "pr2974.rsp091-blocking-fixture-mixed.v1", "run": 35539478823,
              "cells": [verify(root / str(a)) for a in (10614252013, 10614057424, 10613768420)],
              "overall_passed": False, "originals_unchanged": True}
    (root / "VERIFIED-RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"cells": [(c["lane"], c["parent_tests_passed"]) for c in result["cells"]]}))
