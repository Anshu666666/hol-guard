"""Read-only verification of the first functional Unix peer matrix."""
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
    assert report["cases"] == [] and report["passed"] is False
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
    for label in ("rustc", "rustfmt", "build", "collection", "case-0"):
        command = strict.read_json(root / (label + ".json"))
        assert command["returncode"] == (101 if label == "case-0" else 0)
        assert command["timed_out"] is False and command["direct_child_reaped"] is True
        for stream in ("stdout", "stderr"):
            assert strict.identity((root / f"{label}.{stream}").read_bytes()) == command[stream]
    command = strict.read_json(root / "case-0.json")
    assert command["argv"][1:] == ["--exact", strict.CASES[0], "--nocapture", "--test-threads=1"]
    assert command["timeout_seconds"] == 45
    assert report["selected_parent_cases"] == list(strict.CASES)
    assert all(not (root / f"case-{i}.json").exists() for i in (1, 2, 3))
    stdout = (root / "case-0.stdout").read_bytes().decode()
    stderr = (root / "case-0.stderr").read_bytes().decode()
    assert len(re.findall(r"test result: FAILED\. 0 passed; 1 failed; 0 ignored;", stdout)) == 2
    assert "native_resident_auth_client_failed" in stderr
    parent_error = "native_client_timeout_failed" if report["lane"] == "macos-x64" else "native_client_frame_read_failed"
    assert parent_error in stderr
    assert "RSP091_OBSERVATION=" not in stdout + stderr
    cleanup = [json.loads(line.split("RSP091_CLEANUP=", 1)[1]) for line in stdout.splitlines() if "RSP091_CLEANUP=" in line]
    assert cleanup == [{"negative": False, "reaped": True, "directory_removed": False}]
    log = (cell / "raw/rsp091-driver-controls.log").read_bytes().decode()
    assert "Ran 11 tests" in log and log.rstrip().endswith("OK")
    names = re.findall(r"^(test_\w+) \(test_driver\.Admission\.\w+\) \.\.\. ok$", log, re.M)
    assert len(names) == len(set(names)) == 11
    return {"lane": report["lane"], "passed": False, "parent_tests_passed": 0,
            "parent_tests_failed": 1, "owned_child_fixture_failures": 1,
            "later_parent_cases_unoffered": list(strict.CASES[1:]), "driver_controls_passed": 11,
            "test_binary": binary, "members": members, "source_binding": before,
            "child_error": "native_resident_auth_client_failed", "parent_error": parent_error,
            "observed_cleanup": cleanup, "drop_removal_observed": False,
            "underlying_os_error_observed": False, "installed_or_performance_claim": False}


if __name__ == "__main__":
    root = Path(__file__).parent / "run35538594974"
    result = {"schema": "pr2974.rsp091-first-functional-mixed.v1", "run": 35538594974,
              "cells": [verify(root / str(a)) for a in (10613960938, 10614200614, 10614380219)],
              "overall_passed": False, "originals_unchanged": True}
    (root / "VERIFIED-RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"cells": [(c["lane"], c["parent_tests_passed"]) for c in result["cells"]]}))
