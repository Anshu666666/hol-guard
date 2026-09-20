"""Data-only joins for retained RSP091 original archives and exact commands."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path

SOURCE = "a63cfdf9c5f49d7bd3199e65ae48f393297a391b"
TREE = "9c472594937f085864e2cb0ff60227c6a9e0f713"
DRIVER = "178109c220a4f39744ef2b37abc177c32aa87918"
DRIVER_TREE = "70a713c8f1b0e1fa4f373abd98c41e1368fc7adb"
CASES = (
    "resident_transport::peer_identity_tests::unix_peer_actual_owner_completes_original_exchange",
    "resident_transport::peer_identity_tests::unix_peer_other_process_is_rejected_before_auth",
    "resident_client::connect_deadline_tests::unix_socket_setup_cannot_admit_after_original_deadline",
    "resident_client::connect_deadline_tests::unix_socket_setup_retains_in_budget_connection",
)


def identity(body: bytes) -> dict[str, object]:
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def read_json(path: Path) -> object:
    return json.loads(path.read_bytes())


def verify(cell: Path) -> dict[str, object]:
    metadata = read_json(cell / "metadata.json")
    assert isinstance(metadata, dict)
    archive = (cell / "original.zip").read_bytes()
    assert len(archive) == metadata["size_in_bytes"]
    assert "sha256:" + hashlib.sha256(archive).hexdigest() == metadata["digest"]
    assert metadata["workflow_run"]["head_sha"] == DRIVER
    rows = []
    with zipfile.ZipFile(cell / "original.zip") as zipped:
        names = zipped.namelist()
        assert len(names) == len(set(names))
        for name in names:
            body = zipped.read(name)
            assert body == (cell / "raw" / name).read_bytes()
            rows.append({"path": name, **identity(body)})
    roots = list((cell / "raw").rglob("result.json"))
    assert len(roots) == 1
    root = roots[0].parent
    report = read_json(root / "result.json")
    assert isinstance(report, dict)
    assert report["passed"] is True and report["bindings_unchanged"] is True and report["binary_unchanged"] is True
    before, after = read_json(root / "binding-before.json"), read_json(root / "binding-after.json")
    assert before == after and isinstance(before, dict)
    assert (before["source_sha"], before["source_tree"], before["driver_sha"], before["driver_tree"]) == (
        SOURCE, TREE, DRIVER, DRIVER_TREE
    )
    assert before["source_clean"] is True and before["driver_clean"] is True
    binary = (root / "hol-guard-runtime-test-binary").read_bytes()
    assert identity(binary) == report["binary_before"] == report["binary_after"]
    for name, value in before["members"].items():
        path = root / "source" / name
        if path.is_file():
            assert identity(path.read_bytes()) == value
    compiler = read_json(root / "compiler-artifact.json")
    assert compiler["target"]["name"] == "hol-guard-runtime"
    assert compiler["features"] in ([], ["default"]) and compiler["profile"]["test"] is True
    assert report["selected_parent_cases"] == list(CASES)
    assert len(report["cases"]) == 4
    for label in ("rustc", "rustfmt", "build", "collection", "case-0", "case-1", "case-2", "case-3"):
        record = read_json(root / (label + ".json"))
        assert record["returncode"] == 0 and record["timed_out"] is False and record["direct_child_reaped"] is True
        for stream in ("stdout", "stderr"):
            assert identity((root / f"{label}.{stream}").read_bytes()) == record[stream]
    for index, case in enumerate(CASES):
        record = report["cases"][index]
        command = read_json(root / f"case-{index}.json")
        assert command["argv"][1:] == ["--exact", case, "--nocapture", "--test-threads=1"]
        assert command["timeout_seconds"] == 45
        assert record["case"] == case and record["passed"] is True
        assert record["parent_pass_count"] == 1 and record["owned_child_fixture_pass_count"] == (1 if index < 2 else 0)
        stdout = (root / f"case-{index}.stdout").read_bytes().decode()
        stderr = (root / f"case-{index}.stderr").read_bytes().decode()
        text = stdout + "\n" + stderr
        assert f"test {case} ..." in text
        summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured;", stdout)
        assert len(summaries) == (2 if index < 2 else 1)
        assert all(row == ("1", "0", "0", "0") for row in summaries)
        prefix = "RSP091_OBSERVATION=" if index < 2 else "HOL_GUARD_DEADLINE_CONTROL "
        values = [json.loads(line.split(prefix, 1)[1]) for line in text.splitlines() if prefix in line]
        assert values == record["observations"]
        if index < 2:
            cleanup = [json.loads(line.split("RSP091_CLEANUP=", 1)[1]) for line in text.splitlines()
                       if "RSP091_CLEANUP=" in line]
            assert cleanup == record["cleanup"] == [{"negative": index == 1, "reaped": True, "directory_removed": True}]
        if index == 0:
            assert values == [{"accepted": 1, "payload_bytes": 32, "authenticated": True,
                               "request_digest_valid": True, "response_written": True}]
        if index == 1:
            assert values == [{"accepted": 1, "received_bytes": 0, "authenticated": False}]
        if index >= 2:
            assert values == [{"case": case.rsplit("::", 1)[1],
                               "result": "deadline" if index == 2 else "connected",
                               "connected": index != 2, "expired_on_release": index == 2,
                               "owned_cleanup": True}]
    logs = list((cell / "raw").rglob("rsp091-driver-controls.log"))
    assert len(logs) == 1
    log = logs[0].read_text()
    assert "Ran 11 tests" in log and log.rstrip().endswith("OK")
    passed_names = re.findall(r"^(test_\w+) \(test_driver\.Admission\.\w+\) \.\.\. ok$", log, re.MULTILINE)
    assert len(passed_names) == len(set(passed_names)) == 11
    return {"lane": report["lane"], "parent_tests_passed": 4, "owned_child_fixture_passes": 2,
            "driver_controls_passed": 11, "test_binary": identity(binary), "members": rows,
            "source_binding": before, "cases": report["cases"], "installed_or_performance_claim": False}
