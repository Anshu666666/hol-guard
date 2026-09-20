"""Retain the separate incoming2433 C builds, including every partial failure."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

from common import REPORT, SCRATCH, write_json
from control_capture_evidence import read_capture_file

COHORT = "incoming_2433_python"
FILES = (
    "compile-0.json", "compile-1.json", "extension.d", "fixture.d", "build-receipt.json",
    "guard_vfs.so", "forward_fixture",
)


def retain_incoming_2433_c_builds(temporary: Path, *, incoming_passed: bool) -> dict:
    assert type(incoming_passed) is bool
    result = {
        "schema": "pr2974-incoming-c-build-retention.v1", "builds": [], "errors": [],
        "cohort": COHORT, "cohort_passed": incoming_passed, "fixture_admission": None,
        "candidate_paths": [], "skipped_symlinks": [], "complete_builds": 0,
        "observed_only": True, "qualification_complete": False,
    }

    def failure(stage: str, error: Exception, row: dict | None = None, name: str | None = None) -> None:
        detail = {"stage": stage, "error": repr(error), "file": name}
        if row is not None:
            detail["path"] = row["path"]
            row["errors"].append(dict(detail))
        result["errors"].append(detail)

    try:
        temporary = temporary.resolve(strict=True)
        base = temporary / ("controls-" + COHORT + "-run")
        candidates = sorted(base.glob("rsp131-sqlite-vfs-build*")) if base.is_dir() else []
        result["candidate_paths"] = [str(path) for path in candidates]
        if len(candidates) > 4:
            failure("candidate_bound", ValueError("Unexpected number of C build directories"))
        for index, path in enumerate(candidates[:4]):
            if path.is_symlink():
                result["skipped_symlinks"].append(str(path))
                continue
            row = {
                "path": str(path), "files": {}, "missing": [], "errors": [],
                "complete_build_receipt": False,
            }
            result["builds"].append(row)
            try:
                assert path.is_dir() and path.resolve(strict=True).is_relative_to(base.resolve(strict=True))
                assert path.stat().st_uid == os.getuid()
            except Exception as error:
                failure("build_directory", error, row)
                continue
            destination = REPORT / "c-builds" / COHORT / str(index)
            destination_ready = False
            try:
                destination.mkdir(parents=True, exist_ok=False)
                destination_ready = True
            except Exception as error:
                failure("retention_directory", error, row)
            for name in FILES:
                try:
                    source = path / name
                    if not source.exists():
                        row["missing"].append(name)
                        continue
                    info = source.lstat()
                    assert stat.S_ISREG(info.st_mode) and not source.is_symlink() and info.st_uid == os.getuid()
                    assert info.st_size <= 4 * 1024 * 1024
                    raw = source.read_bytes()
                    assert len(raw) <= 4 * 1024 * 1024
                    identity = {
                        "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "retained": False,
                    }
                    row["files"][name] = identity
                    if name in {"guard_vfs.so", "forward_fixture"}:
                        artifact = SCRATCH / "native-binaries" / ("sqlite-incoming2433-" + str(index))
                        artifact.mkdir(parents=True, exist_ok=True)
                        target = artifact / name
                        assert not target.exists()
                        shutil.copyfile(source, target)
                        assert target.read_bytes() == raw
                        identity["retained_artifact_path"] = str(target)
                    else:
                        assert destination_ready, "Do not overwrite an existing retention directory"
                        target = destination / name
                        target.write_bytes(raw)
                        assert target.read_bytes() == raw
                    identity["retained"] = True
                except Exception as error:
                    failure("file", error, row, name)
            if "build-receipt.json" in row["files"]:
                try:
                    assert row["files"]["build-receipt.json"]["retained"]
                    receipt = json.loads((destination / "build-receipt.json").read_text())
                    assert receipt["extension_sha256"] == row["files"]["guard_vfs.so"]["sha256"]
                    assert receipt["fixture_sha256"] == row["files"]["forward_fixture"]["sha256"]
                    assert len(receipt["compiler_sha256"]) == 64
                    assert receipt["included_file_sha256"] and receipt["dependency_files"]
                    assert len(receipt["compilation"]) == 2
                    assert all(item["returncode"] == 0 for item in receipt["compilation"])
                    assert set(row["files"]) == set(FILES)
                    assert all(record["retained"] for record in row["files"].values())
                    assert not row["missing"] and not row["errors"]
                    row["complete_build_receipt"] = True
                except Exception as error:
                    failure("build_receipt", error, row, "build-receipt.json")
    except Exception as error:
        failure("inventory", error)
    result["complete_builds"] = sum(row["complete_build_receipt"] for row in result["builds"])
    if incoming_passed:
        try:
            capture = read_capture_file(REPORT / "controls" / COHORT / "run.json")
            assert capture["mode"] == "run" and capture["cohort"] == COHORT
            assert capture["capture_retention"]["complete"] is True
            assert capture["collection_admitted"] is capture["execution_collection_matches_prior"] is True
            assert capture["pytest_exit_code"] == 0 and capture["error"] is capture["evidence_error"] is None
            admission = capture["contract"]["incoming_2433_c_fixtures"]
            result["fixture_admission"] = admission
            assert admission["fixture_instances_expected"] == 2 and admission["selected_cases"] == 24
            assert admission["same_unwrapped_provider_function_object"] is True
            assert admission["same_imported_fixture_wrapper_object"] is True
            assert set(admission["registrations"]) == {
                "tests/test_native_slo_sqlite_vfs.py", "tests/test_native_slo_sqlite_vfs_loader.py",
            }
            assert len(result["builds"]) == result["complete_builds"] == 2
            assert not result["errors"]
        except Exception as error:
            failure("passed_cohort_admission", error)
    write_json(REPORT / "incoming2433-c-build-retention.json", result)
    return result
