"""Retain actual C fixture compile receipts and artifacts after owned pytest exits."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

from common import REPORT, SCRATCH, write_json


def retain_c_builds(temporary: Path) -> dict:
    temporary = temporary.resolve(strict=True)
    base = temporary / "controls-python-run"
    result = {"schema": "pr2974-c-build-retention.v1", "builds": [], "errors": [],
              "observed_only": True, "qualification_complete": False}
    candidates = sorted(base.glob("rsp131-sqlite-vfs-build*")) if base.is_dir() else []
    try:
        assert len(candidates) <= 4, "Unexpected number of C build directories"
        for index, path in enumerate(candidates):
            if path.is_symlink():
                continue
            assert path.is_dir() and path.resolve(strict=True).is_relative_to(base.resolve(strict=True))
            assert path.stat().st_uid == os.getuid()
            row = {"path": str(path), "files": {}, "missing": [], "complete_build_receipt": False}
            result["builds"].append(row)
            destination = REPORT / "c-builds" / str(index)
            destination.mkdir(parents=True, exist_ok=False)
            for name in ("compile-0.json", "compile-1.json", "extension.d", "fixture.d", "build-receipt.json",
                         "guard_vfs.so", "forward_fixture"):
                source = path / name
                if not source.exists():
                    row["missing"].append(name)
                    continue
                info = source.lstat()
                assert stat.S_ISREG(info.st_mode) and not source.is_symlink() and info.st_uid == os.getuid()
                assert info.st_size <= 4 * 1024 * 1024
                raw = source.read_bytes()
                identity = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                row["files"][name] = identity
                if name in {"guard_vfs.so", "forward_fixture"}:
                    artifact = SCRATCH / "native-binaries" / ("sqlite-" + str(index))
                    artifact.mkdir(parents=True, exist_ok=True)
                    target = artifact / name
                    assert not target.exists()
                    shutil.copyfile(source, target)
                    assert target.read_bytes() == raw
                    identity["retained_artifact_path"] = str(target)
                else:
                    (destination / name).write_bytes(raw)
            if "build-receipt.json" in row["files"]:
                receipt = json.loads((destination / "build-receipt.json").read_text())
                assert receipt["extension_sha256"] == row["files"]["guard_vfs.so"]["sha256"]
                assert receipt["fixture_sha256"] == row["files"]["forward_fixture"]["sha256"]
                assert len(receipt["compiler_sha256"]) == 64
                assert receipt["included_file_sha256"] and receipt["dependency_files"]
                assert len(receipt["compilation"]) == 2
                assert all(item["returncode"] == 0 for item in receipt["compilation"])
                row["complete_build_receipt"] = True
    except Exception as error:
        result["errors"].append(repr(error))
    result["complete_builds"] = sum(row["complete_build_receipt"] for row in result["builds"])
    write_json(REPORT / "c-build-retention.json", result)
    return result
