"""Check bounded C evidence continuation with modeled bytes in real temporary files."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from unittest import mock

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from common import REPORT, SCRATCH, write_json  # noqa: E402
import retain_incoming_c_builds as retention  # noqa: E402


def make_build(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=False)
    extension, fixture = b"modeled-extension-bytes", b"modeled-fixture-bytes"
    commands = [
        {"argv": ["modeled-compiler", str(index)], "returncode": 0, "stdout": "", "stderr": ""}
        for index in range(2)
    ]
    for index, command in enumerate(commands):
        (path / ("compile-" + str(index) + ".json")).write_text(json.dumps(command) + "\n")
    for name in ("extension.d", "fixture.d"):
        (path / name).write_text("modeled-output: /modeled/source.c\n")
    (path / "guard_vfs.so").write_bytes(extension)
    (path / "forward_fixture").write_bytes(fixture)
    receipt = {
        "extension_sha256": hashlib.sha256(extension).hexdigest(),
        "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
        "compiler_sha256": "c" * 64,
        "included_file_sha256": {"/modeled/source.c": "d" * 64},
        "dependency_files": {"extension.d": "modeled-output: /modeled/source.c\n"},
        "compilation": commands,
    }
    (path / "build-receipt.json").write_text(json.dumps(receipt) + "\n")


def check_case(root: Path, kind: str) -> dict:
    root.mkdir(parents=True, exist_ok=False)
    temporary, report, scratch = root / "temporary", root / "report", root / "scratch"
    for path in (temporary, report, scratch):
        path.mkdir()
    base = temporary / ("controls-" + retention.COHORT + "-run")
    first, second = base / "rsp131-sqlite-vfs-build0", base / "rsp131-sqlite-vfs-build1"
    make_build(first)
    make_build(second)
    original_copy = retention.shutil.copyfile

    def copy(source: Path, target: Path):
        if kind == "first_binary_copy" and source == first / "guard_vfs.so":
            raise OSError("modeled first-binary copy failure")
        return original_copy(source, target)

    if kind == "first_invalid_receipt":
        (first / "build-receipt.json").write_text("{invalid-json")
    elif kind == "first_nonregular_file":
        (first / "compile-0.json").unlink()
        (first / "compile-0.json").mkdir()
    with (
        mock.patch.object(retention, "REPORT", report),
        mock.patch.object(retention, "SCRATCH", scratch),
        mock.patch.object(retention.shutil, "copyfile", side_effect=copy),
    ):
        result = retention.retain_incoming_c_builds(temporary, incoming_passed=False)
    assert result["cohort_passed"] is False and result["fixture_admission"] is None
    assert len(result["builds"]) == 2 and result["complete_builds"] == 1
    one, two = result["builds"]
    assert one["errors"] and one["complete_build_receipt"] is False
    assert two["errors"] == [] and two["missing"] == [] and two["complete_build_receipt"] is True
    assert set(two["files"]) == set(retention.FILES)
    assert all(row["retained"] for row in two["files"].values())
    for name in retention.FILES:
        record = two["files"][name]
        assert record["sha256"] == hashlib.sha256((second / name).read_bytes()).hexdigest()
        target = (
            Path(record["retained_artifact_path"])
            if name in {"guard_vfs.so", "forward_fixture"}
            else report / "c-builds" / retention.COHORT / "1" / name
        )
        assert target.read_bytes() == (second / name).read_bytes()
    assert one["files"]["compile-1.json"]["retained"] is True
    assert one["files"]["forward_fixture"]["retained"] is True
    if kind == "first_invalid_receipt":
        assert one["files"]["build-receipt.json"]["retained"] is True
        assert (report / "c-builds" / retention.COHORT / "0" / "build-receipt.json").read_text() == "{invalid-json"
    elif kind == "first_binary_copy":
        assert one["files"]["guard_vfs.so"]["retained"] is False
        assert one["files"]["build-receipt.json"]["retained"] is True
    else:
        assert "compile-0.json" not in one["files"]
    assert json.loads((report / "incoming-c-build-retention.json").read_text()) == result
    return {"name": kind, "passed": True, "observed_retention": result}


def main() -> int:
    result = {
        "schema": "pr2974-incoming-C-retention-control.v1", "cases": [], "passed": False,
        "scope": "modeled_C_bytes_real_filesystem_retention_only", "C_compilation_executed": False,
        "product_test_execution_claim": False, "qualification_complete": False,
    }
    try:
        root = SCRATCH / "incoming-c-retention-control"
        for name in ("first_invalid_receipt", "first_binary_copy", "first_nonregular_file"):
            result["cases"].append(check_case(root / name, name))
        assert len(result["cases"]) == 3
        result["passed"] = True
    except Exception as error:
        result["error"] = repr(error)
    finally:
        write_json(REPORT / "incoming-c-retention-control.json", result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
