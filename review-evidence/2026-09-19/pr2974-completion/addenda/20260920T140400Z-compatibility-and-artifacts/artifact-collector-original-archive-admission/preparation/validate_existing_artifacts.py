"""Run one source-bound, offline admission of four retained original CI archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--archives", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    contract_path = Path(__file__).with_name("input-contract.json")
    contract = json.loads(contract_path.read_bytes())
    args.output.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {
        "schema": "pr2974-existing-native-artifacts-admission-result.v1",
        "passed": False,
        "candidate_tree": contract["candidate_tree"],
        "original_build": contract["original"]["normal_build_commit"],
        "original_run": contract["original"]["run"],
        "input_contract_sha256": digest(contract_path),
        "source_bindings": [],
        "archives": [],
        "commands": [],
        "native_execution": False,
        "native_rebuild": False,
        "release_or_signing_qualified": False,
    }
    try:
        for expected in contract["files"]:
            path = args.source / expected["path"]
            actual: dict[str, Any] = {"path": expected["path"], "bytes": path.stat().st_size, "sha256": digest(path)}
            report["source_bindings"].append(actual)
            assert actual["bytes"] == expected["bytes"] and actual["sha256"] == expected["sha256"]
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=args.source, text=True, timeout=10).strip()
        assert head == contract["base"]
        report["checkout_base"] = head
        tracked = subprocess.check_output(
            ["git", "diff", "--name-only", "HEAD"], cwd=args.source, text=True, timeout=10
        ).splitlines()
        untracked = subprocess.check_output(
            ["git", "ls-files", "--others", "--exclude-standard"], cwd=args.source, text=True, timeout=10
        ).splitlines()
        assert tracked == [".github/workflows/native-wheel-ci.yml"]
        assert set(untracked) == {
            "scripts/ci/aggregate_native_wheel_artifacts.py",
            "tests/test_aggregate_native_wheel_artifacts.py",
        }
        version = subprocess.run(
            [sys.executable, "scripts/sync_repo_version.py", "--check"],
            cwd=args.source,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        report["commands"].append(
            {
                "stage": "canonical-version",
                "returncode": version.returncode,
                "stdout": version.stdout,
                "stderr": version.stderr,
            }
        )
        assert version.returncode == 0 and version.stdout.strip() == contract["version"]
        with tempfile.TemporaryDirectory(prefix="native-matrix-original-") as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for expected in contract["original"]["archives"]:
                archive = args.archives / f"{expected['artifact_id']}.zip"
                actual = {
                    "artifact_id": expected["artifact_id"],
                    "artifact_name": expected["artifact_name"],
                    "bytes": archive.stat().st_size,
                    "sha256": digest(archive),
                    "members": [],
                }
                report["archives"].append(actual)
                assert actual["bytes"] == expected["archive_bytes"]
                assert actual["sha256"] == expected["archive_sha256"]
                target = artifacts / expected["artifact_name"]
                target.mkdir()
                members = {entry["name"]: entry for entry in expected["members"]}
                with zipfile.ZipFile(archive) as compressed:
                    infos = compressed.infolist()
                    assert len(infos) == len(members) and {info.filename for info in infos} == set(members)
                    for info in infos:
                        member = members[info.filename]
                        name = Path(info.filename)
                        assert not name.is_absolute() and ".." not in name.parts and "\\" not in info.filename
                        assert 0 < info.file_size == member["bytes"] <= 256 * 1024 * 1024
                        output = target / name
                        output.parent.mkdir(parents=True, exist_ok=True)
                        with compressed.open(info) as reader, output.open("xb") as writer:
                            shutil.copyfileobj(reader, writer, 1024 * 1024)
                        assert output.stat().st_size == member["bytes"] and digest(output) == member["sha256"]
                        actual["members"].append(member)
            command = [
                sys.executable,
                "-m",
                "scripts.ci.aggregate_native_wheel_artifacts",
                "--artifacts-dir",
                str(artifacts),
                "--version",
                contract["version"],
                "--source-sha",
                contract["original"]["normal_build_commit"],
                "--rule-digest",
                contract["rule_digest"],
                "--output",
                str(args.output / "admission.json"),
            ]
            result = subprocess.run(command, cwd=args.source, capture_output=True, text=True, timeout=120, check=False)
            (args.output / "admission.stdout.log").write_text(result.stdout)
            (args.output / "admission.stderr.log").write_text(result.stderr)
            report["commands"].append(
                {
                    "stage": "admission",
                    "command": command,
                    "returncode": result.returncode,
                    "stdout_sha256": digest(args.output / "admission.stdout.log"),
                    "stderr_sha256": digest(args.output / "admission.stderr.log"),
                }
            )
            assert result.returncode == 0
            admitted = json.loads((args.output / "admission.json").read_bytes())
            assert admitted["passed"] is True and admitted["validation"]["windows_waiver"] is None
            assert len(admitted["validation"]["platforms"]) == 4
            assert len(admitted["validation"]["artifacts"]) == 5
            assert len(admitted["collected"]) == 7
            assert sum(record["identical_duplicate"] for record in admitted["collected"]) == 2
        for expected in contract["files"]:
            assert digest(args.source / expected["path"]) == expected["sha256"]
        report["source_unchanged_after"] = True
        report["passed"] = True
    except Exception as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error)}
        if isinstance(error, subprocess.TimeoutExpired):
            report["timeout"] = {"stdout": repr(error.stdout), "stderr": repr(error.stderr)}
    (args.output / "result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
