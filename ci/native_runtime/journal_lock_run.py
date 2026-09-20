"""Bind and run the source-only journal lock controls exactly once on Windows."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BASE = "ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d"
FILES = (
    "ci/native_runtime/journal_lock_child.py",
    "ci/native_runtime/journal_lock_process.py",
    "ci/native_runtime/journal_lock_run.py",
    "tests/test_journal_lock_overlap.py",
)
JOURNAL = "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_journal.py"
JOURNAL_HASH = "ae6482f105278138f419ae2b33771cc3a91a8bcd8b3552a0bc082b5e9e424988"
CELLS = {"uncontended", "held", "released", "nonblocking", "blocking"}


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def git(*args: str) -> str:
    result = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True, timeout=20)
    return result.stdout.strip()


def binding() -> dict[str, Any]:
    source, tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    if source != os.environ["DIAGNOSTIC_SOURCE_SHA"] or tree != os.environ["DIAGNOSTIC_SOURCE_TREE"]:
        raise RuntimeError("source_binding_mismatch")
    if git("rev-parse", "HEAD^") != BASE:
        raise RuntimeError("source_parent_mismatch")
    changed = set(git("diff", "--name-only", BASE, "HEAD").splitlines())
    if changed != set(FILES) or git("diff", "--name-only") or git("diff", "--cached", "--name-only"):
        raise RuntimeError("source_delta_mismatch")
    members = []
    for name in (*FILES, JOURNAL, "pyproject.toml", "uv.lock"):
        body = (ROOT / name).read_bytes()
        normalized = body.replace(b"\r\n", b"\n")
        expected = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"HEAD:{name}"], capture_output=True, check=True, timeout=20
        ).stdout
        if normalized != expected:
            raise RuntimeError("source_member_mismatch")
        if name == JOURNAL and hashlib.sha256(normalized).hexdigest() != JOURNAL_HASH:
            raise RuntimeError("journal_source_mismatch")
        members.append(
            {
                "path": name,
                "actual_sha256": hashlib.sha256(body).hexdigest(),
                "lf_sha256": hashlib.sha256(normalized).hexdigest(),
                "bytes": len(body),
            }
        )
    return {
        "source": source,
        "tree": tree,
        "parent": BASE,
        "members": members,
        "python": platform.python_version(),
        "executable": sys.executable,
        "prefix": sys.prefix,
        "dependencies": sorted((item.metadata["Name"], item.version) for item in importlib.metadata.distributions()),
    }


def attempt(command: list[str], output: Path, *, seconds: int = 180) -> int:
    with output.open("wb") as stream:
        try:
            result = subprocess.run(
                command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=seconds, check=False
            )
        except subprocess.TimeoutExpired:
            write(
                output.with_suffix(".timeout.json"),
                {
                    "timeout_seconds": seconds,
                    "direct_child_killed_reaped_by_subprocess": True,
                    "all_descendants_proved_retired": False,
                },
            )
            return 124
    return result.returncode


def junit(path: Path) -> dict[str, Any]:
    cases = ET.parse(path).getroot().findall(".//testcase")
    identities = [(case.attrib.get("classname"), case.attrib.get("name")) for case in cases]
    if len(cases) != 26 or len(set(identities)) != 26:
        raise RuntimeError("control_count_mismatch")
    windows: dict[str, Any] = {}
    for case in cases:
        properties: dict[str, str] = {}
        for item in case.findall("./properties/property"):
            name = item.attrib["name"]
            if name in properties:
                raise RuntimeError("duplicate_case_property")
            properties[name] = item.attrib.get("value", "")
        name = case.attrib["name"]
        if name.startswith("test_actual_windows_journal_overlap["):
            cell = name.removeprefix("test_actual_windows_journal_overlap[").removesuffix("]")
            if cell not in CELLS or cell in windows or "journal_lock_report" not in properties:
                raise RuntimeError("windows_cell_binding")
            windows[cell] = json.loads(properties["journal_lock_report"])
    skipped = sum(case.find("skipped") is not None for case in cases)
    failures = sum(case.find("failure") is not None or case.find("error") is not None for case in cases)
    if set(windows) != CELLS or skipped:
        raise RuntimeError("actual_windows_cells_missing")
    return {
        "total": len(cases),
        "failures_or_errors": failures,
        "skipped": skipped,
        "windows_cells": windows,
        "timing_qualification": False,
        "historical_journal_cause_established": False,
        "installed_artifact_qualification": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output: Path = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if os.name != "nt" or platform.python_version() != "3.12.10":
        raise RuntimeError("declared_windows_python_required")
    before = binding()
    write(output / "binding-before.json", before)
    scripts = Path(sys.executable).parent
    commands = [
        ([str(scripts / "ruff.exe"), "check", *FILES], "ruff.log"),
        ([str(scripts / "ruff.exe"), "format", "--check", *FILES], "format.log"),
        (
            [
                str(scripts / "basedpyright.exe"),
                "--pythonversion",
                "3.12",
                "--pythonplatform",
                "Windows",
                "--outputjson",
                *FILES,
            ],
            "types.json",
        ),
    ]
    status = 1
    try:
        for command, name in commands:
            code = attempt(command, output / name)
            if code:
                return code
        status = attempt(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/test_journal_lock_overlap.py",
                "-q",
                "--tb=short",
                f"--junitxml={output / 'controls.xml'}",
            ],
            output / "controls.log",
        )
        write(output / "original-control-exit.json", {"invocations": 1, "returncode": status})
        result = junit(output / "controls.xml")
        write(output / "result.json", result)
        if result["failures_or_errors"]:
            return status or 1
        return status
    finally:
        after = binding()
        write(output / "binding-after.json", after)
        write(output / "binding-comparison.json", {"equal": before == after})
        if before != after:
            raise RuntimeError("after_binding_mismatch")


if __name__ == "__main__":
    raise SystemExit(main())
