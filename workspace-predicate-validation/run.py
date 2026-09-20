"""Validate one exact installed first-admission-only predicate subset without repeating admitted source tests."""

from __future__ import annotations

import argparse
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, cast

from common import COMMANDS, digest, run, source_state, verify_files, write
from install import install

SOURCE_SHA = "e44008445630aad28ccc291ec234f55a14892e6d"
SOURCE_TREE = "addf0c1daf8ceb6313d6805ee4d05e216d6fdac8"


def reader_controls(python: Path, source: Path, driver: Path, output: Path, expected: list[str]) -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(driver), str(source)))
    arguments = [
        str(python),
        "-m",
        "pytest",
        "--noconftest",
        "--import-mode=importlib",
        "-p",
        "no:cacheprovider",
        "-o",
        "addopts=",
        str(driver / "reader_controls"),
    ]
    run("reader-collect", [*arguments, "--collect-only", "-q"], cwd=driver, output=output, environment=environment)
    collected = [
        line.strip()
        for line in (output / "commands/reader-collect.stdout").read_text().splitlines()
        if line.startswith("reader_controls/") and "::" in line
    ]
    if not expected or len(set(expected)) != len(expected) or collected != expected:
        raise RuntimeError("reader_collection_identity")
    run(
        "reader-controls",
        [
            *arguments,
            "-q",
            "--tb=short",
            "-o",
            "junit_family=xunit2",
            "--junitxml",
            str(output / "reader-controls.xml"),
        ],
        cwd=driver,
        output=output,
        environment=environment,
    )
    cases = list(ET.parse(output / "reader-controls.xml").getroot().iter("testcase"))
    actual = [case.attrib["classname"].replace(".", "/") + ".py::" + case.attrib["name"] for case in cases]
    if actual != expected or any(list(case.iter(kind)) for case in cases for kind in ("failure", "error", "skipped")):
        raise RuntimeError("reader_execution_identity_or_outcome")
    write(
        output / "reader-controls-result.json",
        {"collected": collected, "executed": actual, "passed": len(cases), "skipped": 0},
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--driver-sha", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, root = args.source.resolve(strict=True), args.driver.resolve(strict=True)
    driver = root / "workspace-predicate-validation"
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (output / "commands").mkdir(mode=0o700)
    manifest_path = driver / "MANIFEST.json"
    if digest(manifest_path)["sha256"] != args.manifest_sha256:
        raise RuntimeError("manifest_identity")
    manifest = json.loads(manifest_path.read_text())
    before = {
        "source": source_state(source, SOURCE_SHA, SOURCE_TREE),
        "driver": source_state(root, args.driver_sha),
        "files": verify_files(root, manifest["driver_files"]),
        "source_files": verify_files(source, manifest["source_files"]),
    }
    write(output / "binding-before.json", before)
    failure, code, preserved = None, None, False
    original_calls = 0
    installed_before: dict[str, Any] | None = None
    python: Path | None = None
    try:
        # Source-control receipts are already admitted on these exact bytes.
        # The manifest binds their original JUnit and source-composition proof.
        write(output / "reused-source-controls.json", manifest["reused_source_controls"])
        python, _expected = install(source, args.archive, manifest["retained_wheel"], output)
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        paths = [str(root / row["path"]) for row in manifest["driver_files"] if row["path"].endswith(".py")]
        for name, command in (
            (
                "ruff",
                [str(python), "-m", "ruff", "check", "--no-cache", "--config", str(source / "pyproject.toml"), *paths],
            ),
            (
                "format",
                [
                    str(python),
                    "-m",
                    "ruff",
                    "format",
                    "--check",
                    "--no-cache",
                    "--config",
                    str(source / "pyproject.toml"),
                    *paths,
                ],
            ),
            (
                "types",
                [
                    str(source / ".venv/bin/basedpyright"),
                    "--pythonpath",
                    str(python),
                    "--pythonversion",
                    "3.12",
                    *paths,
                ],
            ),
        ):
            run(
                name,
                command,
                cwd=driver,
                output=output,
                environment={**environment, "PYTHONPATH": os.pathsep.join((str(driver), str(source)))},
            )
        reader_controls(python, source, driver, output, manifest["expected_reader_nodes"])
        identity_command = [
            str(python),
            "-I",
            str(driver / "install.py"),
            "--source",
            str(source),
            "--expected",
            str(output / "expected-installed.json"),
        ]
        run(
            "installed-before",
            [*identity_command, "--output", str(output / "installed-before.json")],
            cwd=driver,
            output=output,
            environment=environment,
        )
        installed_before = cast(dict[str, Any], json.loads((output / "installed-before.json").read_text()))
        runtime = source / installed_before["runtime_relative"]
        original_calls += 1
        code = run(
            "original-first-admission",
            [
                str(python),
                str(driver / "workload.py"),
                "--source",
                str(source),
                "--runtime",
                str(runtime),
                "--output",
                str(output),
            ],
            cwd=source,
            output=output,
            environment=environment,
            timeout=300,
            require_success=False,
        )
        run(
            "admit-original",
            [
                str(python),
                str(driver / "read_result.py"),
                "--source",
                str(source),
                "--output",
                str(output),
                "--returncode",
                str(code),
            ],
            cwd=driver,
            output=output,
            environment=environment,
        )
    except BaseException as error:
        failure = {"type": type(error).__name__, "stage": COMMANDS[-1]["name"] if COMMANDS else "preparation"}
    finally:
        try:
            if python is not None and installed_before is not None:
                run(
                    "installed-after",
                    [
                        str(python),
                        "-I",
                        str(driver / "install.py"),
                        "--source",
                        str(source),
                        "--expected",
                        str(output / "expected-installed.json"),
                        "--output",
                        str(output / "installed-after.json"),
                    ],
                    cwd=driver,
                    output=output,
                )
                if json.loads((output / "installed-after.json").read_text()) != installed_before:
                    raise RuntimeError("installed_identity_changed")
            after = {
                "source": source_state(source, SOURCE_SHA, SOURCE_TREE),
                "driver": source_state(root, args.driver_sha),
                "files": verify_files(root, manifest["driver_files"]),
                "source_files": verify_files(source, manifest["source_files"]),
            }
            write(output / "binding-after.json", after)
            preserved = before == after and installed_before is not None
        except Exception:
            preserved = False
        write(
            output / "validation-result.json",
            {
                "schema": "hol-guard.current-workspace-predicate-validation.v1",
                "source_sha": SOURCE_SHA,
                "source_tree": SOURCE_TREE,
                "driver_sha": args.driver_sha,
                "failure": failure,
                "original_command_attempts": original_calls,
                "original_exit": code,
                "source_driver_installed_preserved": preserved,
                "passed": failure is None and preserved,
                "commands": COMMANDS,
                "original_readiness_ms": 400,
                "original_full_matrix_passed": False,
                "headline_timing_eligible": False,
                "qualification_complete": False,
                "workload_retries": 0,
            },
        )
    return 0 if failure is None and preserved else 1


if __name__ == "__main__":
    raise SystemExit(main())
