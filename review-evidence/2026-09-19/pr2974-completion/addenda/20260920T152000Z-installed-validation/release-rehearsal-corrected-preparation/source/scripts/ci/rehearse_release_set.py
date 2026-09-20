"""Run a source-bound local six-file rehearsal without publication or signing."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from pathlib import Path
from typing import Any, cast

from scripts.ci.aggregate_native_wheel_artifacts import aggregate_artifacts
from scripts.ci.release_rehearsal_inputs import (
    bound_file,
    digest,
    git,
    read_bound_json,
    source_binding,
    unpack_artifacts,
    verify_driver,
    verify_lock,
)
from scripts.ci.release_rehearsal_process import run
from scripts.ci.release_rehearsal_sdist import compare_wheels, inspect_sdist
from scripts.ci.validate_release_artifacts import EXPECTED_PLATFORMS, validate_wheel_set
from scripts.verify_native_runtime_release import local_guard_hashes

ENVIRONMENT_IDENTITY = """
import hashlib, importlib.metadata, json, pathlib, re, sys
lock = json.loads(pathlib.Path(sys.argv[1]).read_text())
expected = {r['name']: r['version'] for r in lock['wheels']}
root = pathlib.Path(sys.prefix).resolve()
assert sys.prefix != sys.base_prefix
records = []
for distribution in importlib.metadata.distributions():
    name = re.sub(r'[-_.]+', '-', distribution.metadata['Name']).lower()
    assert name == 'pip' or (name in expected and distribution.version == expected[name]), name
    files = []
    for member in distribution.files or []:
        path = pathlib.Path(distribution.locate_file(member)).resolve()
        assert path.is_relative_to(root) and path.is_file(), str(member)
        if path.suffix == '.pyc':
            continue
        body = path.read_bytes()
        files.append({'path': str(path.relative_to(root)), 'bytes': len(body),
                      'sha256': hashlib.sha256(body).hexdigest()})
    record = {'name': name, 'version': distribution.version, 'installed_files': files}
    if name == 'pip':
        bootstrap = record
    else:
        records.append(record)
assert {r['name'] for r in records} == set(expected)
print(json.dumps({'executable': sys.executable, 'prefix': sys.prefix, 'base_prefix': sys.base_prefix,
                  'executable_sha256': hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
                  'bootstrap_installer': bootstrap, 'packages': records}, sort_keys=True))
"""


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def execute(contract: dict[str, Any], work: Path, repo: Path) -> dict[str, Any]:
    if contract.get("ready_for_execution") is not True:
        raise ValueError("rehearsal input contract is not admitted for execution")
    if platform.system() != "Linux" or platform.python_version() != contract["python_version"]:
        raise ValueError("rehearsal requires the exact bound Linux interpreter")
    source = contract["source"]
    binding = source_binding(repo, source)
    verify_driver(repo, contract["driver_files"], source["build_sha"])
    locks = {}
    for label in ("build", "metadata"):
        entry = contract[f"{label}_environment"]
        lock = read_bound_json(Path(entry["manifest"]), entry["manifest_sha256"])
        if digest(Path(entry["requirements"])) != lock["requirements_sha256"]:
            raise ValueError("build requirements lock mismatch")
        verify_lock(Path(entry["wheelhouse"]), lock)
        locks[label] = lock
    versions = {row["name"]: row["version"] for row in locks["build"]["wheels"]}
    if versions.get("hatchling") != "1.30.1" or versions.get("build") != "1.5.0":
        raise ValueError("reviewed backend/frontend identity mismatch")
    for row in contract["archives"]:
        if row["build_sha"] != source["build_sha"] or row["product_sha"] != source["product_sha"]:
            raise ValueError("archive/source contract mismatch")
    work.mkdir(exist_ok=False)
    report: dict[str, Any] = {
        "schema": "hol-guard-six-file-rehearsal.v1",
        "passed": False,
        "source": binding,
        "stages": {},
        "qualification_complete": False,
        "signing_executed": False,
        "publication_executed": False,
        "installed_transitions_executed": False,
        "canary_executed": False,
    }
    stages = report["stages"]
    try:
        stages["archives"] = unpack_artifacts(contract["archives"], work / "artifacts")
        admission = aggregate_artifacts(
            work / "artifacts",
            version=source["version"],
            source_sha=source["build_sha"],
            rule_digest=source["rule_digest"],
        )
        stages["four_platform_admission"] = admission
        dist = work / "dist"
        dist.mkdir()
        for row in cast(list[dict[str, Any]], admission["collected"]):
            if not row["identical_duplicate"]:
                origin = work / "artifacts" / row["artifact"] / row["member"]
                destination = dist / origin.name
                shutil.copyfile(origin, destination)
                bound_file(destination, row)
        for label in ("first", "second", "metadata"):
            environment = contract["metadata_environment" if label == "metadata" else "build_environment"]
            venv = work / f"{label}-venv"
            run([sys.executable, "-m", "venv", str(venv)], cwd=work, output=work / f"{label}-venv-create")
            python = venv / "bin/python"
            run(
                [
                    str(python),
                    "-m",
                    "pip",
                    "install",
                    "--no-index",
                    "--require-hashes",
                    "--only-binary=:all:",
                    "--find-links",
                    environment["wheelhouse"],
                    "-r",
                    environment["requirements"],
                ],
                cwd=work,
                output=work / f"{label}-install",
            )
            run(
                [
                    str(python),
                    "-c",
                    ENVIRONMENT_IDENTITY,
                    environment["manifest"],
                ],
                cwd=work,
                output=work / f"{label}-identity",
            )
            if label == "metadata":
                continue
            checkout = work / f"{label}-source"
            run(
                ["git", "clone", "--shared", "--no-checkout", str(repo), str(checkout)],
                cwd=work,
                output=work / f"{label}-clone",
            )
            run(
                ["git", "-C", str(checkout), "checkout", "--detach", source["build_sha"]],
                cwd=work,
                output=work / f"{label}-checkout",
            )
            if git(checkout, "status", "--porcelain", "--untracked-files=all"):
                raise ValueError("build source is not clean")
            stages[f"{label}_source_before"] = source_binding(checkout, source)
            output = work / f"{label}-dist"
            run(
                [str(python), "-m", "build", "--sdist", "--no-isolation", "--outdir", str(output)],
                cwd=checkout,
                output=work / f"{label}-sdist",
            )
            expected = f"hol_guard-{source['version']}.tar.gz"
            if {p.name for p in output.iterdir()} != {expected}:
                raise ValueError("sdist output membership mismatch")
            stages[f"{label}_sdist"] = inspect_sdist(output / expected, checkout, source["version"])
            if git(checkout, "status", "--porcelain", "--untracked-files=all"):
                raise ValueError("source changed during build")
            stages[f"{label}_source_after"] = source_binding(checkout, source)
        first = work / "first-dist" / f"hol_guard-{source['version']}.tar.gz"
        second = work / "second-dist" / first.name
        stages["sdist_bytes_equal"] = first.read_bytes() == second.read_bytes()
        if not stages["sdist_bytes_equal"]:
            raise ValueError("independent source distributions differ")
        extracted = work / "sdist-source"
        inspect_sdist(first, work / "first-source", source["version"], extracted)
        run(
            [
                str(work / "first-venv/bin/python"),
                "-m",
                "build",
                "--wheel",
                "--no-isolation",
                "--outdir",
                str(work / "rebuilt-wheel"),
            ],
            cwd=extracted,
            output=work / "sdist-wheel",
        )
        pure_name = f"hol_guard-{source['version']}-py3-none-any.whl"
        if {p.name for p in (work / "rebuilt-wheel").iterdir()} != {pure_name}:
            raise ValueError("rebuilt wheel membership mismatch")
        stages["pure_wheel_comparison"] = compare_wheels(dist / pure_name, work / "rebuilt-wheel" / pure_name)
        shutil.copyfile(first, dist / first.name)
        expected = {pure_name, first.name} | {
            f"hol_guard-{source['version']}-py3-none-{p}.whl" for p in EXPECTED_PLATFORMS
        }
        if {p.name for p in dist.iterdir()} != expected:
            raise ValueError("six-file membership mismatch")
        stages["full_set_hashes"] = local_guard_hashes(dist, version=source["version"], source_sha=source["build_sha"])
        stages["four_platform_validation"] = validate_wheel_set(
            dist,
            version=source["version"],
            source_sha=source["build_sha"],
            rule_digest=source["rule_digest"],
            platforms=tuple(sorted(EXPECTED_PLATFORMS)),
        )
        run(
            [
                str(work / "metadata-venv/bin/python"),
                "-m",
                "twine",
                "check",
                "--strict",
                *(str(path) for path in sorted(dist.iterdir())),
            ],
            cwd=work,
            output=work / "twine-check",
        )
        for label in ("build", "metadata"):
            entry = contract[f"{label}_environment"]
            verify_lock(Path(entry["wheelhouse"]), locks[label])
            if digest(Path(entry["requirements"])) != locks[label]["requirements_sha256"]:
                raise ValueError("requirements lock changed during rehearsal")
            read_bound_json(Path(entry["manifest"]), entry["manifest_sha256"])
        for row in contract["archives"]:
            bound_file(Path(row["path"]), row)
        verify_driver(repo, contract["driver_files"], source["build_sha"])
        stages["source_after"] = source_binding(repo, source)
        if not stages["pure_wheel_comparison"]["bytes_equal"]:
            raise ValueError("retained and sdist-rebuilt pure wheel bytes differ; preserved for inspection")
        report["passed"] = True
    except (OSError, ValueError, RuntimeError) as error:
        report["failure"] = f"{type(error).__name__}: {error}"
    finally:
        write(work / "result.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    contract = read_bound_json(args.contract, args.contract_sha256)
    result = execute(contract, args.work.absolute(), Path(__file__).resolve().parents[2])
    print(json.dumps({key: value for key, value in result.items() if key != "stages"}, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
