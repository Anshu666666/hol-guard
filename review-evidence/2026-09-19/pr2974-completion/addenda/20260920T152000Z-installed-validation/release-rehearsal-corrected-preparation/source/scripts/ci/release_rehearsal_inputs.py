"""Bind local rehearsal inputs before invoking any package build."""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import zipfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from scripts.ci.aggregate_native_wheel_artifacts import ARTIFACT_PLATFORMS

MAX_FILE = 256 * 1024 * 1024
MAX_EXPANDED = 1024 * 1024 * 1024


def digest(path: Path, maximum: int = MAX_FILE) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
        raise ValueError(f"not a bounded regular file: {path.name}")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def read_bound_json(path: Path, expected: str) -> dict[str, Any]:
    if digest(path, 4 * 1024 * 1024) != expected:
        raise ValueError(f"JSON input digest mismatch: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("input must be a JSON object")
    return value


def bound_file(path: Path, record: Mapping[str, Any]) -> None:
    if digest(path) != record["sha256"] or path.stat().st_size != record["bytes"]:
        raise ValueError(f"input file identity mismatch: {path.name}")


def git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments], capture_output=True, text=True, check=True, timeout=30
    ).stdout.strip()


def source_binding(repo: Path, source: Mapping[str, Any]) -> dict[str, Any]:
    product, build, tree = (source[name] for name in ("product_sha", "build_sha", "tree"))
    for name, commit in (("product", product), ("build", build)):
        if git(repo, "rev-parse", f"{commit}^{{tree}}") != tree:
            raise ValueError(f"{name} source tree mismatch")
    pyproject = git(repo, "show", f"{build}:pyproject.toml")
    import tomllib

    project = tomllib.loads(pyproject)["project"]
    if project["name"] != "hol-guard" or project["version"] != source["version"]:
        raise ValueError("source package/version mismatch")
    comparison = source.get("provider_comparison")
    difference: list[str] = []
    if comparison:
        difference = git(repo, "diff", "--name-only", comparison["older_sha"], product).splitlines()
        if sorted(difference) != sorted(comparison["test_only_paths"]) or any(
            not name.startswith("tests/") for name in difference
        ):
            raise ValueError("provider comparison includes a non-admitted source change")
    return {
        "product_sha": product,
        "build_sha": build,
        "tree": tree,
        "version": project["version"],
        "provider_comparison_paths": difference,
    }


def verify_lock(directory: Path, lock: Mapping[str, Any]) -> None:
    wheels = lock["wheels"]
    if {entry.name for entry in directory.iterdir()} != {row["filename"] for row in wheels}:
        raise ValueError("wheelhouse membership mismatch")
    if len({row["name"] for row in wheels}) != len(wheels):
        raise ValueError("duplicate build dependency")
    for row in wheels:
        if Path(row["filename"]).name != row["filename"]:
            raise ValueError("wheelhouse path is not a basename")
        bound_file(directory / row["filename"], row)


def verify_driver(repo: Path, rows: list[dict[str, Any]], build_sha: str) -> None:
    for row in rows:
        bound_file(repo / row["path"], row)
        if "git_blob" in row and (
            git(repo, "rev-parse", f"{build_sha}:{row['path']}") != row["git_blob"]
            or git(repo, "hash-object", str(repo / row["path"])) != row["git_blob"]
        ):
            raise ValueError("existing verifier differs from the artifact build source")


def unpack_artifacts(records: list[dict[str, Any]], output: Path) -> list[dict[str, Any]]:
    if len(records) != 4 or {row["name"] for row in records} != set(ARTIFACT_PLATFORMS):
        raise ValueError("exactly four coherent matrix archives are required")
    if len({(row["run_id"], row["build_sha"], row["product_sha"]) for row in records}) != 1:
        raise ValueError("mixed artifact source/run cohort")
    for row in records:
        bound_file(Path(row["path"]), row)
    output.mkdir(exist_ok=False)
    receipt: list[dict[str, Any]] = []
    for row in records:
        target = output / row["name"]
        target.mkdir()
        members: list[dict[str, Any]] = []
        with zipfile.ZipFile(row["path"]) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if len(infos) > 64 or len(names) != len(set(names)):
                raise ValueError("artifact duplicate/excessive members")
            if sum(item.file_size for item in infos) > MAX_EXPANDED:
                raise ValueError("artifact expanded-size bound exceeded")
            for item in infos:
                name = PurePosixPath(item.filename)
                mode = item.external_attr >> 16
                if (
                    name.is_absolute()
                    or ".." in name.parts
                    or "\\" in item.filename
                    or item.flag_bits & 1
                    or stat.S_ISLNK(mode)
                ):
                    raise ValueError("unsafe artifact member")
                if item.is_dir():
                    continue
                if not 0 < item.file_size <= MAX_FILE:
                    raise ValueError("artifact member size bound exceeded")
                destination = target.joinpath(*name.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(item) as incoming, destination.open("xb") as outgoing:
                    total = 0
                    while block := incoming.read(1024 * 1024):
                        total += len(block)
                        if total > item.file_size:
                            raise ValueError("artifact member exceeded declared size")
                        outgoing.write(block)
                if total != item.file_size:
                    raise ValueError("artifact member size mismatch")
                members.append({"path": item.filename, "bytes": total, "sha256": digest(destination)})
        bound_file(Path(row["path"]), row)
        receipt.append({**row, "members": members})
    return receipt
