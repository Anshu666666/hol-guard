"""Bind a separate Windows observer to one retained original CI wheel."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

import tomllib

SOURCE = "60bdeab2ac04ff6ba6e13778be7d6d1fc8e67773"
BUILD = "fe6879f2b9d6c65fdd57ef630a45379f9cb897ef"
TREE = "562dc2e59f2650f6e8bc999d5a945cd75bf7ab2e"
RUN_ID = 35418644989
JOB_ID = 105832041712
ARTIFACT_ID = 10576711059
ARCHIVE_BYTES = 8096166
ARCHIVE_SHA256 = "545d3013b56434fe0ff8f40533fa8cea2373a212a6e1bfa7fb0c42ffc9e9f3f0"
WHEEL_MEMBER = "native-dist/hol_guard-3.0.1-py3-none-win_amd64.whl"
WHEEL_SHA256 = "a3c53c7116520e7bfee7db97b6fe1a6901b74e1df964fdb253cd4eeaa9257fcb"
PACKAGE_SHA256 = "710eb73775ce407997f48fb17c52ac16f4ac6d4d47cff47c6b6836a192c04ca4"
RUNTIME_SHA256 = "772eb948dba37c97d269efcbaba42e824022e08813328ba89eb147ce9268dfb0"
MANIFEST_SHA256 = "ea7c02e8f7f8f4b683e0589839f1e79271f5eff4796ea07060a00d6a3a56e698"
PREFIX = "codex_plugin_scanner/"
MAX_MEMBER_BYTES = 64 * 1024 * 1024


class BindingError(RuntimeError):
    """Fixed admission codes contain no payloads, credentials or paths."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise BindingError(code)


def sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.exists(), "evidence_already_exists")
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def git(root: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "--no-lazy-fetch", "-C", str(root), *arguments], timeout=60)


def checkout_inventory(root: Path, expected_commit: str, expected_tree: str | None = None) -> dict[str, str]:
    require(git(root, "rev-parse", "HEAD").decode().strip() == expected_commit, "checkout_commit")
    require(not git(root, "ls-files", "--others", "--exclude-standard"), "checkout_untracked")
    if expected_tree is not None:
        require(git(root, "rev-parse", "HEAD^{tree}").decode().strip() == expected_tree, "checkout_tree")
    inventory = {}
    for entry in git(root, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not entry:
            continue
        metadata, raw_name = entry.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        require(kind == b"blob" and mode in (b"100644", b"100755"), "checkout_entry")
        name = raw_name.decode()
        path = root / name
        require(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()), "checkout_path")
        content = path.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content, usedforsecurity=False).hexdigest()
        require(blob == oid.decode(), "checkout_bytes")
        inventory[name] = sha(content)
    require(bool(inventory), "checkout_empty")
    return inventory


def safe_members(archive: zipfile.ZipFile) -> list[str]:
    infos = archive.infolist()
    names = [info.filename for info in infos if not info.is_dir()]
    require(len(names) == len(set(names)) and 0 < len(names) < 20000, "archive_members")
    require(sum(info.file_size for info in infos) < 256 * 1024 * 1024, "archive_expansion")
    for info in infos:
        path = PurePosixPath(info.filename)
        require(not path.is_absolute() and ".." not in path.parts and "\\" not in info.filename, "archive_path")
        require(info.file_size < MAX_MEMBER_BYTES, "archive_member_size")
    return names


def verify_metadata(metadata: dict[str, Any]) -> None:
    require(
        metadata["id"] == ARTIFACT_ID and metadata["name"] == "hol-guard-native-wheel-windows-x64", "artifact_identity"
    )
    require(
        metadata["size_in_bytes"] == ARCHIVE_BYTES and metadata["digest"] == "sha256:" + ARCHIVE_SHA256,
        "artifact_digest",
    )
    require(metadata["expired"] is False, "artifact_expired")
    require(
        metadata["workflow_run"]["id"] == RUN_ID and metadata["workflow_run"]["head_sha"] == SOURCE, "artifact_source"
    )


def verified_wheel(archive_path: Path) -> bytes:
    content = archive_path.read_bytes()
    require(len(content) == ARCHIVE_BYTES and sha(content) == ARCHIVE_SHA256, "archive_bytes")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        names = safe_members(archive)
        require([name for name in names if name.endswith(".whl")] == [WHEEL_MEMBER], "wheel_member")
        wheel = archive.read(WHEEL_MEMBER)
    require(sha(wheel) == WHEEL_SHA256, "wheel_bytes")
    return wheel


def package_map(wheel_bytes: bytes, source_root: Path) -> dict[str, str]:
    require(sha(wheel_bytes) == WHEEL_SHA256, "wheel_bytes")
    project = tomllib.loads((source_root / "pyproject.toml").read_text(encoding="utf-8"))
    includes = project["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    reverse = {destination: original for original, destination in includes.items()}
    require(len(reverse) == len(includes), "package_source_alias")
    result = {}
    with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as wheel:
        for name in sorted(safe_members(wheel)):
            if not name.startswith(PREFIX):
                continue
            content = wheel.read(name)
            if not name.startswith(PREFIX + "_native/"):
                original = source_root / reverse.get(name, "src/" + name)
                require(
                    content.replace(b"\r\n", b"\n") == original.read_bytes().replace(b"\r\n", b"\n"),
                    "package_source_bytes",
                )
            result[name] = sha(content)
    digest = hashlib.sha256()
    for name, value in result.items():
        digest.update(name.encode() + b"\0" + bytes.fromhex(value))
    require(len(result) == 1331 and digest.hexdigest() == PACKAGE_SHA256, "package_inventory")
    require(result[PREFIX + "_native/hol-guard-runtime.exe"] == RUNTIME_SHA256, "runtime_bytes")
    require(result[PREFIX + "_native/runtime-manifest.json"] == MANIFEST_SHA256, "runtime_manifest")
    return result


def installed_inventory(expected: dict[str, str]) -> tuple[Path, dict[str, str]]:
    distribution = importlib.metadata.distribution("hol-guard")
    direct_url = distribution.read_text("direct_url.json")
    require(
        direct_url is None or not json.loads(direct_url).get("dir_info", {}).get("editable", False), "editable_install"
    )
    root = Path(str(distribution.locate_file("codex_plugin_scanner"))).resolve()
    require(root.is_relative_to(Path(sys.prefix).resolve()) and "site-packages" in root.parts, "installed_origin")
    observed = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        require(not path.is_symlink() and path.resolve().is_relative_to(root), "installed_path")
        observed[PREFIX + path.relative_to(root).as_posix()] = sha(path.read_bytes())
    require(observed == expected, "installed_bytes")
    return root, observed


def gh_download(output: Path, evidence: Path) -> Path:
    require(not output.exists(), "download_already_exists")
    output.mkdir(parents=True)
    endpoint = f"repos/hashgraph-online/hol-guard/actions/artifacts/{ARTIFACT_ID}"
    metadata_call = subprocess.run(
        ["gh", "api", "--hostname", "github.com", endpoint], capture_output=True, timeout=60, check=False
    )
    require(metadata_call.returncode == 0 and len(metadata_call.stdout) < 1024 * 1024, "artifact_metadata_request")
    metadata = json.loads(metadata_call.stdout)
    dump(evidence / "original-artifact-metadata.json", metadata)
    verify_metadata(metadata)
    archive_path = output / f"{ARTIFACT_ID}.zip"
    exit_code = None
    failed = False
    invoked = False
    try:
        with archive_path.open("xb") as handle:
            invoked = True
            result = subprocess.run(
                ["gh", "api", "--hostname", "github.com", endpoint + "/zip"],
                stdout=handle,
                stderr=subprocess.PIPE,
                timeout=60,
                check=False,
            )
            exit_code = result.returncode
    except BaseException:
        failed = True
        raise
    finally:
        try:
            data = archive_path.read_bytes() if archive_path.exists() else b""
            dump(
                evidence / "artifact-download.json",
                {
                    "artifact_id": ARTIFACT_ID,
                    "gh_invocations_for_archive": int(invoked),
                    "gh_exit_code": exit_code,
                    "transfer_raised": failed,
                    "archive_bytes": len(data),
                    "archive_sha256": sha(data),
                    "signed_url_retained": False,
                    "automatic_http_retry_behavior_measured": False,
                    "workload_invocations": 0,
                },
            )
        except BaseException:
            if not failed:
                raise
            print("windows_storage_artifact_evidence_failed", file=sys.stderr)
    require(exit_code == 0, "artifact_download")
    wheel = verified_wheel(archive_path)
    wheel_path = output / PurePosixPath(WHEEL_MEMBER).name
    wheel_path.write_bytes(wheel)
    return wheel_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--driver-source", required=True, type=Path)
    parser.add_argument("--driver-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--download", required=True, type=Path)
    options = parser.parse_args()
    require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "original_workflow_attempt_required")
    before = checkout_inventory(options.source, SOURCE, TREE)
    driver = checkout_inventory(options.driver_source, options.driver_commit)
    dump(
        options.output / "source-binding.json",
        {
            "source": SOURCE,
            "build": BUILD,
            "tree": TREE,
            "source_files": before,
            "driver_commit": options.driver_commit,
            "driver_files": driver,
        },
    )
    wheel = gh_download(options.download, options.output)
    files = package_map(wheel.read_bytes(), options.source)
    require(checkout_inventory(options.source, SOURCE, TREE) == before, "source_changed")
    require(checkout_inventory(options.driver_source, options.driver_commit) == driver, "driver_changed")
    dump(
        options.output / "wheel-binding.json",
        {
            "wheel_sha256": WHEEL_SHA256,
            "package_sha256": PACKAGE_SHA256,
            "package_files": files,
            "runtime_sha256": RUNTIME_SHA256,
            "runtime_manifest_sha256": MANIFEST_SHA256,
            "source": SOURCE,
            "build": BUILD,
            "source_before_after_equal": True,
            "driver_before_after_equal": True,
            "downloaded_binary_executed": False,
        },
    )


if __name__ == "__main__":
    main()
