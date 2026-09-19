"""Read one existing Actions artifact and extract only its bound Linux wheel.

The GitHub token is attached only to api.github.com requests. Signed storage
redirects are fetched without Authorization, and no URL, header, response body,
or credential value is logged. The original archive digest is checked before
ZIP parsing. No native executable or package source is imported or executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

REPOSITORY = "hashgraph-online/hol-guard"
REPOSITORY_ID = 1194748811
ARTIFACT_ID = 10573761511
PRODUCER_RUN_ID = 35409046665
ARTIFACT_NAME = "hol-guard-native-wheel-linux-x64"
ARCHIVE_BYTES = 13361896
ARCHIVE_SHA = "857e3701e64130d078b4483a7d5b3dc8267a6ae9e348ef1322c28f6810f8f14c"
SOURCE_SHA = "8156ba5ec1e69908290d481bad421ba5f9bd93b2"
BUILD_SHA = "c331bb1ac5d9ee2082ea379713490b5b6d41e782"
SOURCE_TREE = "1c551084cffda3f73ec410b432f0455579502754"
WHEEL_NAME = "hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl"
WHEEL_MEMBER = "native-dist/" + WHEEL_NAME
WHEEL_BYTES = 8728320
WHEEL_SHA = "7b82fa210d88b2e4be3f21791101a9a0d378cd7df29205ee13fe024388c97bc8"
RUNTIME_MEMBER = "codex_plugin_scanner/_native/hol-guard-runtime"
RUNTIME_BYTES = 12400288
RUNTIME_SHA = "679da56f12eca504da0e3bc65b9abb99b1109e4caab2deb6961283865db9b2ba"
MANIFEST_MEMBER = "codex_plugin_scanner/_native/runtime-manifest.json"
MANIFEST_SHA = "fa20cf9b73c6d7b695ab6f4c8888153f83f3451a6f0190c03fa5175a12c78b12"


class BindingError(RuntimeError):
    """Fixed privacy-safe failure code."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise BindingError(code)


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode(content: bytes) -> Any:
    return json.loads(content, object_pairs_hook=strict_object)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def api_request(path: str, token: str) -> Any:
    request = urllib.request.Request(
        "https://api.github.com/repos/" + REPOSITORY + path,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "hol-guard-bound-lifecycle-diagnostic",
        },
    )
    return urllib.request.build_opener(NoRedirect()).open(request, timeout=30)


def api_json(path: str, token: str) -> dict[str, Any]:
    with api_request(path, token) as response:
        content = response.read(1024 * 1024 + 1)
    require(0 < len(content) <= 1024 * 1024, "github_metadata_size")
    value = decode(content)
    require(type(value) is dict, "github_metadata_shape")
    return value


def verify_metadata(artifact: dict[str, Any], build: dict[str, Any]) -> None:
    require(artifact.get("id") == ARTIFACT_ID and artifact.get("name") == ARTIFACT_NAME, "artifact_identity")
    require(
        artifact.get("size_in_bytes") == ARCHIVE_BYTES
        and artifact.get("expired") is False
        and artifact.get("digest") == "sha256:" + ARCHIVE_SHA,
        "artifact_digest_metadata",
    )
    run = artifact.get("workflow_run")
    require(
        type(run) is dict
        and run.get("id") == PRODUCER_RUN_ID
        and run.get("head_sha") == SOURCE_SHA
        and run.get("repository_id") == REPOSITORY_ID
        and run.get("head_repository_id") == REPOSITORY_ID,
        "artifact_producer_identity",
    )
    require(
        build.get("sha") == BUILD_SHA and build.get("tree", {}).get("sha") == SOURCE_TREE, "build_source_tree_binding"
    )


def download_archive(token: str, destination: Path) -> None:
    try:
        with api_request(f"/actions/artifacts/{ARTIFACT_ID}/zip", token):
            raise BindingError("github_archive_redirect_missing")
    except urllib.error.HTTPError as error:
        require(error.code == 302, "github_archive_redirect_status")
        location = error.headers.get("Location")
    require(isinstance(location, str), "github_archive_redirect_location")
    parsed = urllib.parse.urlsplit(location)
    hostname = parsed.hostname or ""
    require(
        parsed.scheme == "https"
        and parsed.port in (None, 443)
        and parsed.username is None
        and parsed.password is None
        and (hostname.endswith(".blob.core.windows.net") or hostname.endswith(".githubusercontent.com")),
        "github_archive_storage_origin",
    )
    # A distinct unauthenticated request prevents token propagation across hosts.
    request = urllib.request.Request(location, headers={"User-Agent": "hol-guard-bound-lifecycle-diagnostic"})
    total = 0
    with (
        urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response,
        destination.open("xb") as output,
    ):
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            require(total <= ARCHIVE_BYTES, "archive_size_exceeded")
            output.write(chunk)
    require(total == ARCHIVE_BYTES and sha256(destination) == ARCHIVE_SHA, "archive_bytes_binding")


def bound_member(archive: zipfile.ZipFile, member: str, expected_size: int, expected_sha: str) -> bytes:
    require(archive.namelist().count(member) == 1, "archive_member_uniqueness")
    info = archive.getinfo(member)
    require(
        not info.is_dir() and not stat.S_ISLNK(info.external_attr >> 16) and info.file_size == expected_size,
        "archive_member_shape",
    )
    with archive.open(info) as handle:
        content = handle.read(expected_size + 1)
    require(
        len(content) == expected_size and hashlib.sha256(content).hexdigest() == expected_sha,
        "archive_member_bytes_binding",
    )
    return content


def verify_archive(archive_path: Path, output_directory: Path, source_root: Path) -> dict[str, Any]:
    require(
        archive_path.stat().st_size == ARCHIVE_BYTES and sha256(archive_path) == ARCHIVE_SHA, "archive_bytes_binding"
    )
    head = subprocess.check_output(["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(["git", "-C", str(source_root), "rev-parse", "HEAD^{tree}"], text=True).strip()
    require(head == SOURCE_SHA and tree == SOURCE_TREE, "source_checkout_binding")
    with zipfile.ZipFile(archive_path) as archive:
        content = bound_member(archive, WHEEL_MEMBER, WHEEL_BYTES, WHEEL_SHA)
    wheel_path = output_directory / WHEEL_NAME
    with wheel_path.open("xb") as output:
        output.write(content)
    sources = []
    with zipfile.ZipFile(wheel_path) as wheel:
        bound_member(wheel, RUNTIME_MEMBER, RUNTIME_BYTES, RUNTIME_SHA)
        require(wheel.namelist().count(MANIFEST_MEMBER) == 1, "manifest_uniqueness")
        info = wheel.getinfo(MANIFEST_MEMBER)
        require(0 < info.file_size <= 16384, "manifest_size")
        manifest_bytes = bound_member(wheel, MANIFEST_MEMBER, info.file_size, MANIFEST_SHA)
        manifest = decode(manifest_bytes)
        require(
            manifest.get("source_sha") == BUILD_SHA
            and manifest.get("runtime_sha256") == RUNTIME_SHA
            and manifest.get("runtime_size") == RUNTIME_BYTES
            and manifest.get("protocol_version") == 1
            and manifest.get("package_version") == "3.0.1",
            "native_manifest_binding",
        )
        for member in sorted(wheel.namelist()):
            if not member.startswith("codex_plugin_scanner/") or not member.endswith(".py"):
                continue
            relative = Path(member)
            require(not relative.is_absolute() and ".." not in relative.parts, "python_source_member_path")
            source = (source_root / "src" / relative).resolve()
            require(
                source.is_relative_to((source_root / "src").resolve()) and source.is_file(),
                "python_source_path_binding",
            )
            data = wheel.read(member)
            require(source.read_bytes() == data, "python_source_bytes_binding")
            sources.append(
                {"path": str(Path("src") / relative), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            )
    require(len(sources) > 1000, "python_source_inventory_incomplete")
    return {
        "archive_sha256": ARCHIVE_SHA,
        "archive_bytes": ARCHIVE_BYTES,
        "wheel_sha256": WHEEL_SHA,
        "wheel_bytes": WHEEL_BYTES,
        "wheel_basename": WHEEL_NAME,
        "source_sha": SOURCE_SHA,
        "build_sha": BUILD_SHA,
        "source_tree": SOURCE_TREE,
        "runtime_sha256": RUNTIME_SHA,
        "runtime_bytes": RUNTIME_BYTES,
        "manifest_sha256": MANIFEST_SHA,
        "python_sources": sources,
        "python_source_count": len(sources),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    result: dict[str, Any] = {
        "schema": "bound-existing-linux-artifact.v1",
        "result": "failed",
        "repository": REPOSITORY,
        "artifact_id": ARTIFACT_ID,
        "producer_run_id": PRODUCER_RUN_ID,
        "native_execution_performed": False,
        "guard_source_imported": False,
    }
    try:
        require(not args.receipt.exists(), "binding_receipt_exists")
        require(not args.output_directory.exists(), "download_directory_exists")
        args.output_directory.mkdir(mode=0o700)
        token = os.environ.get("GH_TOKEN")
        require(bool(token), "github_read_token_missing")
        artifact = api_json(f"/actions/artifacts/{ARTIFACT_ID}", token)
        build = api_json(f"/git/commits/{BUILD_SHA}", token)
        verify_metadata(artifact, build)
        archive_path = args.output_directory / "bound-artifact.zip"
        download_archive(token, archive_path)
        token = None
        result.update(verify_archive(archive_path, args.output_directory, args.source_root))
        result["result"] = "passed"
        result["artifact_digest_verified_before_zip_parsing"] = True
        result["authorization_sent_only_to_api_github_com"] = True
    except BaseException as error:
        result["failure_code"] = str(error) if isinstance(error, BindingError) else type(error).__name__
    with args.receipt.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    print(
        json.dumps(
            {
                "result": result["result"],
                "artifact_id": ARTIFACT_ID,
                "failure_code": result.get("failure_code"),
                "receipt_sha256": sha256(args.receipt),
            }
        )
    )
    return int(result["result"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
