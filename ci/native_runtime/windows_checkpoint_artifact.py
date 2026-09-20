"""Download only the pinned original Windows wheel artifact, without auth redirects."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ARTIFACT_ID = 10599457190
RUN_ID = 35492742680
HEAD_SHA = "4d10758e2cb44e5afa72a08aa631a02541dad534"
ZIP_BYTES = 8233778
ZIP_SHA256 = "c978177b8bbcfbfeee7d9a7171722b27b7d7e20d3659b3f779be707c9b2f59d7"
REPOSITORY = "hashgraph-online/hol-guard"
WHEEL_NAME = "hol_guard-3.0.1-py3-none-win_amd64.whl"
EXPECTED_NAMES = frozenset(
    {
        WHEEL_NAME,
        "native-default-auto.json",
        "native-installed-identity.json",
        "native-installed-control-lock.json",
    }
)
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_UNPACKED_BYTES = 64 * 1024 * 1024
DOWNLOAD_SECONDS = 90


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        del request, response, code, message, headers, new_url
        return None


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeError(code)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bounded_read(response, maximum: int, deadline: float) -> bytes:
    chunks = []
    count = 0
    while True:
        require(time.monotonic() < deadline, "artifact_download_deadline")
        block = response.read(min(65536, maximum + 1 - count))
        if not block:
            return b"".join(chunks)
        chunks.append(block)
        count += len(block)
        require(count <= maximum, "artifact_download_size")


def request_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hol-guard-pinned-artifact-diagnostic",
    }


def fetch_original_archive(token: str) -> tuple[bytes, dict[str, object]]:
    deadline = time.monotonic() + DOWNLOAD_SECONDS
    opener = urllib.request.build_opener(NoRedirect())
    api = f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{ARTIFACT_ID}"
    request = urllib.request.Request(api, headers=request_headers(token))
    with opener.open(request, timeout=10) as response:
        metadata_bytes = bounded_read(response, 65536, deadline)
    metadata = json.loads(metadata_bytes)
    require(metadata["id"] == ARTIFACT_ID and metadata["size_in_bytes"] == ZIP_BYTES, "artifact_metadata_identity")
    require(metadata["digest"] == "sha256:" + ZIP_SHA256, "artifact_metadata_digest")
    require(metadata["expired"] is False, "artifact_expired")
    require(
        metadata["workflow_run"]["id"] == RUN_ID and metadata["workflow_run"]["head_sha"] == HEAD_SHA,
        "artifact_original_run_mismatch",
    )
    download = urllib.request.Request(api + "/zip", headers=request_headers(token))
    try:
        response = opener.open(download, timeout=10)
    except urllib.error.HTTPError as error:
        require(error.code == 302, "artifact_redirect_status")
        location = error.headers.get("Location")
        error.close()
    else:
        response.close()
        raise RuntimeError("artifact_redirect_missing")
    require(type(location) is str, "artifact_redirect_location")
    parsed = urllib.parse.urlsplit(location)
    hostname = parsed.hostname
    require(
        parsed.scheme == "https"
        and parsed.username is None
        and parsed.password is None
        and parsed.port in {None, 443}
        and type(hostname) is str
        and (hostname.endswith(".blob.core.windows.net") or hostname.endswith(".actions.githubusercontent.com")),
        "artifact_storage_origin",
    )
    # This new request has no Authorization header; the opener follows no redirects.
    signed_request = urllib.request.Request(location)
    require(not signed_request.has_header("Authorization"), "artifact_auth_forwarding")
    with opener.open(signed_request, timeout=10) as response:
        archive = bounded_read(response, MAX_ARCHIVE_BYTES, deadline)
    require(len(archive) == ZIP_BYTES and sha256(archive) == ZIP_SHA256, "artifact_archive_digest")
    return archive, {
        "artifact_id": ARTIFACT_ID,
        "run_id": RUN_ID,
        "source_head": HEAD_SHA,
        "zip_bytes": len(archive),
        "zip_sha256": sha256(archive),
        "authenticated_redirects_followed": False,
        "storage_request_authorization_header": False,
        "api_metadata_sha256": sha256(metadata_bytes),
    }


def extract_original_files(archive: bytes, destination: Path) -> list[dict[str, object]]:
    require(len(archive) == ZIP_BYTES and sha256(archive) == ZIP_SHA256, "artifact_archive_digest")
    members = []
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        entries = zipped.infolist()
        require(len(entries) == 4, "artifact_member_count")
        total = 0
        seen = set()
        for entry in entries:
            name = entry.filename
            require("\\" not in name and "\x00" not in name, "artifact_member_name")
            relative = Path(name)
            require(not relative.is_absolute() and ".." not in relative.parts, "artifact_member_path")
            basename = relative.name
            require(basename in EXPECTED_NAMES and basename not in seen, "artifact_member_identity")
            allowed = {basename}
            if basename == WHEEL_NAME:
                allowed.add("native-dist/" + basename)
            require(name in allowed, "artifact_member_prefix")
            mode = entry.external_attr >> 16
            require(not entry.is_dir() and not stat.S_ISLNK(mode), "artifact_member_kind")
            require(mode == 0 or stat.S_IFMT(mode) in {0, stat.S_IFREG}, "artifact_member_mode")
            require(not (entry.flag_bits & 1), "artifact_member_encrypted")
            total += entry.file_size
            require(
                0 <= entry.file_size <= MAX_UNPACKED_BYTES and total <= MAX_UNPACKED_BYTES, "artifact_unpacked_size"
            )
            data = zipped.read(entry)
            require(len(data) == entry.file_size, "artifact_member_size")
            seen.add(basename)
            members.append({"name": name, "output_name": basename, "bytes": len(data), "sha256": sha256(data)})
            with (destination / basename).open("xb") as target:
                target.write(data)
        require(seen == EXPECTED_NAMES, "artifact_member_set")
    return members


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    token = os.environ.pop("GITHUB_TOKEN")
    require(bool(token), "artifact_token_missing")
    archive, report = fetch_original_archive(token)
    with (destination / "original-artifact.zip").open("xb") as target:
        target.write(archive)
    report["members"] = extract_original_files(archive, destination)
    report["schema"] = "hol-guard.original-windows-artifact.v1"
    (destination / "artifact-binding.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # Never let urllib errors print signed storage URLs or authentication data.
        raise SystemExit("pinned_artifact_fetch_failed") from None
