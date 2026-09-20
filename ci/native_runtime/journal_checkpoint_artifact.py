"""Retrieve and verify one retained wheel; never execute or rebuild its runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.request
import zipfile
from pathlib import Path

ARTIFACT_ID = 10606624387
ARCHIVE_BYTES = 8_255_943
ARCHIVE_SHA = "62e2fd5230a00341a49827106b8e0f0ca074745f245fe4e242e85cb8ca57bc60"
WHEEL_NAME = "hol_guard-3.0.1-py3-none-win_amd64.whl"
WHEEL_BYTES = 8_457_309
WHEEL_SHA = "c13b25af40d3ca5d0594c9486c3b4123d85c56c828bef50a1f5d1b5bfdf8a048"
RUNTIME_SHA = "09142ea9fa88542db7bca04dd6cb568f4b389fea2c5b4ed2709de905931b3e7c"
MANIFEST_SHA = "d65a148a4e8d2920b72f33ea892e75171502f079d640a4b99547aa6d1e1b4ad8"


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            redirected.remove_header("Authorization")
        return redirected


def retrieve(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    endpoint = f"https://api.github.com/repos/hashgraph-online/hol-guard/actions/artifacts/{ARTIFACT_ID}"
    headers = {"Authorization": f"Bearer {os.environ['GH_TOKEN']}", "User-Agent": "hol-guard-journal-diagnostic"}
    opener = urllib.request.build_opener(_Redirect())
    with opener.open(urllib.request.Request(endpoint, headers=headers), timeout=30) as response:
        metadata = json.loads(response.read(131_073))
    if (
        metadata["id"] != ARTIFACT_ID
        or metadata["size_in_bytes"] != ARCHIVE_BYTES
        or metadata["digest"] != f"sha256:{ARCHIVE_SHA}"
        or metadata["expired"]
        or metadata["workflow_run"]["id"] != 35516487925
        or metadata["workflow_run"]["head_sha"] != "ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d"
    ):
        raise RuntimeError("journal_artifact_metadata_mismatch")
    archive = output / "original-artifact.zip"
    digest = hashlib.sha256()
    size = 0
    with (
        opener.open(urllib.request.Request(endpoint + "/zip", headers=headers), timeout=30) as response,
        archive.open("xb") as destination,
    ):
        while block := response.read(65_536):
            size += len(block)
            if size > ARCHIVE_BYTES:
                raise RuntimeError("journal_artifact_size_overflow")
            digest.update(block)
            destination.write(block)
    if size != ARCHIVE_BYTES or digest.hexdigest() != ARCHIVE_SHA:
        raise RuntimeError("journal_artifact_bytes_mismatch")
    members = []
    wheel = output / WHEEL_NAME
    with zipfile.ZipFile(archive) as zipped:
        infos = zipped.infolist()
        if len(infos) > 100 or sum(item.file_size for item in infos) > 64 * 1024 * 1024:
            raise RuntimeError("journal_artifact_expansion_bound")
        if len({item.filename for item in infos}) != len(infos):
            raise RuntimeError("journal_artifact_duplicate_member")
        for item in infos:
            data = zipped.read(item)
            members.append({"member": item.filename, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            if item.filename == "native-dist/" + WHEEL_NAME:
                if len(data) != WHEEL_BYTES or hashlib.sha256(data).hexdigest() != WHEEL_SHA:
                    raise RuntimeError("journal_wheel_bytes_mismatch")
                wheel.write_bytes(data)
    if not wheel.is_file():
        raise RuntimeError("journal_wheel_missing")
    record = {"artifact_id": ARTIFACT_ID, "archive_bytes": size, "archive_sha256": ARCHIVE_SHA, "members": members}
    (output / "artifact-binding.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    retrieve(parser.parse_args().output)
