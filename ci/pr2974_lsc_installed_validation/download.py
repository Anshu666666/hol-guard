"""Download only pinned original artifacts with a token confined to the GitHub API."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from artifact_common import CONFIG, INPUTS, REPORT, digest, safe_name, write_json

TOKEN = os.environ.pop("AUDIT_TOKEN", "")
API_READS = []
API_ROOT = "https://api.github.com/repos/" + CONFIG["repository"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api(path: str, *, authenticated: bool = True) -> dict[str, object]:
    assert path.startswith("/") and not path.startswith("//")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "hol-guard-original-artifact-observer"}
    if authenticated:
        assert TOKEN, "Actions API token missing"
        headers["Authorization"] = "Bearer " + TOKEN
    request = urllib.request.Request(API_ROOT + path, headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
            payload = response.read(16 * 1024 * 1024 + 1)
            assert len(payload) <= 16 * 1024 * 1024, "Oversized API response"
        value = json.loads(payload)
        API_READS.append(path)
        write_json(REPORT / ("api-read-" + str(len(API_READS)).zfill(3) + ".json"),
                   {"resource": path, "authenticated": authenticated, "response": value})
        return value
    except urllib.error.HTTPError as error:
        raise AssertionError("GitHub API HTTP " + str(error.code) + " for " + path) from None
    except urllib.error.URLError:
        raise AssertionError("GitHub API transport failure for " + path) from None


def population(path: str, key: str, *, authenticated: bool = True) -> list[dict[str, object]]:
    rows = []
    total = None
    for page in range(1, 101):
        separator = "&" if "?" in path else "?"
        value = api(path + separator + "per_page=100&page=" + str(page), authenticated=authenticated)
        assert isinstance(value["total_count"], int) and isinstance(value[key], list)
        if total is None:
            total = value["total_count"]
        assert total == value["total_count"], "Population changed during pagination"
        rows.extend(value[key])
        assert len(rows) <= total, "Duplicate or overfull API population"
        if len(rows) == total:
            assert len({row["id"] for row in rows}) == len(rows), "Duplicate API row"
            return rows
        assert value[key], "Incomplete pagination"
    raise AssertionError("Population pagination exceeded bounded limit")


def download(pin: dict[str, object]) -> Path:
    INPUTS.mkdir(parents=True, exist_ok=True)
    destination = INPUTS / (str(pin["id"]) + ".zip")
    assert not destination.exists(), "Refuse existing downloaded artifact"
    endpoint = API_ROOT + "/actions/artifacts/" + str(pin["id"]) + "/zip"
    request = urllib.request.Request(endpoint, headers={
        "Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "hol-guard-original-artifact-observer"})
    try:
        urllib.request.build_opener(NoRedirect).open(request, timeout=60)
    except urllib.error.HTTPError as response:
        assert response.code == 302, "Artifact API returned HTTP " + str(response.code)
        location = response.headers.get("Location")
        response.close()
    except urllib.error.URLError:
        raise AssertionError("Artifact API transport failed for ID " + str(pin["id"])) from None
    else:
        raise AssertionError("Artifact API did not return the documented redirect")
    assert location, "Missing artifact redirect"
    parsed = urllib.parse.urlsplit(location)
    assert parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
    assert not parsed.fragment
    # This fresh request intentionally has no Authorization header, cookies, or opener state.
    request = urllib.request.Request(location, headers={"User-Agent": "hol-guard-original-artifact-observer"})
    hashed = hashlib.sha256()
    count = 0
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=90) as response:
            assert response.status == 200
            with destination.open("xb") as output:
                while chunk := response.read(1024 * 1024):
                    count += len(chunk)
                    assert count <= pin["bytes"], "Artifact download exceeds pinned byte count"
                    hashed.update(chunk)
                    output.write(chunk)
    except urllib.error.HTTPError as error:
        raise AssertionError("Signed artifact transfer HTTP " + str(error.code) + " for ID " + str(pin["id"])) from None
    except urllib.error.URLError:
        raise AssertionError("Signed artifact transport failed for ID " + str(pin["id"])) from None
    receipt = {"artifact_id": pin["id"], "name": pin["name"], "bytes": count, "sha256": hashed.hexdigest(),
               "expected_bytes": pin["bytes"], "expected_sha256": pin["sha256"],
               "token_sent_only_to_api_github_com": True}
    write_json(REPORT / (pin["label"] + "-download.json"), receipt)
    assert count == pin["bytes"] and hashed.hexdigest() == pin["sha256"], "Pinned ZIP digest/size mismatch"
    return destination


def read_zip(path: Path, label: str) -> dict[str, bytes]:
    # Called only after the complete ZIP digest/size guard succeeds.
    payloads = {}
    members = {}
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        assert 0 < len(infos) <= 256
        assert len({info.filename for info in infos}) == len(infos), "Duplicate ZIP member"
        assert sum(info.file_size for info in infos) <= 64 * 1024 * 1024, "Oversized ZIP contents"
        for info in infos:
            safe_name(info.filename)
            assert not info.flag_bits & 1, "Encrypted ZIP member"
            assert info.file_size <= 16 * 1024 * 1024, "Oversized ZIP member"
            kind = stat.S_IFMT(info.external_attr >> 16)
            assert kind in {0, stat.S_IFREG, stat.S_IFDIR}, "Nonregular ZIP member"
            if info.is_dir():
                assert info.file_size == 0 and kind in {0, stat.S_IFDIR}
                members[info.filename] = {"directory": True}
                continue
            assert kind != stat.S_IFDIR, "Inconsistent ZIP directory marker"
            data = archive.read(info)  # The standard reader also verifies each member's CRC.
            assert len(data) == info.file_size
            payloads[info.filename] = data
            members[info.filename] = {**digest(data), "crc32": info.CRC, "compressed_bytes": info.compress_size}
    write_json(REPORT / (label + "-zip-members.json"), {"archive": digest(path.read_bytes()), "members": members,
                                                      "all_actual_members_read_and_crc_verified": True})
    return payloads
