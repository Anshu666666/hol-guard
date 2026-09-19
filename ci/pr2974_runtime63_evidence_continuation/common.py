"""Read-only artifact audit helpers; no inspected-source imports."""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text())
SOURCE = Path(os.environ["AUDIT_SOURCE"]).resolve()
HARNESS = Path(os.environ["AUDIT_HARNESS"]).resolve()
OUTPUT = Path(os.environ["AUDIT_OUTPUT"]).resolve()
INPUTS = OUTPUT / "original-zips"
REPORT = OUTPUT / "audit"
GIT_COMMANDS = []
EMITTED = []
EMITTED_RAW = 0
EMITTED_COMPRESSED = 0

def digest(data: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


def safe_name(name: str) -> str:
    assert isinstance(name, str) and name and "\0" not in name and "\\" not in name
    assert not name.startswith("/") and not re.match(r"^[A-Za-z]:", name)
    parts = name.rstrip("/").split("/")
    assert all(part and part not in {".", ".."} for part in parts), "Unsafe archive member"
    assert PurePosixPath(name).as_posix() == name.rstrip("/"), "Noncanonical archive member"
    return name


def failure(error: BaseException) -> dict[str, object]:
    value = {"type": type(error).__name__}
    if isinstance(error, AssertionError):
        value["message"] = re.sub(r"https?://\S+", "[URL omitted]", str(error))[:2000]
    if isinstance(error, subprocess.TimeoutExpired):
        value["timeout_seconds"] = error.timeout
    return value


def git(*args: str, cwd: Path = SOURCE) -> bytes:
    row = {"command": ["git", *args], "cwd": str(cwd), "timeout_seconds": 120}
    GIT_COMMANDS.append(row)
    label = "git-" + str(len(GIT_COMMANDS)).zfill(3)
    try:
        result = subprocess.run(["git", *args], cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=120, check=False)
        row.update(returncode=result.returncode, stdout=digest(result.stdout), stderr=digest(result.stderr))
        (REPORT / (label + ".stdout")).write_bytes(result.stdout)
        (REPORT / (label + ".stderr")).write_bytes(result.stderr)
        assert result.returncode == 0, "Read-only Git query failed: " + label
        return result.stdout
    except BaseException as error:
        row["error"] = failure(error)
        raise
    finally:
        write_json(REPORT / "observer-git-commands.json", GIT_COMMANDS)


def headers(commit: str, cwd: Path) -> dict[str, object]:
    lines = git("cat-file", "-p", commit, cwd=cwd).split(b"\n\n", 1)[0].decode().splitlines()
    return {"tree": next(line[5:] for line in lines if line.startswith("tree ")),
            "parents": [line[7:] for line in lines if line.startswith("parent ")]}


def frame(label: str, data: bytes, *, limit: int) -> None:
    global EMITTED_RAW, EMITTED_COMPRESSED
    safe_name(label)
    assert label not in EMITTED, "Duplicate frame label"
    assert len(data) <= limit, "Original frame exceeds explicit byte limit: " + label
    compressed = gzip.compress(data, compresslevel=9, mtime=0)
    assert len(compressed) <= 4 * 1024 * 1024, "Compressed frame too large"
    assert EMITTED_RAW + len(data) <= 48 * 1024 * 1024, "Aggregate raw-frame limit"
    assert EMITTED_COMPRESSED + len(compressed) <= 8 * 1024 * 1024, "Aggregate compressed-frame limit"
    EMITTED.append(label)
    EMITTED_RAW += len(data)
    EMITTED_COMPRESSED += len(compressed)
    encoded = base64.b64encode(compressed).decode("ascii")
    chunks = [encoded[index:index + 8192] for index in range(0, len(encoded), 8192)]
    meta = {"label": label, **digest(data), "encoding": "gzip+base64",
            "compressed_bytes": len(compressed), "compressed_sha256": digest(compressed)["sha256"],
            "chunks": len(chunks), "chunk_characters": 8192, "raw_limit": limit}
    print("RUNTIME63_EVIDENCE_AUDIT_FRAME_BEGIN " + json.dumps(meta, sort_keys=True), flush=True)
    for index, chunk in enumerate(chunks, 1):
        print(f"RUNTIME63_EVIDENCE_AUDIT_FRAME_CHUNK {label} {index}/{len(chunks)} {chunk}", flush=True)
    print("RUNTIME63_EVIDENCE_AUDIT_FRAME_END " + json.dumps(meta, sort_keys=True), flush=True)


def parsed(payloads: dict[str, bytes], name: str):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            assert key not in value, "Duplicate JSON key"
            value[key] = item
        return value
    assert name in payloads, "Missing original evidence: " + name
    return json.loads(payloads[name], object_pairs_hook=unique)
