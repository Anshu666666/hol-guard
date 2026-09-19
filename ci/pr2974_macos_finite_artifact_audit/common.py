"""Read-only source witnesses and explicitly bounded original-evidence framing."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text())
SOURCE = Path(os.environ["AUDIT_SOURCE"]).resolve()
HARNESS = Path(os.environ["AUDIT_HARNESS"]).resolve()
OUTPUT = Path(os.environ["AUDIT_OUTPUT"]).resolve()
INPUTS = OUTPUT / "original-zips"
REPORT = OUTPUT / "audit"
ORIGINAL = json.loads((HARNESS / "ci/pr2974_macos_phase_finite/manifest.json").read_text())
EVIDENCE_BYTES = (HERE / "original-evidence.json").read_bytes()
EVIDENCE = json.loads(EVIDENCE_BYTES)
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


def source_witness(label: str) -> dict[str, object]:
    assert SOURCE != HARNESS and not SOURCE.is_relative_to(HARNESS) and not HARNESS.is_relative_to(SOURCE)
    assert not OUTPUT.is_relative_to(SOURCE) and not OUTPUT.is_relative_to(HARNESS)
    assert os.environ["GITHUB_REPOSITORY"] == CONFIG["repository"]
    assert os.environ["GITHUB_EVENT_NAME"] == "push"
    assert os.environ["GITHUB_REF"] == "refs/heads/" + CONFIG["branch"]
    assert os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    assert git("rev-parse", "HEAD").decode().strip() == CONFIG["source_sha"]
    assert headers(CONFIG["source_sha"], SOURCE) == {
        "tree": CONFIG["source_tree"], "parents": [CONFIG["source_parent"]]}
    assert headers(CONFIG["source_parent"], SOURCE)["tree"] == CONFIG["source_parent_tree"]
    observer_sha = git("rev-parse", "HEAD", cwd=HARNESS).decode().strip()
    assert observer_sha == os.environ["GITHUB_SHA"]
    assert headers(observer_sha, HARNESS)["parents"] == [CONFIG["original_harness_sha"]]
    assert headers(CONFIG["original_harness_sha"], HARNESS) == {
        "tree": CONFIG["original_harness_tree"], "parents": [CONFIG["source_sha"]]}
    changes = git("diff-tree", "--no-commit-id", "--name-status", "-r",
                  CONFIG["original_harness_sha"], observer_sha, cwd=HARNESS).decode().splitlines()
    assert len(changes) == len(CONFIG["additions"])
    assert set(changes) == {"A\t" + path for path in CONFIG["additions"]}
    for path in CONFIG["additions"]:
        assert (HARNESS / path).read_bytes() == git("show", observer_sha + ":" + path, cwd=HARNESS)
    for path, expected in CONFIG["original_files"].items():
        assert digest((HARNESS / path).read_bytes()) == expected, path
    assert digest(EVIDENCE_BYTES) == CONFIG["original_evidence"]
    for key in ("source_sha", "source_tree", "source_parent", "python_version"):
        assert ORIGINAL[key] == CONFIG[key], key
    entries = git("ls-tree", "-rz", "--full-tree", CONFIG["source_sha"]).split(b"\0")
    files = {}
    for entry in entries:
        if not entry:
            continue
        prefix, raw_path = entry.split(b"\t", 1)
        mode, kind, blob = prefix.decode().split()
        relative = safe_name(raw_path.decode("utf-8"))
        assert kind == "blob" and mode in {"100644", "100755"}
        path = SOURCE / relative
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode)
        data = path.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        assert actual == blob and bool(info.st_mode & 0o111) == (mode == "100755"), relative
        assert relative not in files
        files[relative] = {"git_blob": blob, **digest(data), "mode": mode}
    assert len(files) == CONFIG["tracked_files"] == 4224
    fixed = ORIGINAL["changed_files"] | ORIGINAL["preserved_files"] | ORIGINAL["source_inputs"]
    for path, expected in fixed.items():
        assert files[path]["sha256"] == expected, path
    for root in (SOURCE, HARNESS):
        assert not git("status", "--porcelain", "--untracked-files=all", cwd=root).strip()
    result = {"input_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"], "files": files}
    write_json(REPORT / ("observer-source-" + label + ".json"), result)
    return result


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
    print("MACOS_AUDIT_FRAME_BEGIN " + json.dumps(meta, sort_keys=True), flush=True)
    for index, chunk in enumerate(chunks, 1):
        print(f"MACOS_AUDIT_FRAME_CHUNK {label} {index}/{len(chunks)} {chunk}", flush=True)
    print("MACOS_AUDIT_FRAME_END " + json.dumps(meta, sort_keys=True), flush=True)


def parsed(payloads: dict[str, bytes], name: str):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            assert key not in value, "Duplicate JSON key"
            value[key] = item
        return value
    assert name in payloads, "Missing original evidence: " + name
    return json.loads(payloads[name], object_pairs_hook=unique)
