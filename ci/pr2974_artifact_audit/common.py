"""Read-only observer plumbing, immutable source witnesses, and bounded framing."""

from __future__ import annotations

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
ORIGINAL = json.loads((HARNESS / "ci/pr2974_source_validation/manifest.json").read_text())
GIT_COMMANDS: list[dict[str, object]] = []


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
    result: dict[str, object] = {"type": type(error).__name__}
    if isinstance(error, AssertionError):
        message = str(error)
        result["message"] = re.sub(r"https?://\S+", "[URL omitted]", message)[:2000]
    if isinstance(error, subprocess.TimeoutExpired):
        result["timeout_seconds"] = error.timeout
    return result


def git(*args: str, cwd: Path = SOURCE, data: bytes | None = None, timeout: int = 120) -> bytes:
    label = "git-" + str(len(GIT_COMMANDS) + 1).zfill(3)
    row: dict[str, object] = {"command": ["git", *args], "cwd": str(cwd), "timeout_seconds": timeout}
    GIT_COMMANDS.append(row)
    try:
        result = subprocess.run(["git", *args], cwd=cwd, input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        row["returncode"] = result.returncode
        (REPORT / (label + ".stdout")).write_bytes(result.stdout)
        (REPORT / (label + ".stderr")).write_bytes(result.stderr)
        row["stdout"] = digest(result.stdout)
        row["stderr"] = digest(result.stderr)
        assert result.returncode == 0, "Read-only " + label + " returned " + str(result.returncode)
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
    assert git("rev-parse", "HEAD").decode().strip() == CONFIG["source_sha"]
    assert headers(CONFIG["source_sha"], SOURCE) == {
        "tree": CONFIG["source_tree"], "parents": [CONFIG["source_parent"]]}
    assert git("rev-parse", "--is-shallow-repository").strip() == b"false"
    assert not (SOURCE / ".git/shallow").exists()
    local_config = git("config", "--local", "--list").decode().lower()
    assert "partialclone" not in local_config and ".promisor=" not in local_config
    observer_sha = git("rev-parse", "HEAD", cwd=HARNESS).decode().strip()
    assert observer_sha == os.environ["GITHUB_SHA"]
    assert headers(observer_sha, HARNESS)["parents"] == [CONFIG["original_harness_sha"]]
    assert headers(CONFIG["original_harness_sha"], HARNESS) == {
        "tree": CONFIG["original_harness_tree"], "parents": [CONFIG["source_sha"]]}
    changes = git("diff-tree", "--no-commit-id", "--name-status", "-r",
                  CONFIG["original_harness_sha"], observer_sha, cwd=HARNESS).decode().splitlines()
    assert set(changes) == {"A\t" + path for path in CONFIG["additions"]}
    assert len(changes) == len(CONFIG["additions"])
    for path in CONFIG["additions"]:
        committed = git("show", observer_sha + ":" + path, cwd=HARNESS)
        assert (HARNESS / path).read_bytes() == committed, path
    assert not git("status", "--porcelain", "--untracked-files=no", cwd=HARNESS).strip()
    assert os.environ["GITHUB_REPOSITORY"] == CONFIG["repository"]
    assert os.environ["GITHUB_EVENT_NAME"] == "push"
    assert os.environ["GITHUB_REF"] == "refs/heads/" + CONFIG["branch"]
    assert os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    for path, expected in CONFIG["original_files"].items():
        assert digest((HARNESS / path).read_bytes())["sha256"] == expected, path
    for key in ("source_sha", "source_tree", "source_parent", "release_base", "tracked_files"):
        assert ORIGINAL[key] == CONFIG[key], key
    entries = git("ls-tree", "-rz", "--full-tree", CONFIG["source_sha"]).split(b"\0")
    files = {}
    for entry in entries:
        if not entry:
            continue
        prefix, raw_path = entry.split(b"\t", 1)
        mode, kind, blob = prefix.decode().split()
        relative = raw_path.decode("utf-8")
        safe_name(relative)
        assert kind == "blob" and mode in {"100644", "100755"}, relative
        path = SOURCE / relative
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode), relative
        data = path.read_bytes()
        actual_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        assert actual_blob == blob and bool(info.st_mode & 0o111) == (mode == "100755"), relative
        files[relative] = {"git_blob": blob, **digest(data), "mode": mode}
    assert len(files) == CONFIG["tracked_files"], len(files)
    for path, expected in (ORIGINAL["fixed_files"] | ORIGINAL["source_inputs"]).items():
        assert files[path]["sha256"] == expected, path
    assert files[".gitleaksignore"]["sha256"] == ORIGINAL["gitleaks_ignore_sha256"]
    ignores = [line for line in (SOURCE / ".gitleaksignore").read_text().splitlines()
               if line.strip() and not line.lstrip().startswith("#")]
    assert len(ignores) == ORIGINAL["gitleaks_ignore_entries"] == 152
    assert not git("status", "--porcelain", "--untracked-files=no").strip()
    witness = {"source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
               "source_parent": CONFIG["source_parent"], "files": files}
    write_json(REPORT / ("source-" + label + ".json"), witness)
    return witness


def frame(label: str, data: bytes, *, limit: int = 65536) -> None:
    assert len(data) <= limit, "Framed output exceeds its declared limit: " + label
    text = data.decode("utf-8")
    chunks = [text[index:index + 8000] for index in range(0, len(text), 8000)] or [""]
    print(json.dumps({"frame": "begin", "label": label, **digest(data), "chunks": len(chunks)}), flush=True)
    for index, chunk in enumerate(chunks):
        print(json.dumps({"frame": "chunk", "label": label, "index": index, "text": chunk}), flush=True)
    print(json.dumps({"frame": "end", "label": label, **digest(data)}), flush=True)


def json_summary(label: str, value: object) -> None:
    print(json.dumps({"audit_summary": label, "value": value}, sort_keys=True), flush=True)
