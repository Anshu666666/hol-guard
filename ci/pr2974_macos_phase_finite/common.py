"""Bounded, owned diagnostic execution and exact Git/source witnesses."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import stat
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_text())
SOURCE = Path(os.environ["VALIDATION_SOURCE"]).resolve()
HARNESS = Path(os.environ["VALIDATION_HARNESS"]).resolve()
REPORT = Path(os.environ["VALIDATION_REPORT"]).resolve()
SCRATCH = Path(os.environ["VALIDATION_SCRATCH"]).resolve()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def git(*args: str, cwd: Path = SOURCE) -> bytes:
    return subprocess.check_output(["git", *args], cwd=cwd, stderr=subprocess.PIPE, timeout=60)


def headers(commit: str, cwd: Path) -> dict[str, object]:
    lines = git("cat-file", "-p", commit, cwd=cwd).split(b"\n\n", 1)[0].decode().splitlines()
    return {
        "tree": next(line[5:] for line in lines if line.startswith("tree ")),
        "parents": [line[7:] for line in lines if line.startswith("parent ")],
    }


def admit() -> None:
    roots = (SOURCE, HARNESS, REPORT, SCRATCH)
    assert all(a != b and not a.is_relative_to(b) for a in roots for b in roots if a is not b)
    assert CONFIG["mode"] == "finite" and CONFIG["finite_execution_authorized"] is True
    assert os.environ["GITHUB_EVENT_NAME"] == "push"
    assert os.environ["GITHUB_REF"] == "refs/heads/" + CONFIG["branch"]
    assert os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    assert git("rev-parse", "HEAD").decode().strip() == CONFIG["source_sha"]
    assert headers(CONFIG["source_sha"], SOURCE) == {
        "tree": CONFIG["source_tree"], "parents": [CONFIG["source_parent"]]
    }
    head = git("rev-parse", "HEAD", cwd=HARNESS).decode().strip()
    assert head == os.environ["GITHUB_SHA"]
    assert headers(head, HARNESS)["parents"] == [CONFIG["source_sha"]]
    changes = git("diff-tree", "--no-commit-id", "--name-status", "-r",
                  CONFIG["source_sha"], head, cwd=HARNESS).decode().splitlines()
    expected = {"A\t" + path for path in CONFIG["harness_paths"]}
    assert len(changes) == len(expected) and set(changes) == expected, changes
    assert not (SOURCE / "ci/pr2974_macos_phase_finite").exists()
    assert not git("status", "--porcelain", "--untracked-files=all").strip()
    for directory in (REPORT, SCRATCH):
        info = directory.lstat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
    harness = {}
    for relative in CONFIG["harness_paths"]:
        data = (HARNESS / relative).read_bytes()
        expected_data = git("show", head + ":" + relative, cwd=HARNESS)
        assert data == expected_data, relative
        harness[relative] = {"sha256": digest(data), "bytes": len(data)}
    write_json(REPORT / "harness.json", {"sha": head, **headers(head, HARNESS), "files": harness})


def source_map(label: str, *, original: bool = False) -> dict[str, object]:
    assert git("rev-parse", "HEAD").decode().strip() == CONFIG["source_sha"]
    files = {}
    for entry in git("ls-tree", "-rz", "--full-tree", CONFIG["source_sha"]).split(b"\0"):
        if not entry:
            continue
        prefix, raw_path = entry.split(b"\t", 1)
        mode, kind, original_blob = prefix.decode().split()
        relative = raw_path.decode()
        assert kind == "blob" and mode in {"100644", "100755"}, (relative, mode, kind)
        path = SOURCE / relative
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode), relative
        assert bool(info.st_mode & 0o111) == (mode == "100755"), relative
        data = path.read_bytes()
        actual_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if original:
            assert actual_blob == original_blob, relative
        files[relative] = {"git_blob": actual_blob, "sha256": digest(data), "bytes": len(data), "mode": mode}
    if original:
        fixed = CONFIG["changed_files"] | CONFIG["preserved_files"] | CONFIG["source_inputs"]
        for path, expected in fixed.items():
            assert files[path]["sha256"] == expected, path
    write_json(REPORT / ("source-" + label + ".json"), {
        "input_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"], "files": files,
    })
    return files


def emit_file(path: Path, kind: str, limit: int = 262144) -> None:
    data = path.read_bytes()
    assert len(data) <= limit, (str(path), len(data), limit)
    encoded = base64.b64encode(data).decode("ascii")
    chunks = [encoded[index:index + 1024] for index in range(0, len(encoded), 1024)]
    print("MACOS_FINITE_FILE_BEGIN " + json.dumps({
        "kind": kind, "bytes": len(data), "sha256": digest(data), "chunks": len(chunks),
        "encoding": "base64", "chunk_characters": 1024,
    }), flush=True)
    for index, chunk in enumerate(chunks, 1):
        print(f"MACOS_FINITE_FILE_CHUNK {kind} {index}/{len(chunks)} {chunk}", flush=True)
    print("MACOS_FINITE_FILE_END " + kind, flush=True)


class Run:
    def __init__(self) -> None:
        self.steps = []
        self.errors = []
        self.started = time.time()

    def require(self, value: object, message: str) -> None:
        if not value:
            raise AssertionError(message)

    def command(self, name: str, args: list[str], env: dict[str, str], timeout: int = 90) -> bool:
        path = REPORT / (name + ".log")
        result = {"name": name, "args": args, "timeout_seconds": timeout, "returncode": None,
                  "timed_out": False, "log_limit_exceeded": False, "passed": False}
        self.steps.append(result)
        write_json(REPORT / "steps.json", self.steps)
        started = time.monotonic()
        process = None
        try:
            with path.open("wb") as stream:
                process = subprocess.Popen(args, cwd=SOURCE, env=env, stdout=stream,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                result["pid"] = process.pid
                while process.poll() is None:
                    result["timed_out"] = time.monotonic() - started > timeout
                    result["log_limit_exceeded"] = path.stat().st_size > 8 * 1024 * 1024
                    if result["timed_out"] or result["log_limit_exceeded"]:
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=10)
                        break
                    time.sleep(0.1)
                result["returncode"] = process.wait(timeout=10)
        except Exception as error:
            result["error"] = repr(error)
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
                except Exception as cleanup_error:
                    result["cleanup_error"] = repr(cleanup_error)
        finally:
            result["duration_seconds"] = time.monotonic() - started
            result["passed"] = (result["returncode"] == 0 and not result["timed_out"]
                                and not result["log_limit_exceeded"] and "error" not in result)
            if path.is_file():
                data = path.read_bytes()
                result.update(log_bytes=len(data), log_sha256=digest(data))
                print("MACOS_FINITE_COMMAND " + json.dumps(result, sort_keys=True), flush=True)
                if not result["passed"]:
                    print("MACOS_FINITE_LOG_PREFIX_BASE64 " + name + " " +
                          base64.b64encode(data[:12288]).decode("ascii"), flush=True)
            write_json(REPORT / "steps.json", self.steps)
        return bool(result["passed"])
