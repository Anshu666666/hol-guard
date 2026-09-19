"""Source-only formatting evidence; no product imports or qualification claims."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
SOURCE = Path(os.environ["VALIDATION_SOURCE"]).resolve()
REPORT = Path(os.environ["VALIDATION_REPORT"]).resolve()
SCRATCH = Path(os.environ["VALIDATION_SCRATCH"]).resolve()
HARNESS = Path(os.environ["VALIDATION_HARNESS"]).resolve()
ALLOWED_ADDITIONS = {
    ".github/workflows/pr2974-partition-format.yml",
    "ci/pr2974_partition_format/manifest.json",
    "ci/pr2974_partition_format/common.py",
    "ci/pr2974_partition_format/format.py",
    "ci/pr2974_partition_format/format_bridge.py",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def git(*args: str, cwd: Path = SOURCE) -> bytes:
    return subprocess.check_output(["git", *args], cwd=cwd, stderr=subprocess.PIPE, timeout=60)


def commit_headers(commit: str, cwd: Path) -> dict[str, object]:
    content = git("cat-file", "-p", commit, cwd=cwd).split(b"\n\n", 1)[0].decode()
    lines = content.splitlines()
    return {
        "tree": next(line.removeprefix("tree ") for line in lines if line.startswith("tree ")),
        "parents": [line.removeprefix("parent ") for line in lines if line.startswith("parent ")],
    }


def source_witness(label: str) -> dict[str, object]:
    assert SOURCE != HARNESS and not SOURCE.is_relative_to(HARNESS) and not HARNESS.is_relative_to(SOURCE)
    assert REPORT != SOURCE and not REPORT.is_relative_to(SOURCE)
    assert SCRATCH != SOURCE and not SCRATCH.is_relative_to(SOURCE)
    assert git("rev-parse", "HEAD").decode().strip() == CONFIG["source_sha"]
    headers = commit_headers(CONFIG["source_sha"], SOURCE)
    assert headers == {"tree": CONFIG["source_tree"], "parents": [CONFIG["source_parent"]]}, headers
    assert os.environ["GITHUB_EVENT_NAME"] == "push"
    assert os.environ["GITHUB_REF"] == "refs/heads/" + CONFIG["branch"]
    assert os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    harness_sha = git("rev-parse", "HEAD", cwd=HARNESS).decode().strip()
    assert harness_sha == os.environ["GITHUB_SHA"]
    assert commit_headers(harness_sha, HARNESS)["parents"] == [CONFIG["source_sha"]]
    changes = git("diff-tree", "--no-commit-id", "--name-status", "-r", CONFIG["source_sha"],
                  harness_sha, cwd=HARNESS).decode().splitlines()
    additions = {line.split("\t", 1)[1] for line in changes if line.startswith("A\t")}
    assert additions == ALLOWED_ADDITIONS and len(changes) == len(ALLOWED_ADDITIONS), changes
    assert not (SOURCE / "ci/pr2974_partition_format").exists()
    entries = git("ls-tree", "-rz", "--full-tree", CONFIG["source_sha"]).split(b"\0")
    files = {}
    for entry in entries:
        if not entry:
            continue
        prefix, raw_path = entry.split(b"\t", 1)
        mode, kind, blob = prefix.decode().split()
        relative = raw_path.decode("utf-8")
        assert kind == "blob" and mode in {"100644", "100755"}, (relative, mode, kind)
        path = SOURCE / relative
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), relative
        data = path.read_bytes()
        actual_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        assert actual_blob == blob, relative
        assert bool(info.st_mode & 0o111) == (mode == "100755"), relative
        files[relative] = {"git_blob": blob, "sha256": sha256(data), "bytes": len(data), "mode": mode}
    assert len(files) == CONFIG["tracked_files"], len(files)
    for path, expected in (CONFIG["fixed_files"] | CONFIG["source_inputs"]).items():
        assert files[path]["sha256"] == expected, path
    for path, expected in CONFIG["partition_input_files"].items():
        assert files[path] == {key: expected[key] for key in ("git_blob", "sha256", "bytes", "mode")}, path
    assert files[".gitleaksignore"]["sha256"] == CONFIG["gitleaks_ignore_sha256"]
    ignores = [line for line in (SOURCE / ".gitleaksignore").read_text().splitlines()
               if line.strip() and not line.lstrip().startswith("#")]
    assert len(ignores) == CONFIG["gitleaks_ignore_entries"], len(ignores)
    assert not git("status", "--porcelain", "--untracked-files=no").strip()
    witness = {"source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
               "source_parent": CONFIG["source_parent"], "harness_sha": harness_sha, "files": files}
    write_json(REPORT / ("source-" + label + ".json"), witness)
    return witness


class Run:
    def __init__(self, name: str):
        REPORT.mkdir(parents=True, exist_ok=True)
        SCRATCH.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.steps: list[dict[str, object]] = []
        self.before = None
        self.name = name
        self.error = None
        self.started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_json(REPORT / "job-start.json", {
            "job": name, "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "harness_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "started_utc": self.started,
            "status": "started", "qualification_complete": False,
        })

    def require(self, condition: object, message: str) -> None:
        if not condition:
            raise AssertionError(message)

    def command(self, name: str, args: list[str], *, cwd: Path = SOURCE,
                timeout: int = 300, env: dict[str, str] | None = None) -> bool:
        output = REPORT / (name + ".log")
        result: dict[str, object] = {
            "name": name, "command": args, "cwd": str(cwd), "timeout_seconds": timeout,
            "status": "starting", "returncode": None, "timed_out": False,
        }
        self.steps.append(result)
        write_json(REPORT / "steps.json", self.steps)
        started = time.monotonic()
        process = None
        try:
            with output.open("wb") as stream:
                process = subprocess.Popen(args, cwd=cwd, env=env, stdout=stream,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                result["pid"] = process.pid
                result["status"] = "running"
                write_json(REPORT / "steps.json", self.steps)
                try:
                    result["returncode"] = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    result["timed_out"] = True
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)
                    result["returncode"] = process.returncode
        except Exception as error:
            result["launch_or_wait_error"] = repr(error)
        finally:
            result["duration_seconds"] = time.monotonic() - started
            result["status"] = "finished"
            if output.is_file():
                data = output.read_bytes()
                result.update(log_bytes=len(data), log_sha256=sha256(data))
            result["passed"] = result["returncode"] == 0 and not result["timed_out"]
            write_json(REPORT / "steps.json", self.steps)
        return bool(result["passed"])

    def finish(self) -> bool:
        unchanged = False
        try:
            after = source_witness("after")
            unchanged = self.before is not None and self.before == after
            if not unchanged:
                raise AssertionError("Full candidate source changed or initial witness unavailable")
        except Exception as error:
            self.error = self.error or repr(error)
        passed = not self.error and unchanged and all(step.get("passed") for step in self.steps)
        files = {}
        for path in sorted(REPORT.rglob("*")):
            if path.is_file() and path.relative_to(REPORT).as_posix() not in {"job-outcome.json", "artifact-manifest.json"}:
                data = path.read_bytes()
                files[path.relative_to(REPORT).as_posix()] = {"sha256": sha256(data), "bytes": len(data)}
        write_json(REPORT / "artifact-manifest.json", files)
        outcome = {
            "job": self.name, "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "harness_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "started_utc": self.started,
            "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "finished", "passed": bool(passed), "error": self.error,
            "source_unchanged": unchanged, "steps": self.steps, "qualification_complete": False,
            "scope": CONFIG["scope"], "no_complete_descendant_cleanup_certificate": True,
            "mutable_formatter_output_is_not_an_immutable_validation_result": True,
            "fresh_immutable_formatted_commit_and_validation_required": True,
        }
        write_json(REPORT / "job-outcome.json", outcome)
        print(json.dumps({key: value for key, value in outcome.items() if key != "steps"}, sort_keys=True))
        return bool(passed)
