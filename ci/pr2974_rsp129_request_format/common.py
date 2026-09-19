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
    ".github/workflows/pr2974-rsp129-request-format.yml",
    "ci/pr2974_rsp129_request_format/manifest.json",
    "ci/pr2974_rsp129_request_format/common.py",
    "ci/pr2974_rsp129_request_format/format.py",
    "ci/pr2974_rsp129_request_format/format_bridge.py",
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
    assert not (SOURCE / "ci/pr2974_rsp129_request_format").exists()
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


def process_identity(pid: int) -> dict[str, object]:
    root = Path("/proc") / str(pid)
    fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "state": fields[0], "ppid": int(fields[1]),
            "pgrp": int(fields[2]), "session": int(fields[3]),
            "start_ticks": int(fields[19]), "uid": root.stat().st_uid}


def group_snapshot(pgid: int, leader_start: int) -> dict[str, object]:
    members = []
    errors = []
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            row = process_identity(int(path.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            errors.append({"pid": int(path.name), "error_type": type(error).__name__})
            continue
        if row["pgrp"] == pgid:
            assert row["uid"] == os.getuid() and row["session"] == pgid, row
            assert row["start_ticks"] >= leader_start, row
            if row["pid"] == pgid:
                assert row["start_ticks"] == leader_start, "Refuse a reused process-group leader"
            members.append(row)
    return {"members": members, "live": [row for row in members if row["state"] != "Z"],
            "inspection_errors": errors}


def retire_group(process: subprocess.Popen, leader: dict[str, object]) -> dict[str, object]:
    result = {"pgid": process.pid, "leader_start_ticks": leader["start_ticks"],
              "scope": "Only this verified original process group; no complete-descendant claim",
              "signals": [], "snapshots": [], "errors": []}
    try:
        for signal_name, signum in (("TERM", signal.SIGTERM), ("KILL", signal.SIGKILL)):
            process.poll()
            snapshot = group_snapshot(process.pid, leader["start_ticks"])
            result["snapshots"].append(snapshot)
            if snapshot["inspection_errors"]:
                raise RuntimeError("Original process group inspection incomplete")
            if not snapshot["live"]:
                break
            try:
                os.killpg(process.pid, signum)
                result["signals"].append({"signal": signal_name, "sent": True})
            except ProcessLookupError:
                result["signals"].append({"signal": signal_name, "sent": False, "group_missing": True})
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                process.poll()
                current = group_snapshot(process.pid, leader["start_ticks"])
                if current["inspection_errors"] or not current["live"]:
                    break
                time.sleep(0.1)
        process.poll()
        final = group_snapshot(process.pid, leader["start_ticks"])
        result["snapshots"].append(final)
        result["no_live_members_in_original_group"] = not final["live"] and not final["inspection_errors"]
        if process.poll() is None:
            result["errors"].append("Direct child is still unreaped or running")
    except Exception as error:
        result["errors"].append(repr(error))
        result["no_live_members_in_original_group"] = False
    result["passed"] = result["no_live_members_in_original_group"] and not result["errors"]
    return result


def command(name: str, args: list[str], root: Path, env: dict[str, str],
            timeout: int, rows: list[dict[str, object]]) -> bool:
    output = REPORT / (name + ".log")
    output.parent.mkdir(parents=True, exist_ok=True)
    row = {"name": name, "command": args, "timeout_seconds": timeout, "cwd": str(root),
           "returncode": None, "timed_out": False}
    rows.append(row)
    write_json(REPORT / "commands.json", rows)
    start = time.monotonic()
    process = None
    leader = None
    guard = SCRATCH / "unsafe-process-cleanup.json"
    try:
        assert not guard.exists(), "Refuse new command after unverified owned-group cleanup"
        with output.open("wb") as stream:
            process = subprocess.Popen(args, cwd=root, env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            row["pid"] = process.pid
            leader = process_identity(process.pid)
            assert leader["pgrp"] == leader["session"] == process.pid and leader["uid"] == os.getuid()
            row["leader_identity"] = leader
            try:
                row["returncode"] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row["timed_out"] = True
    except Exception as error:
        row["error"] = repr(error)
    finally:
        if process is not None and leader is not None:
            row["group_cleanup"] = retire_group(process, leader)
            row["returncode"] = process.returncode
            if not row["group_cleanup"]["passed"]:
                write_json(guard, {"command": name, "cleanup": row["group_cleanup"]})
        elif process is not None:
            row["group_cleanup"] = {"passed": False, "error": "Owned leader identity unavailable",
                                    "complete_descendant_claim": False}
            write_json(guard, {"command": name, "cleanup": row["group_cleanup"]})
        row["wall_seconds"] = time.monotonic() - start
        row["passed"] = (row["returncode"] == 0 and not row["timed_out"]
                         and row.get("group_cleanup", {}).get("passed") is True
                         and "error" not in row)
        if output.exists():
            row.update(log_bytes=output.stat().st_size, log_sha256=sha256(output.read_bytes()))
        write_json(REPORT / "commands.json", rows)
    return bool(row["passed"])

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
        try:
            return command(name, args, cwd, os.environ.copy() if env is None else env, timeout, self.steps)
        finally:
            write_json(REPORT / "steps.json", self.steps)

    def finish(self) -> bool:
        unchanged = False
        try:
            after = source_witness("after")
            unchanged = self.before is not None and self.before == after
            if not unchanged:
                raise AssertionError("Full candidate source changed or initial witness unavailable")
        except Exception as error:
            self.error = self.error or repr(error)
        groups_retired = all(step.get("group_cleanup", {}).get("passed") is True for step in self.steps)
        unsafe = SCRATCH / "unsafe-process-cleanup.json"
        if unsafe.is_file():
            (REPORT / unsafe.name).write_bytes(unsafe.read_bytes())
        passed = not self.error and unchanged and groups_retired and not unsafe.exists() and all(
            step.get("passed") for step in self.steps
        )
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
            "all_original_owned_groups_retired": groups_retired,
            "mutable_formatter_output_is_not_an_immutable_validation_result": True,
            "fresh_immutable_formatted_commit_and_source_bridge_required": True,
        }
        write_json(REPORT / "job-outcome.json", outcome)
        print(json.dumps({key: value for key, value in outcome.items() if key != "steps"}, sort_keys=True))
        return bool(passed)
