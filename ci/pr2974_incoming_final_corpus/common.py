"""Bind immutable input and owned report staging; retain every bounded command."""

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
CONFIG = json.loads((HERE / "manifest.json").read_text())
SEED = Path(os.environ["VALIDATION_SEED"]).resolve()
SOURCE = Path(os.environ["VALIDATION_SOURCE"]).resolve()
HARNESS = Path(os.environ["VALIDATION_HARNESS"]).resolve()
REPORT = Path(os.environ["VALIDATION_REPORT"]).resolve()
SCRATCH = Path(os.environ["VALIDATION_SCRATCH"]).resolve()
REPORT_RELATIVE = CONFIG["report_path"]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


def git(*args: str, cwd: Path) -> bytes:
    return subprocess.check_output(["git", *args], cwd=cwd, stderr=subprocess.PIPE, timeout=60)


def commit_headers(commit: str, cwd: Path) -> dict:
    lines = git("cat-file", "-p", commit, cwd=cwd).split(b"\n\n", 1)[0].decode().splitlines()
    return {"tree": next(line[5:] for line in lines if line.startswith("tree ")),
            "parents": [line[7:] for line in lines if line.startswith("parent ")]}


def source_files(root: Path) -> dict:
    assert git("rev-parse", "HEAD", cwd=root).decode().strip() == CONFIG["source_sha"]
    assert commit_headers(CONFIG["source_sha"], root) == {
        "tree": CONFIG["source_tree"], "parents": [CONFIG["source_parent"]]}
    files = {}
    for entry in git("ls-tree", "-rz", "--full-tree", CONFIG["source_sha"], cwd=root).split(b"\0"):
        if not entry:
            continue
        header, raw_path = entry.split(b"\t", 1)
        mode, kind, blob = header.decode().split()
        relative = raw_path.decode("utf-8")
        assert kind == "blob" and mode in {"100644", "100755"}
        path = root / relative
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), relative
        raw = path.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        assert bool(info.st_mode & 0o111) == (mode == "100755"), relative
        files[relative] = {"git_blob": actual, "committed_blob": blob, "sha256": sha256(raw),
                           "bytes": len(raw), "mode": mode}
    assert len(files) == CONFIG["tracked_files"] == 4622
    return files


def seed_witness(label: str) -> dict:
    assert os.environ["GITHUB_REPOSITORY"] == CONFIG["repository"]
    assert os.environ["GITHUB_EVENT_NAME"] == "push"
    assert os.environ["GITHUB_REF"] == "refs/heads/" + CONFIG["branch"]
    assert os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    assert SOURCE == SCRATCH / "source"
    for root in (HARNESS, SEED):
        assert not SOURCE.is_relative_to(root) and not root.is_relative_to(SOURCE)
        assert not REPORT.is_relative_to(root) and not SCRATCH.is_relative_to(root)
    assert SEED != HARNESS and not SEED.is_relative_to(HARNESS) and not HARNESS.is_relative_to(SEED)
    assert not REPORT.is_relative_to(SOURCE) and not SOURCE.is_relative_to(REPORT)
    observer = git("rev-parse", "HEAD", cwd=HARNESS).decode().strip()
    assert observer == os.environ["GITHUB_SHA"]
    assert commit_headers(observer, HARNESS)["parents"] == [CONFIG["source_sha"]]
    changes = git("diff-tree", "--no-commit-id", "--name-status", "-r",
                  CONFIG["source_sha"], observer, cwd=HARNESS).decode().splitlines()
    assert set(changes) == {"A\t" + path for path in CONFIG["harness_paths"]}
    assert len(changes) == len(CONFIG["harness_paths"])
    harness_files = {}
    for relative in CONFIG["harness_paths"]:
        path = HARNESS / relative
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        raw = path.read_bytes()
        assert raw == git("show", observer + ":" + relative, cwd=HARNESS)
        harness_files[relative] = {"sha256": sha256(raw), "bytes": len(raw)}
    for relative, expected in CONFIG["observer_payloads"].items():
        assert sha256((HERE / relative).read_bytes()) == expected
    assert commit_headers(CONFIG["source_parent"], SEED)["tree"] == CONFIG["source_parent_tree"]
    files = source_files(SEED)
    assert all(row["git_blob"] == row["committed_blob"] for row in files.values())
    for relative, expected in CONFIG["source_inputs"].items():
        assert files[relative]["sha256"] == expected, relative
    for relative, expected in CONFIG["repair_files"].items():
        assert all(files[relative][key] == expected[key]
                   for key in ("sha256", "git_blob", "bytes", "mode")), relative
    for row in CONFIG["corpus_sources"]:
        actual = files[row["path"]]
        assert all(actual[key] == row[key] for key in ("sha256", "git_blob", "mode")), row["path"]
        assert row["binding_id"] == "source-" + sha256(row["path"].encode())[:24]
    assert not git("status", "--porcelain", "--untracked-files=all", cwd=SEED).strip()
    assert not git("status", "--porcelain", "--untracked-files=all", cwd=HARNESS).strip()
    result = {"source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
              "source_parent": CONFIG["source_parent"], "harness_sha": observer,
              "harness_files": harness_files, "files": files}
    write_json(REPORT / ("input-source-" + label + ".json"), result)
    return result


def staged_tree_hash(files: dict) -> str:
    root = {}
    for relative, record in files.items():
        parts = relative.split("/")
        folder = root
        for part in parts[:-1]:
            folder = folder.setdefault(part, {})
        folder[parts[-1]] = (record["mode"], record["git_blob"])

    def visit(folder):
        payload = bytearray()
        for name, value in sorted(folder.items(), key=lambda item: (
                item[0] + ("/" if isinstance(item[1], dict) else "")).encode()):
            if isinstance(value, dict):
                mode, digest = "40000", visit(value)
            else:
                mode, digest = value
            payload.extend((mode + " " + name + "\0").encode())
            payload.extend(bytes.fromhex(digest))
        return hashlib.sha1(b"tree " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
    return visit(root)


def staging_witness(label: str, before: dict, *, allow_report_change: bool) -> dict:
    files = source_files(SOURCE)
    changes = [relative for relative, row in files.items() if row != before["files"][relative]]
    assert set(changes) <= ({REPORT_RELATIVE} if allow_report_change else set()), changes
    status = git("status", "--porcelain", "--untracked-files=all", cwd=SOURCE).decode().splitlines()
    expected_status = [" M " + REPORT_RELATIVE] if changes else []
    assert status == expected_status, status
    result = {"input_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"],
              "staged_tree": staged_tree_hash(files), "source_root": str(SOURCE),
              "only_allowed_report_path": REPORT_RELATIVE, "changed_paths": changes,
              "status": status, "files": files, "immutable_final_source": not changes}
    if not changes:
        assert result["staged_tree"] == CONFIG["source_tree"]
    write_json(REPORT / ("staged-source-" + label + ".json"), result)
    return result


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
        self.steps = []
        self.before = None
        self.name = name
        self.error = None
        self.started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_json(REPORT / "job-start.json", {
            "job": name, "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "harness_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "started_utc": self.started,
            "status": "started", "qualification_complete": False})

    def require(self, condition: object, message: str) -> None:
        if not condition:
            raise AssertionError(message)

    def command(self, name: str, args: list[str], *, cwd: Path = SOURCE,
                timeout: int = 300, env: dict[str, str] | None = None) -> bool:
        passed = command(name, args, cwd, env, timeout, self.steps)
        write_json(REPORT / "steps.json", self.steps)
        return passed

    def finish(self) -> bool:
        unchanged = False
        staged = None
        try:
            after = seed_witness("after")
            unchanged = self.before is not None and self.before == after
            assert unchanged, "Immutable input changed or initial witness unavailable"
            if SOURCE.is_dir():
                staged = staging_witness("final", self.before, allow_report_change=False)
        except Exception as error:
            self.error = self.error or repr(error)
        cleanup_guard = SCRATCH / "unsafe-process-cleanup.json"
        if cleanup_guard.exists():
            write_json(REPORT / "owned-group-cleanup-guard.json", json.loads(cleanup_guard.read_bytes()))
            self.error = self.error or "Original owned process-group cleanup is unverified"
        groups_retired = bool(self.steps) and all(
            step.get("group_cleanup", {}).get("passed") is True for step in self.steps)
        passed = (not self.error and unchanged and groups_retired
                  and all(step.get("passed") for step in self.steps))
        files = {}
        for path in sorted(REPORT.rglob("*")):
            if path.is_file() and path.name not in {"job-outcome.json", "artifact-manifest.json"}:
                raw = path.read_bytes()
                files[path.relative_to(REPORT).as_posix()] = {"sha256": sha256(raw), "bytes": len(raw)}
        write_json(REPORT / "artifact-manifest.json", files)
        outcome = {
            "job": self.name, "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "harness_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "started_utc": self.started,
            "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "finished", "passed": bool(passed), "error": self.error,
            "immutable_input_unchanged": unchanged, "steps": self.steps, "qualification_complete": False,
            "scope": CONFIG["scope"], "all_original_owned_groups_retired": groups_retired,
            "no_complete_descendant_cleanup_certificate": True,
            "workload_source_is_owned_staging_tree": True,
            "staged_tree": staged["staged_tree"] if staged else None,
            "staged_changed_paths": staged["changed_paths"] if staged else None,
            "requires_new_immutable_report_descendant_and_fresh_final_validation": False,
            "immutable_final_source_validation": bool(passed and staged and not staged["changed_paths"])}
        write_json(REPORT / "job-outcome.json", outcome)
        print(json.dumps({key: value for key, value in outcome.items() if key != "steps"}, sort_keys=True))
        return bool(passed)
