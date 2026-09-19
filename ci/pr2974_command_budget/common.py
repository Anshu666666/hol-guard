"""Bounded helpers for paired command-corpus diagnosis."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "config.json").read_text())
HARNESS = Path(os.environ["BUDGET_HARNESS"]).resolve()
REPORT = Path(os.environ["BUDGET_REPORT"]).resolve()
SCRATCH = Path(os.environ["BUDGET_SCRATCH"]).resolve()
ROOT = Path(os.environ["GITHUB_WORKSPACE"]).resolve()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE, timeout=90)


def headers(root: Path, commit: str) -> dict[str, object]:
    lines = git(root, "cat-file", "-p", commit).split(b"\n\n", 1)[0].decode().splitlines()
    return {"tree": next(line[5:] for line in lines if line.startswith("tree ")),
            "parents": [line[7:] for line in lines if line.startswith("parent ")]}


def witness(name: str, label: str) -> dict[str, object]:
    root = ROOT / name
    expected = CONFIG["sources"][name]
    assert root != HARNESS and not root.is_relative_to(HARNESS)
    assert not REPORT.is_relative_to(root) and not SCRATCH.is_relative_to(root)
    assert git(root, "rev-parse", "HEAD").decode().strip() == expected["sha"]
    assert headers(root, expected["sha"]) == {"tree": expected["tree"], "parents": expected["parents"]}
    files = {}
    for entry in git(root, "ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0"):
        if not entry:
            continue
        prefix, raw_path = entry.split(b"\t", 1)
        mode, kind, blob = prefix.decode().split()
        path = raw_path.decode()
        assert kind == "blob" and mode in {"100644", "100755"}, path
        target = root / path
        info = target.lstat()
        assert stat.S_ISREG(info.st_mode), path
        assert bool(info.st_mode & 0o111) == (mode == "100755"), path
        data = target.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        assert actual == blob, path
        files[path] = {"git_blob": blob, "sha256": sha256(data), "bytes": len(data), "mode": mode}
    assert len(files) == expected["tracked_files"]
    assert not git(root, "status", "--porcelain", "--untracked-files=no").strip()
    for path, blob in CONFIG["equal_input_blobs"].items():
        assert files[path]["git_blob"] == blob, path
    fixture = files["tests/fixtures/guard-command-corpus/decision-diff-report.json"]
    assert fixture["sha256"] == CONFIG["fixture_reports"][name]["file_sha256"]
    seed = json.loads((root / "tests/fixtures/guard-command-corpus/seed-manifest.json").read_text())
    assert int(seed["evaluation_budget_seconds"]) == CONFIG["evaluation_budget_seconds"] == 60
    assert int(seed["evaluation_rss_budget_mib"]) == CONFIG["evaluation_rss_budget_mib"] == 512
    result = {"source": name, **expected, "files": files}
    write_json(REPORT / name / ("source-" + label + ".json"), result)
    return result


def harness_witness() -> None:
    assert os.environ["GITHUB_EVENT_NAME"] == "push"
    assert os.environ["GITHUB_REF"] == "refs/heads/" + CONFIG["branch"]
    assert os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    sha = git(HARNESS, "rev-parse", "HEAD").decode().strip()
    assert sha == os.environ["GITHUB_SHA"]
    assert headers(HARNESS, sha)["parents"] == [CONFIG["source_parent"]]
    expected = {".github/workflows/pr2974-command-budget.yml"}
    expected.update("ci/pr2974_command_budget/" + path.name for path in HERE.iterdir() if path.is_file())
    changes = git(HARNESS, "diff-tree", "--no-commit-id", "--name-status", "-r",
                  CONFIG["source_parent"], sha).decode().splitlines()
    assert set(changes) == {"A\t" + path for path in expected}, changes
    assert len(changes) == len(expected)
    write_json(REPORT / "harness.json", {"sha": sha, "headers": headers(HARNESS, sha),
                                       "added_paths": sorted(expected), "scope": CONFIG["scope"]})


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

def frame(label: str, value: object) -> None:
    text = json.dumps(value, sort_keys=True, indent=2) + "\n"
    data = text.encode()
    assert len(data) <= 1500000, "Refuse oversized log projection; artifact retains full report"
    parts = [text[index:index + 5000] for index in range(0, len(text), 5000)]
    common = {"label": label, "bytes": len(data), "sha256": sha256(data)}
    print(json.dumps({"frame": "begin", **common, "chunks": len(parts)}), flush=True)
    for index, part in enumerate(parts):
        print(json.dumps({"frame": "chunk", "label": label, "index": index, "text": part}), flush=True)
    print(json.dumps({"frame": "end", **common}), flush=True)
