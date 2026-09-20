"""Shared immutable source and bounded subprocess accounting."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

MAX_LOG_BYTES = 16 * 1024 * 1024
COMMANDS: list[dict[str, Any]] = []


def digest(path: Path, maximum: int = MAX_LOG_BYTES) -> dict[str, Any]:
    size, hashed = 0, hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            if size > maximum:
                raise RuntimeError("artifact_read_bound")
            hashed.update(block)
    return {"bytes": size, "sha256": hashed.hexdigest()}


def write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def git(path: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(path), *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    if len(completed.stdout) > 512 * 1024 or len(completed.stderr) > 512 * 1024:
        raise RuntimeError("git_output_bound")
    return completed.stdout.strip()


def source_state(path: Path, expected_sha: str, expected_tree: str | None = None) -> dict[str, Any]:
    state = {
        "head": git(path, "rev-parse", "HEAD"),
        "tree": git(path, "rev-parse", "HEAD^{tree}"),
        "tracked_status": git(path, "status", "--porcelain", "--untracked-files=no"),
    }
    if (
        state["head"] != expected_sha
        or state["tracked_status"]
        or (expected_tree is not None and state["tree"] != expected_tree)
    ):
        raise RuntimeError("immutable_source_binding")
    return state


def verify_files(root: Path, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    verified = []
    for entry in entries:
        relative = entry["path"]
        path = root / relative
        if path.resolve(strict=True) != path or not path.is_file():
            raise RuntimeError("source_file_type")
        observed = digest(path, 2 * 1024 * 1024)
        raw = path.read_bytes()
        observed["git_blob"] = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if any(observed[key] != entry[key] for key in ("bytes", "sha256", "git_blob")):
            raise RuntimeError("source_file_hash")
        verified.append({"path": relative, **observed})
    return verified


def kill_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def run(
    name: str,
    argv: list[str],
    *,
    cwd: Path,
    output: Path,
    environment: dict[str, str] | None = None,
    timeout: float = 360,
    require_success: bool = True,
) -> int:
    if any(row["name"] == name for row in COMMANDS):
        raise RuntimeError("duplicate_command")
    out_path, err_path = output / "commands" / f"{name}.stdout", output / "commands" / f"{name}.stderr"
    started, timed_out, cleanup_confirmed = time.monotonic(), False, True
    process = None
    code = None
    try:
        with out_path.open("wb") as stdout, err_path.open("wb") as stderr:
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                kill_group(process.pid)
                try:
                    code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    cleanup_confirmed = False
    finally:
        record: dict[str, Any] = {
            "name": name,
            "returncode": code,
            "timed_out": timed_out,
            "direct_child_exited": process is not None and process.poll() is not None,
            "timeout_cleanup_confirmed": cleanup_confirmed and not timed_out,
            "elapsed_seconds": time.monotonic() - started,
            "scope": "preparation_or_diagnostic_command_not_headline_workload_timing",
        }
        for kind, path in (("stdout", out_path), ("stderr", err_path)):
            try:
                record[kind] = digest(path)
            except Exception:
                record[kind] = {"available_within_bound": False}
        COMMANDS.append(record)
        write(output / "commands.json", COMMANDS)
    if timed_out or code is None or (require_success and code != 0):
        raise RuntimeError("command_failed:" + name)
    if any(record[kind].get("available_within_bound") is False for kind in ("stdout", "stderr")):
        raise RuntimeError("command_log_bound:" + name)
    return code
