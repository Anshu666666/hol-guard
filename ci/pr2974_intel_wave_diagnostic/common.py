"""Immutable source admission, bounded commands and retained diagnostic reports."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import signal
import subprocess
import time

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_text())
SOURCE = Path(os.environ["VALIDATION_SOURCE"]).resolve(strict=True)
HARNESS = HERE.parents[1]
REPORT = Path(os.environ["VALIDATION_REPORT"]).resolve()
SCRATCH = Path(os.environ["VALIDATION_SCRATCH"]).resolve()
INPUTS = REPORT / "inputs"
COMMANDS = []
GROUP_REFUSAL = False


def digest(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def safe_name(name):
    path = PurePosixPath(name)
    assert name and not path.is_absolute() and ".." not in path.parts and "\\" not in name
    assert all(part not in {"", "."} for part in path.parts)
    return path


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=60, check=False)
    assert result.returncode == 0, {"git_args": args, "stderr": result.stderr.decode(errors="replace")}
    return result.stdout


def header(root):
    raw = git(root, "cat-file", "-p", "HEAD").decode()
    lines = raw.split("\n\n", 1)[0].splitlines()
    return {"sha": git(root, "rev-parse", "HEAD").decode().strip(),
            "tree": next(line[5:] for line in lines if line.startswith("tree ")),
            "parents": [line[7:] for line in lines if line.startswith("parent ")]}


def inventory(root):
    rows = {}
    for entry in git(root, "ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        path = name.decode()
        assert kind == "blob", "Submodules are outside this admission"
        candidate = root / path
        if mode == "120000":
            data = os.readlink(candidate).encode()
        else:
            assert mode in {"100644", "100755"} and candidate.is_file() and not candidate.is_symlink()
            data = candidate.read_bytes()
            assert bool(candidate.stat().st_mode & 0o111) == (mode == "100755"), path
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        assert actual == blob, path
        rows[path] = {"git_blob": blob, "mode": mode, **digest(data)}
    return rows


def source_witness(label):
    source = header(SOURCE)
    assert source == {"sha": CONFIG["source_sha"], "tree": CONFIG["source_tree"],
                      "parents": [CONFIG["source_parent"]]}, source
    rows = inventory(SOURCE)
    assert len(rows) == CONFIG["tracked_files"]
    assert not git(SOURCE, "diff", "--name-only", "HEAD", "--"), "Tracked source changed"
    for path, pin in CONFIG["source_inputs"].items():
        assert rows[path] == pin, path
    value = {"header": source, "files": rows}
    write_json(REPORT / ("source-" + label + ".json"), value)
    return value


def admission():
    REPORT.mkdir(parents=True, exist_ok=True)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    assert not REPORT.is_relative_to(SOURCE) and not SCRATCH.is_relative_to(SOURCE)
    source = source_witness("before")
    harness = header(HARNESS)
    assert harness["sha"] == os.environ["GITHUB_SHA"]
    assert harness["parents"] == [CONFIG["source_sha"]]
    assert os.environ["GITHUB_REF"] == "refs/heads/" + CONFIG["branch"]
    assert os.environ["GITHUB_EVENT_NAME"] == "push" and os.environ["GITHUB_RUN_ATTEMPT"] == "1"
    rows = inventory(HARNESS)
    added = set(rows) - set(source["files"])
    assert added == set(CONFIG["harness_paths"])
    assert {p: v for p, v in rows.items() if p not in added} == source["files"]
    write_json(REPORT / "admission.json", {"source": source["header"], "harness": harness,
               "harness_files": {p: rows[p] for p in sorted(added)},
               "run_id": os.environ["GITHUB_RUN_ID"], "attempt": 1, "event": "push",
               "qualification_complete": False})
    return source


def command(name, arguments, *, env, timeout=120, cwd=SOURCE):
    global GROUP_REFUSAL
    assert not GROUP_REFUSAL, "Earlier owned group was not retired; refuse another command"
    log = REPORT / (name + ".log")
    started = time.monotonic()
    record = {"name": name, "arguments": list(map(str, arguments)), "timeout_seconds": timeout,
              "process_group_scope": "known_new_session_group_only_not_all_possible_descendants"}
    with log.open("wb") as output:
        process = subprocess.Popen(list(map(str, arguments)), cwd=cwd, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        record["pid"] = process.pid
        timed_out = False
        try:
            record["returncode"] = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            record["returncode"] = None
        signals = []
        # This PID was the session/group leader created by this command; never select by process name.
        for sig, bound in ((signal.SIGTERM, 5.0), (signal.SIGKILL, 5.0)):
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            os.killpg(process.pid, sig)
            signals.append(sig.name)
            deadline = time.monotonic() + bound
            while time.monotonic() < deadline:
                process.poll()
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            retired = True
        else:
            retired = False
        record.update(timed_out=timed_out, group_signals=signals, group_absence_observed=retired,
                      elapsed_seconds=time.monotonic() - started, log=digest(log.read_bytes()))
    record["passed"] = record["returncode"] == 0 and not timed_out and retired
    COMMANDS.append(record)
    write_json(REPORT / "commands.json", COMMANDS)
    GROUP_REFUSAL = not retired
    assert retired, "Owned process group remains; refuse following commands"
    return record


def retain_frames():
    members = {}
    total = 0
    for path in sorted(REPORT.rglob("*")):
        if path.is_file() and "inputs" not in path.relative_to(REPORT).parts:
            raw = path.read_bytes()
            total += len(raw)
            assert len(raw) <= 16 * 1024 * 1024 and total <= 48 * 1024 * 1024
            members[path.relative_to(REPORT).as_posix()] = {**digest(raw), "base64": base64.b64encode(raw).decode()}
    raw = json.dumps({"files": members}, sort_keys=True, separators=(",", ":")).encode()
    assert len(raw) <= 64 * 1024 * 1024
    zipped = gzip.compress(raw, mtime=0)
    assert len(zipped) <= 8 * 1024 * 1024
    encoded = base64.b64encode(zipped).decode()
    parts = [encoded[index:index + 6000] for index in range(0, len(encoded), 6000)]
    metadata = {"raw": digest(raw), "gzip": digest(zipped), "parts": len(parts), "members": len(members)}
    print("INTEL_WAVE_FRAME_BEGIN " + json.dumps(metadata, sort_keys=True), flush=True)
    for index, part in enumerate(parts, 1):
        print("INTEL_WAVE_FRAME_PART " + str(index) + "/" + str(len(parts)) + " " + part, flush=True)
    print("INTEL_WAVE_FRAME_END " + json.dumps(metadata, sort_keys=True), flush=True)
