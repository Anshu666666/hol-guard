"""Admit complete frozen source, isolated harness and exact selected host tools."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import shutil
import sys
import tomllib

from common import (
    CONFIG, HARNESS, HERE, REPORT, ROOT, SOURCE, clean_environment, command,
    content_identity, file_identity, require, successful, write_json,
)


def capture_text(name: str, arguments: list[str], environment: dict[str, str], timeout: int = 30) -> str:
    row = command(name, arguments, environment=environment, timeout=timeout)
    require(successful(row), "Input command failed: " + name)
    return Path(row["stdout"]["path"]).read_text(encoding="utf-8").strip()


def git(name: str, root: Path, arguments: list[str], context: dict) -> bytes:
    row = command(name, [context["tools"]["git"]["path"], "-C", str(root), *arguments],
                  environment=context["environment"], timeout=60)
    require(successful(row), "Frozen Git input read failed: " + name)
    return Path(row["stdout"]["path"]).read_bytes()


def source_witness(label: str, context: dict) -> dict:
    header = git("source-header-" + label, SOURCE, ["cat-file", "-p", "HEAD"], context)
    commit = git("source-sha-" + label, SOURCE, ["rev-parse", "HEAD"], context).decode().strip()
    lines = header.split(b"\n\n", 1)[0].decode().splitlines()
    require(commit == CONFIG["source_sha"], "Source commit differs")
    require([line[5:] for line in lines if line.startswith("tree ")] == [CONFIG["source_tree"]],
            "Source tree differs")
    require([line[7:] for line in lines if line.startswith("parent ")] == [CONFIG["source_parent"]],
            "Source parent differs")
    entries = git("source-tree-" + label, SOURCE, ["ls-tree", "-rz", "--full-tree", "HEAD"], context)
    files = {}
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        prefix, name = entry.split(b"\t", 1)
        mode, kind, blob = prefix.decode().split()
        path = name.decode("utf-8")
        require(kind == "blob" and mode in {"100644", "100755"}, "Unsupported source leaf")
        actual = SOURCE / path
        pin = file_identity(actual)
        raw = actual.read_bytes()
        expected = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(expected == blob and file_identity(actual) == pin, "Tracked source bytes differ: " + path)
        require(bool(pin["mode"] & 0o111) == (mode == "100755"), "Source mode differs: " + path)
        files[path] = {"git_blob": blob, "git_mode": mode, **content_identity(pin)}
    require(len(files) == CONFIG["tracked_files"], "Source population differs")
    for path, pin in CONFIG["source_inputs"].items():
        require(files[path]["git_blob"] == pin["git_blob"], "Provider source mismatch: " + path)
    require(not git("source-status-" + label, SOURCE,
                    ["status", "--porcelain=v1", "--untracked-files=all"], context).strip(),
            "Frozen source gained changed or untracked files")
    value = {"sha": commit, "tree": CONFIG["source_tree"], "files": files}
    write_json(REPORT / ("source-" + label + ".json"), value)
    return value


def reachable_cargo_configs(context: dict) -> dict:
    candidates = {ROOT / "cargo-home" / name for name in ("config", "config.toml")}
    for location in (SOURCE / "rust", SOURCE, ROOT):
        for directory in (location, *location.parents):
            candidates.update(directory / ".cargo" / name for name in ("config", "config.toml"))
    rows = {}
    for path in sorted(candidates):
        if path.exists() or path.is_symlink():
            require(not path.is_symlink(), "Symlinked Cargo config")
            rows[str(path)] = {"identity": file_identity(path), "content": path.read_text(encoding="utf-8")}
    write_json(REPORT / "cargo-config-census.json", {"existing": rows, "all_considered": list(map(str, sorted(candidates)))})
    require(not rows, "Unplanned reachable Cargo configuration")
    return rows


def host_witness(label: str, context: dict) -> dict:
    env = context["environment"]
    result = {
        "system": platform.system(), "machine": platform.machine(), "python": platform.python_version(),
        "uname": list(os.uname()), "uid": os.getuid(), "gid": os.getgid(),
        "sw_vers": capture_text("host-sw-vers-" + label, ["/usr/bin/sw_vers"], env),
        "boot": capture_text("host-boot-" + label, ["/usr/sbin/sysctl", "-n", "kern.boottime"], env),
        "cpu": capture_text("host-cpu-" + label, ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], env),
        "tools": {name: file_identity(Path(pin["path"])) for name, pin in context["tools"].items()},
    }
    if "sdk" in context:
        sdk = context["sdk"]
        result["sdk"] = sdk | {
            "settings": {name: file_identity(Path(sdk["path"]) / name)
                         for name in ("SDKSettings.json", "SDKSettings.plist")
                         if (Path(sdk["path"]) / name).is_file()}
        }
    write_json(REPORT / ("host-" + label + ".json"), result)
    return result


def start() -> dict:
    require(__debug__ and sys.flags.isolated and sys.dont_write_bytecode, "Assertions/-I/-B required")
    require(platform.system() == "Darwin" and platform.machine() == "x86_64", "Intel macOS only")
    require(platform.python_version() == CONFIG["python_version"], "Python version mismatch")
    require(not ROOT.exists() and not ROOT.is_symlink(), "Experiment root must be previously absent")
    require(ROOT.parent.resolve(strict=True) == ROOT.parent, "Root parent must be canonical")
    require(SOURCE != HARNESS and not SOURCE.is_relative_to(HARNESS) and not HARNESS.is_relative_to(SOURCE),
            "Separate immutable source and harness required")
    require(not ROOT.is_relative_to(SOURCE) and not ROOT.is_relative_to(HARNESS), "Owned output outside checkouts")
    ROOT.mkdir(mode=0o700)
    for name in ("reports", "artifacts", "tmp", "cargo-home", "rustup-home", "uv-cache",
                 "targets", "wheels", "venvs", "backend-wheels", "pure-wheel", "raw-commands"):
        (ROOT / name).mkdir(mode=0o700)
    empty_targets = {}
    for variant in ("baseline", "candidate"):
        target = ROOT / "targets" / variant
        target.mkdir(mode=0o700)
        info = target.lstat()
        require(not any(target.iterdir()), "New target directory is not empty")
        empty_targets[variant] = {"path": str(target), "device": info.st_dev,
                                  "inode": info.st_ino, "empty": True}
    write_json(REPORT / "initial-empty-targets.json", empty_targets)
    environment = clean_environment()
    tools = {}
    for name in ("git", "uv", "rustup"):
        selected = shutil.which(name)
        require(selected is not None, "Missing preflight tool: " + name)
        tools[name] = file_identity(Path(selected).resolve(strict=True))
    tools["python"] = file_identity(Path(sys.executable).resolve(strict=True))
    require(file_identity(SOURCE / "scripts/native_qualification_process.py")["sha256"]
            == CONFIG["source_inputs"]["scripts/native_qualification_process.py"]["sha256"],
            "Actual current WNOWAIT observer differs")
    from process_controls import run_control
    run_control()
    context = {"environment": environment, "tools": tools}
    write_json(REPORT / "preflight-raw.json", context)
    require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1" and os.environ.get("GITHUB_EVENT_NAME") == "push",
            "Only the first push-triggered attempt is admitted")
    require(os.environ.get("GITHUB_REF") == "refs/heads/" + CONFIG["branch"], "Unexpected event branch")
    require(os.environ.get("GITHUB_WORKFLOW") == CONFIG["workflow_name"], "Unexpected workflow")
    sha = git("harness-sha", HARNESS, ["rev-parse", "HEAD"], context).decode().strip()
    require(sha == os.environ["GITHUB_SHA"], "Harness/event SHA mismatch")
    headers = git("harness-header", HARNESS, ["cat-file", "-p", "HEAD"], context).decode().split("\n\n", 1)[0]
    require([line[7:] for line in headers.splitlines() if line.startswith("parent ")] == [CONFIG["source_sha"]],
            "Harness must be a sole-parent addition to the frozen source")
    changes = git("harness-delta", HARNESS,
                  ["diff-tree", "--no-commit-id", "--name-status", "-r", CONFIG["source_sha"], sha], context)
    require(changes.decode().splitlines() == ["A\t" + path for path in sorted(CONFIG["harness_paths"])],
            "Harness has unexpected source modifications")
    added = git("harness-added-blobs", HARNESS,
                ["ls-tree", "-rz", "--full-tree", "HEAD", "--", *CONFIG["harness_paths"]], context)
    actual_added = {}
    for entry in added.split(b"\0"):
        if not entry:
            continue
        prefix, name = entry.split(b"\t", 1)
        mode, kind, blob = prefix.decode().split()
        path = name.decode("utf-8")
        require(kind == "blob" and mode in {"100644", "100755"}, "Unexpected harness leaf")
        pin = file_identity(HARNESS / path)
        raw = (HARNESS / path).read_bytes()
        actual_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(actual_blob == blob and file_identity(HARNESS / path) == pin,
                "Harness working bytes differ from actual Git input: " + path)
        require(bool(pin["mode"] & 0o111) == (mode == "100755"), "Harness executable mode differs")
        actual_added[path] = {"git_blob": blob, **pin}
    require(sorted(actual_added) == sorted(CONFIG["harness_paths"]), "Harness input population differs")
    require(not git("harness-status", HARNESS, ["status", "--porcelain=v1", "--untracked-files=all"],
                    context).strip(), "Harness checkout is not clean")
    write_json(REPORT / "harness-added-inputs.json", actual_added)
    helper_files = {str(path.relative_to(HARNESS)): file_identity(path)
                    for path in sorted(HERE.rglob("*")) if path.is_file()}
    write_json(REPORT / "harness-inputs.json", {"sha": sha, "files": helper_files})
    for relative, digest in CONFIG["helper_sha256"].items():
        require(file_identity(HERE / relative)["sha256"] == digest, "Helper changed: " + relative)
    require(capture_text("uv-version", [tools["uv"]["path"], "--version"], environment)
            .split()[:2] == ["uv", CONFIG["uv_version"]], "uv version mismatch")
    reachable_cargo_configs(context)
    context["source_before"] = source_witness("before", context)
    context["host_initial"] = host_witness("initial", context)
    context["version"] = tomllib.loads((SOURCE / "pyproject.toml").read_text())["project"]["version"]
    require(context["version"] == CONFIG["project_version"], "Frozen project version differs")
    return context
