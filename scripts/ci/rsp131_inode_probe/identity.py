"""Bound regular source/tool bytes and retain the actual unprivileged environment."""

from __future__ import annotations

import gzip
import hashlib
import importlib.metadata
import os
import platform
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

MAX_FILE = 256 * 1024 * 1024
CONFIG_KEYS = (
    "CONFIG_BPF", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_JIT", "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_KPROBES", "CONFIG_UPROBES", "CONFIG_FTRACE",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fields(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def file_identity(path: Path, maximum: int = MAX_FILE) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
            raise ValueError("regular_file_bound")
        hasher = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise ValueError("file_truncated")
            hasher.update(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise ValueError("file_grew")
        after = os.fstat(descriptor)
        if _fields(before) != _fields(after) or _fields(after) != _fields(path.stat(follow_symlinks=False)):
            raise ValueError("file_identity_changed")
    finally:
        os.close(descriptor)
    return {"sha256": hasher.hexdigest(), "bytes": before.st_size, "device": before.st_dev, "inode": before.st_ino}


def _small(path: Path, maximum: int = 64 * 1024) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("metadata_bound")
    return data


def distributions() -> dict[str, Any]:
    expected = {
        "pytest": "9.0.3", "iniconfig": "2.3.0", "packaging": "26.0",
        "pluggy": "1.6.0", "pygments": "2.20.0",
    }
    prefix = Path(sys.prefix).resolve()
    result: dict[str, Any] = {}
    total = 0
    for name, version in expected.items():
        distribution = importlib.metadata.distribution(name)
        files = distribution.files
        if distribution.version != version or files is None or not 1 <= len(files) <= 2048:
            raise ValueError("finite_runner_distribution")
        rows = {}
        for relative in files:
            path = Path(distribution.locate_file(relative)).resolve(strict=True)
            if not path.is_relative_to(prefix) or "__pycache__" in path.parts or path.suffix == ".pyc":
                raise ValueError("finite_runner_file_boundary")
            row = file_identity(path, maximum=4 * 1024 * 1024)
            total += row["bytes"]
            if total > 64 * 1024 * 1024:
                raise ValueError("finite_runner_file_bound")
            rows[str(path.relative_to(prefix))] = row
        result[name] = {"version": version, "files": rows}
    return result


def environment(compiler: Path) -> dict[str, Any]:
    status = {}
    selected = {"CapEff", "CapBnd", "NoNewPrivs", "Seccomp", "Seccomp_filters", "TracerPid"}
    for line in _small(Path("/proc/self/status")).decode("ascii").splitlines():
        key, _, value = line.partition(":")
        if key in selected:
            status[key] = value.strip()
    yama: dict[str, Any]
    try:
        data = _small(Path("/proc/sys/kernel/yama/ptrace_scope"), 128)
        yama = {"available": True, "value": data.decode("ascii").strip(), "sha256": digest(data)}
    except OSError as error:
        yama = {"available": False, "error_type": type(error).__name__, "errno": error.errno}
    config: dict[str, Any] = {"available": False, "flags": {key: None for key in CONFIG_KEYS}}
    for path in (Path("/boot") / ("config-" + platform.release()), Path("/proc/config.gz")):
        try:
            if path.suffix == ".gz":
                with gzip.open(path, "rb") as stream:
                    data = stream.read(2 * 1024 * 1024 + 1)
            else:
                data = _small(path, 2 * 1024 * 1024)
            if len(data) > 2 * 1024 * 1024:
                raise ValueError("kernel_config_bound")
            lines = set(data.decode("ascii").splitlines())
            config = {
                "available": True, "source": path.name, "sha256": digest(data),
                "flags": {
                    key: next((value for value in ("y", "m", "n") if key + "=" + value in lines),
                              "n" if "# " + key + " is not set" in lines else None)
                    for key in CONFIG_KEYS
                },
            }
            break
        except OSError:
            continue
    btf = Path("/sys/kernel/btf/vmlinux")
    return {
        "system": platform.system(), "machine": platform.machine(), "release": platform.release(),
        "version": platform.version(), "uid": os.getuid(), "euid": os.geteuid(),
        "gid": os.getgid(), "groups": sorted(os.getgroups()), "status": status,
        "yama": yama, "kernel_config": config, "vmlinux_btf_path_exists": btf.exists(),
        "finite_runner_distributions": distributions(),
        "python_version": sys.version, "python_executable": file_identity(Path(sys.executable).resolve()),
        "compiler_executable": file_identity(compiler), "compiler_basename": compiler.name,
        "reviewed_prior_kernel_series": "6.8", "previous_observed_kernel": "6.18.44",
        "privilege_changes_attempted": False, "bpf_or_perf_attachment_attempted": False,
        "complete_toolchain_attestation": False,
    }


def git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments], check=True, capture_output=True, timeout=10,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if len(completed.stdout) > 64 * 1024 or len(completed.stderr) > 64 * 1024:
        raise ValueError("git_output_bound")
    return completed.stdout.decode("utf-8").strip()


def source_snapshot(root: Path, commit: str, paths: list[str]) -> dict[str, Any]:
    if git(root, "rev-parse", "HEAD") != commit:
        raise ValueError("checkout_commit_changed")
    result = {}
    for relative in paths:
        path = root / relative
        identity = file_identity(path, maximum=256 * 1024)
        data = path.read_bytes()
        if len(data) != identity["bytes"] or digest(data) != identity["sha256"]:
            raise ValueError("source_read_changed")
        blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        entry = git(root, "ls-tree", commit, "--", relative)
        if entry != "100644 blob " + blob + "\t" + relative:
            raise ValueError("source_git_binding")
        result[relative] = identity | {"git_blob": blob}
    return result
