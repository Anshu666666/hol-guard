"""Private experiment paths, exact bytes, bounded commands and JSON receipts."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import time

HERE = Path(__file__).resolve().parent
CONFIG = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
support_raw = (HERE / "source-support.json").read_bytes()
if hashlib.sha256(support_raw).hexdigest() != CONFIG["source_support_sha256"]:
    raise RuntimeError("Frozen source support index changed")
support_inputs = json.loads(support_raw)
if set(support_inputs) & set(CONFIG["source_inputs"]):
    raise RuntimeError("Overlapping frozen source input indexes")
CONFIG["source_inputs"].update(support_inputs)
SOURCE = Path(os.environ["INTEL_SOURCE"]).resolve(strict=True)
HARNESS = Path(os.environ["INTEL_HARNESS"]).resolve(strict=True)
ROOT = Path(os.environ["INTEL_EXPERIMENT_ROOT"]).absolute()
REPORT = ROOT / "reports"
ARTIFACTS = ROOT / "artifacts"
MAX_FILE = CONFIG["bounds"]["projection_per_file_bytes"]
COMMANDS: list[dict] = []
DEADLINES: list[float] = []


@contextmanager
def deadline(seconds: float):
    end = time.monotonic() + seconds
    if DEADLINES:
        end = min(end, min(DEADLINES))
    DEADLINES.append(end)
    try:
        check_deadline()
        yield
        check_deadline()
    finally:
        DEADLINES.pop()


def check_deadline() -> None:
    if DEADLINES:
        require(time.monotonic() < min(DEADLINES), "Frozen outer phase deadline reached")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require(value: object, reason: str) -> None:
    if not value:
        raise RuntimeError(reason)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")
    require(len(raw) <= MAX_FILE, "JSON capture bound: " + str(path))
    temporary = path.with_name(path.name + ".new")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def metadata(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def file_identity(path: Path, *, maximum: int = 1024 * 1024 * 1024,
                  honor_deadline: bool = True) -> dict:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink(), "Expected a regular file: " + str(path))
    require(0 <= before.st_size <= maximum, "File byte bound: " + str(path))
    digest = hashlib.sha256()
    count = 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        require(metadata(os.fstat(stream.fileno())) == metadata(before), "File changed at open")
        while raw := stream.read(1024 * 1024):
            if honor_deadline:
                check_deadline()
            count += len(raw)
            require(count <= maximum, "File grew past bound")
            digest.update(raw)
        require(metadata(os.fstat(stream.fileno())) == metadata(before), "File changed during hash")
    require(metadata(path.lstat()) == metadata(before) and count == before.st_size, "File changed after hash")
    return {"path": str(path), "bytes": count, "sha256": digest.hexdigest(),
            "device": before.st_dev, "inode": before.st_ino,
            "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid,
            "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns}


def content_identity(row: dict) -> dict:
    return {key: row[key] for key in ("bytes", "sha256", "mode")}


def retain_binary(path: Path, name: str) -> dict:
    require("/" not in name and name not in {"", ".", ".."}, "Unsafe retained name")
    before = file_identity(path, maximum=CONFIG["bounds"]["complete_binary_or_wheel_member_bytes"])
    destination = ARTIFACTS / name
    require(not destination.exists(), "Refuse retained artifact replacement")
    with path.open("rb") as original, destination.open("xb") as output:
        while raw := original.read(1024 * 1024):
            output.write(raw)
    os.chmod(destination, before["mode"])
    retained = file_identity(destination)
    require(content_identity(before) == content_identity(retained), "Retained artifact bytes differ")
    require(file_identity(path) == before, "Source artifact changed while retaining")
    return {"original": before, "retained": retained}


def helper_argv(module: str, *arguments: object, python: Path | None = None) -> list[str]:
    import sys
    return [str(python or Path(sys.executable)), "-I", "-B", str(HERE / "entry.py"),
            module, *map(str, arguments)]


def clean_environment() -> dict[str, str]:
    blocked = [name for name in os.environ
               if name in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "PYTHONPATH", "PYTHONOPTIMIZE",
                           "PYTEST_ADDOPTS", "PYTEST_PLUGINS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"}
               or name.startswith(("CARGO_PROFILE_", "HOL_GUARD_", "GUARD_"))]
    require(not blocked, "Unexpected inherited overrides: " + repr(sorted(blocked)))
    environment = {
        "HOME": os.environ["HOME"], "USER": os.environ["USER"],
        "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": str(ROOT / "tmp"), "TMP": str(ROOT / "tmp"), "TEMP": str(ROOT / "tmp"),
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
        "UV_NO_CONFIG": "1", "UV_NO_PROGRESS": "1", "UV_PYTHON_DOWNLOADS": "never",
        "UV_CACHE_DIR": str(ROOT / "uv-cache"),
        "CARGO_HOME": str(ROOT / "cargo-home"), "RUSTUP_HOME": str(ROOT / "rustup-home"),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    return environment


def helper_environment(environment: dict[str, str]) -> dict[str, str]:
    return environment | {
        "INTEL_SOURCE": str(SOURCE), "INTEL_HARNESS": str(HARNESS),
        "INTEL_EXPERIMENT_ROOT": str(ROOT),
    }


def command(name: str, argv: list[str], *, environment: dict[str, str],
            timeout: float, cwd: Path = ROOT) -> dict:
    from owned_process import capture_command
    check_deadline()
    if DEADLINES:
        timeout = min(timeout, max(0.001, min(DEADLINES) - time.monotonic()))
    row = capture_command(name, argv, environment=environment, timeout=timeout, cwd=cwd)
    COMMANDS.append(row)
    write_json(REPORT / "commands.json", COMMANDS)
    return row


def successful(row: dict) -> bool:
    return row["returncode"] == 0 and row["capture_complete"] and row["cleanup"]["safe_to_continue"]


def json_stdout(row: dict) -> object:
    require(successful(row), "Command failed before JSON admission: " + row["name"])
    raw = Path(row["stdout"]["path"]).read_bytes()
    require(len(raw) <= MAX_FILE, "JSON output bound")
    return json.loads(raw)


def phase_record(variant: str, phase: str, state: str, **details: object) -> None:
    write_json(REPORT / variant / (phase + "-outcome.json"),
               {"variant": variant, "phase": phase, "state": state, **details,
                "qualification_complete": False, "production_candidate_eligible": False})
