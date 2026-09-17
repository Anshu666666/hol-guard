"""Fixed Linux source-CLI experiment identities, plan and private records."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from scripts.native_slo_dependency_identity import dependency_versions_digest
from scripts.native_slo_evidence_files import atomic_exclusive, read_file
from scripts.native_slo_evidence_format import canonical, digest
from scripts.scanner_pilot_identity import (
    ExecutableIdentityError,
    IdentityError,
    executable_digest,
    resolved_executable_digest,
)

CASES = (
    "working_provider_small",
    "working_provider_many",
    "working_provider_large",
    "staged_provider_diverged",
    "staged_provider_repeated",
    "history_provider_repeated",
    "working_many_unique",
)
STATES = ("prewarmed", "evicted")
ARMS = ("optimized_python", "native_regex_pilot")
RUNS, PAIRS, ATTEMPTS = 5, 6, 24
COMMAND_SECONDS, CONTROLLER_SECONDS = 120, 6000
RECIPIENT = "d06561fc3cfc12925ed72bbe6967ff681c3a14b869f35debf540b43a26ff21eb"
SCHEMA = "hol-guard.scanner-regex-pilot.v1"
MAX_PRIVATE = 120 * 1024 * 1024
MAX_RECORD = 24 * 1024 * 1024


class BudgetExceededError(TimeoutError):
    """The fixed collector budget elapsed; remaining planned work is unoffered."""


def planned(case: str, run: int) -> list[dict[str, Any]]:
    if case not in CASES or type(run) is not int or not 0 <= run < RUNS:
        raise ValueError("scanner_plan_invalid")
    return [
        {"id": f"{state}-{pair}-{arm}", "state": state, "pair": pair, "arm": arm}
        for state in STATES
        for pair in range(PAIRS)
        for arm in (ARMS if (run + pair) % 2 == 0 else tuple(reversed(ARMS)))
    ]


def private_write(directory: Path, name: str, value: object) -> str:
    data = canonical(value)
    if len(data) > MAX_RECORD or sum(p.stat().st_size for p in directory.iterdir()) + len(data) > MAX_PRIVATE:
        raise ValueError("scanner_private_byte_bound")
    atomic_exclusive(directory / name, data)
    return digest(data)


def git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *arguments], timeout=30, text=True).strip()


def identities(root: Path, binary: Path, expected: str) -> dict[str, Any]:
    try:
        return _identities(root, binary, expected)
    except IdentityError:
        raise
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise IdentityError("source_identity_failed") from error


def _identity_stage(operation: Any, code: str) -> Any:
    try:
        return operation()
    except (OSError, ValueError) as error:
        diagnostic = error.diagnostic if isinstance(error, ExecutableIdentityError) else None
        raise IdentityError(code, diagnostic) from error


def _identities(root: Path, binary: Path, expected: str) -> dict[str, Any]:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("scanner_host_unsupported")
    if git(root, "rev-parse", "HEAD") != expected or git(root, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("scanner_source_not_frozen")
    files = sorted((root / "src/codex_plugin_scanner/guard/secrets").glob("*.py"))
    files += sorted((root / "src/codex_plugin_scanner/checks").glob("security*.py"))
    scanner = hashlib.sha256()
    for path in files:
        scanner.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes())
    scripts = [
        *sorted((root / "scripts").glob("scanner_pilot_*.py")),
        root / "scripts/secret_scan_native_pilot.py",
        root / "scripts/bench_guard_secret_scans.py",
        root / "scripts/secret_scan_benchmark_cache.py",
        root / "scripts/secret_scan_benchmark_fixtures.py",
    ]
    return {
        "source_sha": expected,
        "source_tree": git(root, "rev-parse", "HEAD^{tree}"),
        "python_source_tree": git(root, "rev-parse", "HEAD:src"),
        "scanner_sha256": scanner.hexdigest(),
        "lock_sha256": digest((root / "uv.lock").read_bytes()),
        "rust_lock_sha256": digest((root / "rust/Cargo.lock").read_bytes()),
        "pilot_tree": git(root, "rev-parse", "HEAD:rust/crates/guard-offline-regex-pilot"),
        "harness_sha256": digest(canonical({p.relative_to(root).as_posix(): digest(p.read_bytes()) for p in scripts})),
        "dependency_sha256": _identity_stage(dependency_versions_digest, "dependency_identity_failed"),
        "python_sha256": _identity_stage(
            lambda: resolved_executable_digest(Path(sys.executable)), "python_executable_identity_failed"
        ),
        "binary_sha256": _identity_stage(lambda: executable_digest(binary), "native_executable_identity_failed"),
        "python_version": list(sys.version_info[:3]),
        "host": {
            "system": "linux",
            "architecture": "x86_64",
            "logical_cpus": os.cpu_count(),
            # GitHub runner-images defines these case-sensitive names.
            "image_identity_available": all(os.environ.get(key) for key in ("ImageOS", "ImageVersion")),
            "runner_image_sha256": digest(canonical({key: os.environ.get(key) for key in ("ImageOS", "ImageVersion")})),
            "kernel_sha256": digest(platform.release().encode()),
        },
    }


def fixture_identity(root: Path, workload: Any, dimensions: dict[str, Any]) -> dict[str, Any]:
    entries = []
    total = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        data = read_file(path, 16 * 1024 * 1024)
        total += len(data)
        if len(entries) >= 5000 or total > 16 * 1024 * 1024:
            raise ValueError("scanner_fixture_byte_bound")
        entries.append({"path": path.relative_to(root).as_posix(), **captured(data)})
    value = {"definition": asdict(workload), "dimensions": dimensions, "files": entries}
    return {**value, "sha256": digest(canonical(value))}


def captured(data: bytes) -> dict[str, Any]:
    return {"bytes": len(data), "sha256": digest(data), "base64": base64.b64encode(data).decode("ascii")}


def read_json(path: Path, maximum: int = MAX_RECORD) -> dict[str, Any]:
    value = json.loads(read_file(path, maximum))
    if not isinstance(value, dict):
        raise ValueError("scanner_record_invalid")
    return value


def environment(root: Path) -> dict[str, str]:
    result = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("HOL_GUARD_", "GUARD_")) and key not in {"PYTHONPATH", "PYTEST_CURRENT_TEST"}
    }
    result["PYTHONPATH"] = os.pathsep.join((str(root / "src"), str(root / "scripts")))
    result["PYTHONHASHSEED"] = "0"
    return result
