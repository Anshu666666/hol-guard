"""Fixture signing, private evidence, and source/environment identity for packages."""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import stat
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from scripts.package_benchmark_corpus import canonical, digest


def write_private(path: Path, value: object, *, append: bool = False) -> None:
    if not sys.platform.startswith("linux"):
        raise ValueError("package_matrix_private_files_require_linux")
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise ValueError("package_matrix_private_directory_invalid")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_EXCL)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ValueError("package_matrix_private_file_invalid")
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            for chunk in json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True).iterencode(value):
                stream.write(chunk.encode())
            stream.write(b"\n")
            stream.flush()
    finally:
        os.close(descriptor)


def source_identity(root: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    paths = ["src", "pyproject.toml", "uv.lock"]
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all", "--", *paths], cwd=root):
        raise ValueError("package_matrix_source_dirty")
    names = subprocess.check_output(["git", "ls-files", "-z", "--", *paths], cwd=root).decode().split("\0")
    files = [(name, hashlib.sha256((root / name).read_bytes()).hexdigest()) for name in names if name]
    return {
        "commit": commit,
        "source_sha256": digest(files),
        "uv_lock_sha256": hashlib.sha256((root / "uv.lock").read_bytes()).hexdigest(),
    }


def harness_identity(root: Path) -> str:
    return digest(
        [
            (path.name, hashlib.sha256(path.read_bytes()).hexdigest())
            for path in sorted((root / "scripts").glob("package_benchmark*.py"))
        ]
    )


def environment_identity() -> dict[str, object]:
    distributions = sorted((item.metadata["Name"], item.version) for item in importlib.metadata.distributions())
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "executable_sha256": hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
        "distributions_sha256": digest(distributions),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "ram_bytes": os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"),
        "cpu_model": next(
            (
                line.partition(":")[2].strip()
                for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")
            ),
            "unavailable",
        ),
        "power_mode": "unavailable",
        "installed_artifact": False,
    }


def sign_fixture(value: Mapping[str, object]) -> tuple[dict[str, object], str]:
    """Create an isolated fixture key and real signature before either timed arm."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
        .strip()
    )
    fingerprint = hashlib.sha256(public_pem.encode()).hexdigest()
    payload = canonical(value)
    signature = key.sign(
        payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()
    )
    return {
        "bundle": dict(value),
        "payloadHash": hashlib.sha256(payload).hexdigest(),
        "signature": base64.b64encode(signature).decode(),
        "signatureAlgorithm": "rsa-pss-sha256",
        "verificationKeys": [
            {
                "fingerprintSha256": fingerprint,
                "keyId": "package-matrix-fixture",
                "publicKeyPem": public_pem,
                "state": "active",
                "validUntil": None,
            }
        ],
    }, fingerprint


def compare_pair(baseline: Mapping[str, object], candidate: Mapping[str, object]) -> dict[str, object]:
    """A failed or semantically different arm never yields a speed comparison."""
    for field in (
        "case_id",
        "fixture_sha256",
        "signed_response_sha256",
        "environment",
        "harness_sha256",
        "measurement",
    ):
        if baseline.get(field) != candidate.get(field):
            return {"comparable": False, "reason": "pair_identity_mismatch", "field": field}
    if baseline.get("status") != "completed" or candidate.get("status") != "completed":
        return {"comparable": False, "reason": "incomplete_pair"}
    for field in ("semantic_sha256", "evidence_sha256", "entry_sha256", "protect_sha256"):
        if baseline.get(field) != candidate.get(field):
            return {
                "comparable": False,
                "reason": "contract_difference",
                "field": field,
                "baseline_parser": baseline.get("parser_version"),
                "candidate_parser": candidate.get("parser_version"),
            }
    if baseline.get("measurement") != "timing":
        reason = "validation_only" if baseline.get("measurement") == "validation" else "attribution_only"
        return {"comparable": True, "reason": reason, "performance_qualified": False}
    reductions = {}
    for metric in ("wall", "cpu"):
        before, after = baseline.get(metric + "_ms"), candidate.get(metric + "_ms")
        if not isinstance(before, (float, int)) or not isinstance(after, (float, int)):
            return {"comparable": False, "reason": "timing_invalid"}
        if any(isinstance(value, bool) or not math.isfinite(value) or value <= 0 for value in (before, after)):
            return {"comparable": False, "reason": "timing_invalid"}
        reductions[metric + "_reduction"] = 1 - after / before
    return {"comparable": True, "reason": "matched_source_route", "performance_qualified": False, **reductions}


def load_object(path: Path, *, max_bytes: int = 32 * 1024 * 1024) -> dict[str, object]:
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError("package_matrix_input_too_large")
    with path.open("rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("package_matrix_input_too_large")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("package_matrix_input_invalid")
    return value
