"""Exact existing wheel admission function, isolated from unrelated cohorts."""

from __future__ import annotations

import hashlib
import importlib.metadata
import sys
from pathlib import Path
from typing import Any

from ci.native_runtime import probe_installed_pi_output as existing
from scripts.native_slo_artifact import assert_installed_import_origin, installed_package_digest, wheel_package_digest
from scripts.native_slo_contract import proof_environment_violations


def admit_installed(wheel: Path, source_sha: str) -> tuple[dict[str, object], Any, Any]:
    if not sys.flags.isolated or proof_environment_violations():
        raise RuntimeError("installed_pi_invocation_not_admitted")
    if len(source_sha) != 40 or any(char not in "0123456789abcdef" for char in source_sha):
        raise ValueError("installed_pi_source_sha_invalid")
    distribution = importlib.metadata.distribution("hol-guard")
    existing._installed_package_path(Path(__file__).resolve().parents[3])
    assert_installed_import_origin(distribution)
    package_digest = installed_package_digest(distribution)
    if package_digest != wheel_package_digest(wheel):
        raise RuntimeError("installed_pi_wheel_content_mismatch")
    status, identity, capabilities = existing._probe_native_identity()
    if capabilities.build_sha != source_sha:
        raise RuntimeError("installed_pi_native_source_mismatch")
    digest = hashlib.sha256()
    with wheel.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return (
        {
            "wheel_sha256": digest.hexdigest(),
            "installed_package_sha256": package_digest,
            "package_version": distribution.version,
            "build_sha": source_sha,
            "target": capabilities.target,
            "runtime_sha256": identity.sha256,
            "rule_digest": capabilities.rule_digest,
            "runtime_version": capabilities.runtime_version,
            "mode": status.mode,
        },
        distribution,
        identity,
    )
