"""Export and verify the exact wheel/dependency bundle shared by pair jobs."""

from __future__ import annotations

import re
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

from scripts.native_slo_artifact import wheel_package_digest
from scripts.native_slo_evidence_files import _plain_path, read_file
from scripts.native_slo_pair_io import canonical, decode, digest_file, require

BASELINE_SHA = "2e672d2d950c6ec471005ddba46e49bba16dc23b"
TARGETS = frozenset(
    {"x86_64-unknown-linux-musl", "x86_64-apple-darwin", "aarch64-apple-darwin", "x86_64-pc-windows-msvc"}
)
BUNDLE_SCHEMA = "hol-guard.qualification-wheel-bundle.v1"
WHEEL_LIMIT = 256 * 1024 * 1024
REQUIREMENTS_LIMIT = 4 * 1024 * 1024
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_WHEEL = re.compile(r"hol_guard-[A-Za-z0-9_.-]+\.whl\Z")


def _psutil_requirement(candidate: Path) -> str:
    import tomllib

    lock = tomllib.loads((candidate / "uv.lock").read_text(encoding="utf-8"))
    packages = [package for package in lock["package"] if package["name"] == "psutil"]
    require(len(packages) == 1, "bundle_psutil_lock_ambiguous")
    package = packages[0]
    version = package["version"]
    require(
        isinstance(version, str) and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version) is not None,
        "bundle_psutil_version_invalid",
    )
    distributions = [*package.get("wheels", []), *([package["sdist"]] if "sdist" in package else [])]
    hashes = sorted({distribution["hash"] for distribution in distributions})
    require(
        bool(hashes) and len(hashes) <= 128 and all(re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in hashes),
        "bundle_psutil_hash_invalid",
    )
    return "psutil==" + version + " \\\n" + " \\\n".join("    --hash=" + value for value in hashes) + "\n"


def export_bundle(
    *,
    destination: Path,
    sources: Mapping[str, Path],
    wheels: Mapping[str, Path],
    metadata: Mapping[str, Mapping[str, object]],
    run: Callable[..., str],
) -> dict[str, object]:
    require(not destination.exists(), "bundle_destination_exists")
    destination.mkdir(parents=True)
    requirement = _psutil_requirement(sources["candidate"])
    arms: dict[str, object] = {}
    for arm in ("baseline", "candidate"):
        root = destination / arm
        root.mkdir()
        wheel = wheels[arm]
        require(_WHEEL.fullmatch(wheel.name) is not None and ".." not in wheel.name, "bundle_wheel_name_invalid")
        installed = root / wheel.name
        shutil.copyfile(wheel, installed)
        requirements = root / "requirements.txt"
        run(
            [
                "uv",
                "export",
                "--frozen",
                "--extra",
                "dev",
                "--no-emit-project",
                "--no-emit-package",
                "psutil",
                "--no-header",
                "--no-annotate",
                "--output-file",
                str(requirements),
            ],
            cwd=sources[arm].resolve(),
        )
        with requirements.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("\n" + requirement)
        info = metadata[arm]
        arms[arm] = {
            "wheel": wheel.name,
            "wheel_sha256": digest_file(installed, WHEEL_LIMIT),
            "package_sha256": wheel_package_digest(installed),
            "requirements_sha256": digest_file(requirements, REQUIREMENTS_LIMIT),
            "lock_sha256": digest_file(sources[arm] / "uv.lock", REQUIREMENTS_LIMIT),
            "build_sha": info["source_sha"],
            "runtime_sha256": info["runtime_sha256"],
            "package_version": info["package_version"],
            "python_version": info["python"],
            "dependency_versions_sha256": info["dependency_versions_sha256"],
        }
    value = {"schema": BUNDLE_SCHEMA, "target": metadata["candidate"]["target"], "arms": arms}
    (destination / "bundle.json").write_bytes(canonical(value) + b"\n")
    load_bundle(destination, target=str(value["target"]), candidate_sha=str(metadata["candidate"]["source_sha"]))
    return value


def load_bundle(root: Path, *, target: str, candidate_sha: str, verify_files: bool = True) -> dict[str, Any]:
    require(target in TARGETS and re.fullmatch(r"[0-9a-f]{40}", candidate_sha) is not None, "bundle_context_invalid")
    _plain_path(root)
    value = decode(read_file(root / "bundle.json", 16 * 1024))
    require(
        set(value) == {"schema", "target", "arms"} and value["schema"] == BUNDLE_SCHEMA and value["target"] == target,
        "bundle_schema_or_target_invalid",
    )
    arms = value["arms"]
    require(isinstance(arms, dict) and set(arms) == {"baseline", "candidate"}, "bundle_arms_invalid")
    for name, expected_sha in (("baseline", BASELINE_SHA), ("candidate", candidate_sha)):
        arm = cast(dict[str, Any], arms)[name]
        require(
            isinstance(arm, dict)
            and set(arm)
            == {
                "wheel",
                "wheel_sha256",
                "package_sha256",
                "requirements_sha256",
                "lock_sha256",
                "build_sha",
                "runtime_sha256",
                "package_version",
                "python_version",
                "dependency_versions_sha256",
            },
            "bundle_arm_invalid",
        )
        require(arm["build_sha"] == expected_sha, "bundle_build_identity_mismatch")
        require(
            isinstance(arm["wheel"], str) and _WHEEL.fullmatch(arm["wheel"]) is not None and ".." not in arm["wheel"],
            "bundle_wheel_name_invalid",
        )
        for key in (
            "wheel_sha256",
            "package_sha256",
            "requirements_sha256",
            "lock_sha256",
            "runtime_sha256",
            "dependency_versions_sha256",
        ):
            require(isinstance(arm[key], str) and _HEX.fullmatch(arm[key]) is not None, "bundle_digest_invalid")
        for key in ("package_version", "python_version"):
            require(
                isinstance(arm[key], str) and re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", arm[key]) is not None,
                "bundle_version_invalid",
            )
        if verify_files:
            wheel = root / name / arm["wheel"]
            require(digest_file(wheel, WHEEL_LIMIT) == arm["wheel_sha256"], "bundle_wheel_digest_mismatch")
            require(wheel_package_digest(wheel) == arm["package_sha256"], "bundle_package_digest_mismatch")
            require(
                digest_file(root / name / "requirements.txt", REQUIREMENTS_LIMIT) == arm["requirements_sha256"],
                "bundle_requirements_digest_mismatch",
            )
    return cast(dict[str, Any], value)
