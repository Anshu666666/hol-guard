"""Build an explicitly selected diagnostic wheel, separate from shipping builds."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import cast

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.ci.build_claude_pilot_wheel import _prepare_build_interpreter  # noqa: E402

TARGETS = {
    "x86_64-unknown-linux-musl": ("musllinux_1_2_x86_64", "x86_64-linux"),
    "x86_64-apple-darwin": ("macosx_13_0_x86_64", "x86_64-macos"),
    "aarch64-apple-darwin": ("macosx_11_0_arm64", "aarch64-macos"),
    "x86_64-pc-windows-msvc": ("win_amd64", "x86_64-windows"),
}
FEATURE = "diagnostic-native-client"
CAPABILITY = "native-client-profile-v1"
RESIDENT_CAPABILITY = "native-resident-profile-v1"


def _run(argv: list[str], *, environment: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, cwd=_ROOT, env=environment, check=True, text=True, stdout=subprocess.PIPE)
    print(result.stdout, end="", flush=True)
    return result.stdout.strip()


def _validate_capabilities(value: object, source_sha: str, target: str) -> str:
    if not isinstance(value, dict):
        raise ValueError("native_client_profile_capability_mismatch")
    value = cast(dict[str, object], value)
    features = value.get("features")
    rule_digest = value.get("rule_digest")
    if (
        value.get("build_sha") != source_sha
        or value.get("target") != TARGETS[target][1]
        or not isinstance(features, list)
        or not all(isinstance(feature, str) for feature in features)
        or features.count(CAPABILITY) != 1
        or features.count(RESIDENT_CAPABILITY) != 1
        or not isinstance(rule_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", rule_digest) is None
    ):
        raise ValueError("native_client_profile_capability_mismatch")
    return rule_digest


def build(*, target: str, platform_tag: str, destination: Path, source_sha: str) -> Path:
    if target not in TARGETS or platform_tag != TARGETS[target][0]:
        raise ValueError("native_client_profile_target_mismatch")
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ValueError("native_client_profile_source_invalid")
    if _run(["git", "rev-parse", "HEAD"]) != source_sha:
        raise ValueError("native_client_profile_source_mismatch")
    # Reuse the reviewed outside-checkout venv/alias/private-copy admission.
    python = str(_prepare_build_interpreter())
    destination = destination.resolve()
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    version = _run([python, "scripts/sync_repo_version.py", "--check"]).splitlines()[-1]
    _run([python, "-m", "build", "--wheel", "--outdir", str(destination / "pure")])
    environment = dict(os.environ)
    environment.update(HOL_GUARD_BUILD_SHA=source_sha, HOL_GUARD_PACKAGE_VERSION=version)
    _run(
        [
            "cargo",
            "+1.88.0",
            "build",
            "--manifest-path",
            "rust/Cargo.toml",
            "--locked",
            "--release",
            "--target",
            target,
            "-p",
            "hol-guard-runtime",
            "--features",
            FEATURE,
        ],
        environment=environment,
    )
    name = "hol-guard-runtime.exe" if target.endswith("windows-msvc") else "hol-guard-runtime"
    runtime = _ROOT / "rust/target" / target / "release" / name
    rule_digest = _validate_capabilities(json.loads(_run([str(runtime), "capabilities", "--json"])), source_sha, target)
    _run([str(runtime), "self-test", "--json"])
    _run(
        [
            python,
            "scripts/build_native_hol_guard_wheel.py",
            "--wheel",
            str(destination / "pure" / f"hol_guard-{version}-py3-none-any.whl"),
            "--runtime",
            str(runtime),
            "--output-dir",
            str(destination / "native"),
            "--version",
            version,
            "--platform-tag",
            platform_tag,
            "--target",
            target,
            "--source-sha",
            source_sha,
            "--rule-digest",
            rule_digest,
        ]
    )
    wheels = tuple((destination / "native").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("native_client_profile_wheel_count")
    _run(["uv", "pip", "uninstall", "--python", python, "hol-guard"])
    _run(["uv", "pip", "install", "--python", python, "--no-deps", "--force-reinstall", str(wheels[0])])
    return wheels[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-diagnostic", action="store_true", required=True)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--platform-tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    build(target=args.target, platform_tag=args.platform_tag, destination=args.destination, source_sha=args.source_sha)


if __name__ == "__main__":
    main()
