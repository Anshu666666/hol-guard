#!/usr/bin/env python3
"""Install one immutable platform bundle, then collect one global pair index."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.native_slo_interpreter import prepare_private_interpreter  # noqa: E402
from scripts.native_slo_pair_io import require  # noqa: E402
from scripts.native_slo_qualification_bundle import load_bundle  # noqa: E402


def interpreter(root: Path, arm: str) -> Path:
    return root / arm / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def install_bundle(bundle_root: Path, environment_root: Path, *, target: str, candidate_sha: str) -> None:
    bundle = load_bundle(bundle_root, target=target, candidate_sha=candidate_sha)
    destination = environment_root.resolve()
    require(not destination.is_relative_to(_ROOT) and not destination.exists(), "pair_install_destination_invalid")
    destination.mkdir(parents=True)
    for arm in ("baseline", "candidate"):
        expected = bundle["arms"][arm]
        require(expected["python_version"] == ".".join(map(str, sys.version_info[:3])), "pair_build_python_mismatch")
        python = interpreter(destination, arm)
        subprocess.run(["uv", "venv", "--python", sys.executable, str(destination / arm)], check=True)
        proof = prepare_private_interpreter(python, environment_root=destination / arm)
        print(json.dumps({"arm": arm, "qualification_interpreter": proof}, sort_keys=True), flush=True)
        subprocess.run(
            [
                "uv",
                "pip",
                "sync",
                "--require-hashes",
                "--python",
                str(python),
                str(bundle_root / arm / "requirements.txt"),
            ],
            check=True,
        )
        subprocess.run(
            ["uv", "pip", "install", "--python", str(python), "--no-deps", str(bundle_root / arm / expected["wheel"])],
            check=True,
        )
        inventory = subprocess.run(
            [str(python), "-I", str(_ROOT / "scripts/native_slo_dependency_identity.py")],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        require(
            inventory.stdout.strip() == expected["dependency_versions_sha256"], "pair_installed_dependency_mismatch"
        )


def command(args: argparse.Namespace, bundle: dict[str, Any]) -> list[str]:
    python = interpreter(args.environments.resolve(), "candidate")
    if args.action == "ollama":
        return [
            str(python),
            str(_ROOT / "scripts/ci/verify_native_ollama_install.py"),
            "--python",
            str(python),
            "--wheel",
            str(args.bundle / "candidate" / bundle["arms"]["candidate"]["wheel"]),
            "--source-root",
            str(_ROOT),
            "--source-sha",
            args.candidate_sha,
            "--output",
            str(args.output / "aggregate/installed-ollama.json"),
        ]
    runs = 5 if args.mode == "qualification" else 1
    require(type(args.pair_index) is int and 0 <= args.pair_index < runs, "pair_index_invalid")
    return [
        sys.executable,
        str(_ROOT / "scripts/ci/native_loopback_resolver.py"),
        "--output",
        str(args.output / "aggregate/runner-resolver.json"),
        "--",
        str(python),
        str(_ROOT / "scripts/qualify_guard_native.py"),
        "--baseline-python",
        str(interpreter(args.environments.resolve(), "baseline")),
        "--candidate-python",
        str(python),
        "--baseline-artifact",
        str(args.bundle / "baseline" / bundle["arms"]["baseline"]["wheel"]),
        "--candidate-artifact",
        str(args.bundle / "candidate" / bundle["arms"]["candidate"]["wheel"]),
        "--bundle-directory",
        str(args.bundle),
        "--target",
        args.target,
        "--candidate-sha",
        args.candidate_sha,
        "--run-id",
        str(args.run_id),
        "--run-attempt",
        str(args.run_attempt),
        "--pair-index",
        str(args.pair_index),
        "--runs",
        str(runs),
        "--mode",
        args.mode,
        "--block-timeout-seconds",
        "3600",
        "--output-dir",
        str(args.output),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=("install", "pair", "ollama"), required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--environments", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, default=Path("qualification-evidence"))
    parser.add_argument("--mode", choices=("smoke", "qualification"), default="smoke")
    parser.add_argument("--pair-index", type=int)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--run-attempt", type=int)
    args = parser.parse_args()
    args.bundle, args.output = args.bundle.resolve(), args.output.resolve()
    if args.action == "install":
        install_bundle(args.bundle, args.environments, target=args.target, candidate_sha=args.candidate_sha)
        return 0
    bundle = load_bundle(args.bundle, target=args.target, candidate_sha=args.candidate_sha)
    return subprocess.run(command(args, bundle), cwd=_ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
