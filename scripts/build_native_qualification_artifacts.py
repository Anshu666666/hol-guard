#!/usr/bin/env python3
"""Build and install pinned baseline/candidate wheels into separate environments."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.native_slo_interpreter import prepare_private_interpreter  # noqa: E402


def _run(argv: list[str], *, cwd: Path, environment: dict[str, str] | None = None) -> str:
    completed = subprocess.run(argv, cwd=cwd, env=environment, check=True, text=True, stdout=subprocess.PIPE)
    print(completed.stdout, end="", flush=True)
    return completed.stdout.strip()


def _run_required_checks(checks: tuple[tuple[str, list[str]], ...], *, cwd: Path) -> None:
    """Retain independent installed evidence even when another check fails."""
    failed: list[str] = []
    for name, argv in checks:
        try:
            _run(argv, cwd=cwd)
        except subprocess.CalledProcessError:
            failed.append(name)
    if failed:
        raise RuntimeError("installed qualification failed: " + ",".join(failed))


def _build(
    source: Path, *, environment_root: Path, target: str, platform_tag: str, deployment_target: str
) -> tuple[Path, Path, dict[str, object]]:
    source = source.resolve(strict=True)
    environment_root = environment_root.resolve()
    if environment_root.is_relative_to(source):
        raise ValueError("qualification installed environment must be outside the source checkout")
    python = environment_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    environment = dict(os.environ)
    environment["UV_PROJECT_ENVIRONMENT"] = str(environment_root)
    _run(["uv", "sync", "--frozen", "--extra", "dev", "--python", "3.12"], cwd=source, environment=environment)
    interpreter_proof = prepare_private_interpreter(python, environment_root=environment_root)
    print(json.dumps({"qualification_interpreter": interpreter_proof}, sort_keys=True), flush=True)
    version = _run([str(python), "scripts/sync_repo_version.py", "--check"], cwd=source).splitlines()[-1]
    sha = _run(["git", "rev-parse", "HEAD"], cwd=source).splitlines()[-1]
    _run([str(python), "-m", "build", "--wheel", "--outdir", "qualification-pure"], cwd=source)
    environment["HOL_GUARD_BUILD_SHA"] = sha
    environment["HOL_GUARD_PACKAGE_VERSION"] = version
    if deployment_target:
        environment["MACOSX_DEPLOYMENT_TARGET"] = deployment_target
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
        ],
        cwd=source,
        environment=environment,
    )
    runtime = (
        source
        / "rust"
        / "target"
        / target
        / "release"
        / ("hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime")
    )
    capabilities = json.loads(_run([str(runtime), "capabilities", "--json"], cwd=source))
    _run([str(runtime), "self-test", "--json"], cwd=source)
    pure = source / "qualification-pure" / f"hol_guard-{version}-py3-none-any.whl"
    _run(
        [
            str(python),
            "scripts/build_native_hol_guard_wheel.py",
            "--wheel",
            str(pure),
            "--runtime",
            str(runtime),
            "--output-dir",
            "qualification-native",
            "--version",
            version,
            "--platform-tag",
            platform_tag,
            "--target",
            target,
            "--source-sha",
            sha,
            "--rule-digest",
            capabilities["rule_digest"],
        ],
        cwd=source,
    )
    wheels = tuple((source / "qualification-native").glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("qualification build did not produce exactly one native wheel")
    _run(["uv", "pip", "uninstall", "--python", str(python), "hol-guard"], cwd=source)
    _run(
        ["uv", "pip", "install", "--python", str(python), "--no-deps", "--force-reinstall", str(wheels[0])], cwd=source
    )
    metadata: dict[str, object] = {
        "interpreter": interpreter_proof,
        "source_sha": sha,
        "package_version": version,
        "target": target,
        "platform_tag": platform_tag,
        "rustc": _run(["rustc", "+1.88.0", "--version"], cwd=source),
        "cargo": _run(["cargo", "+1.88.0", "--version"], cwd=source),
        "python": _run([str(python), "-c", "import platform; print(platform.python_version())"], cwd=source),
        "build_flags": ["--locked", "--release", "--target", target],
        "runtime_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
    }
    return python, wheels[0], metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform-tag", required=True)
    parser.add_argument("--deployment-target", default="")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("smoke", "qualification"), default="smoke")
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    destination = args.output_dir.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    baseline_python, baseline_wheel, baseline = _build(
        args.baseline,
        environment_root=destination / "environments" / "baseline",
        target=args.target,
        platform_tag=args.platform_tag,
        deployment_target=args.deployment_target,
    )
    candidate_python, candidate_wheel, candidate = _build(
        args.candidate,
        environment_root=destination / "environments" / "candidate",
        target=args.target,
        platform_tag=args.platform_tag,
        deployment_target=args.deployment_target,
    )
    # The benchmark collector is a development-only dependency. Baseline's old
    # lock does not contain it; install precisely the candidate lock's version
    # into both environments without changing the runtime wheel dependencies.
    import tomllib

    lock = tomllib.loads((args.candidate / "uv.lock").read_text(encoding="utf-8"))
    versions = {package["version"] for package in lock["package"] if package["name"] == "psutil"}
    if len(versions) != 1:
        raise RuntimeError("candidate lock must pin exactly one psutil version")
    dependency = "psutil==" + versions.pop()
    for python in (baseline_python, candidate_python):
        _run(["uv", "pip", "install", "--python", str(python), "--no-deps", dependency], cwd=args.candidate.resolve())
    for python, metadata in ((baseline_python, baseline), (candidate_python, candidate)):
        metadata["dependency_versions_sha256"] = _run(
            [str(python), str(args.candidate.resolve() / "scripts/native_slo_dependency_identity.py")],
            cwd=destination,
        ).splitlines()[-1]
    (destination / "build-metadata.json").write_text(
        json.dumps({"baseline": baseline, "candidate": candidate}, indent=2) + "\n"
    )
    if args.build_only:
        from scripts.native_slo_qualification_bundle import export_bundle

        export_bundle(
            destination=destination / "bundle",
            sources={"baseline": args.baseline, "candidate": args.candidate},
            wheels={"baseline": baseline_wheel, "candidate": candidate_wheel},
            metadata={"baseline": baseline, "candidate": candidate},
            run=_run,
        )
        return 0
    paired = [
        str(candidate_python),
        str(args.candidate.resolve() / "scripts/qualify_guard_native.py"),
        "--baseline-python",
        str(baseline_python),
        "--candidate-python",
        str(candidate_python),
        "--baseline-artifact",
        str(baseline_wheel),
        "--candidate-artifact",
        str(candidate_wheel),
        "--mode",
        args.mode,
        "--runs",
        "5" if args.mode == "qualification" else "1",
        "--output-dir",
        str(destination),
    ]
    ollama = [
        str(candidate_python),
        str(args.candidate.resolve() / "scripts/ci/verify_native_ollama_install.py"),
        "--python",
        str(candidate_python),
        "--wheel",
        str(candidate_wheel),
        "--source-root",
        str(args.candidate.resolve()),
        "--source-sha",
        str(candidate["source_sha"]),
        "--output",
        str(destination / "aggregate/installed-ollama.json"),
    ]
    _run_required_checks((("paired_sampling", paired), ("installed_ollama", ollama)), cwd=args.candidate.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
