"""Build one opt-in experiment wheel; regular release wheel flags stay unchanged."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.native_slo_interpreter import prepare_private_interpreter  # noqa: E402


def _run(argv: list[str], *, environment: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, cwd=_ROOT, env=environment, check=True, text=True, stdout=subprocess.PIPE)
    print(result.stdout, end="", flush=True)
    return result.stdout.strip()


def _prepare_build_interpreter() -> Path:
    prefix = Path(sys.prefix).resolve(strict=True)
    if prefix.is_relative_to(_ROOT) or not (prefix / "pyvenv.cfg").is_file():
        raise ValueError("claude_pilot_build_requires_external_environment")
    python = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    selected = Path(sys.executable).absolute()
    aliases = {
        python.name,
        f"python{sys.version_info.major}",
        f"python{sys.version_info.major}.{sys.version_info.minor}",
    }
    if (
        selected.parent != python.parent
        or selected.name not in aliases
        or selected.resolve(strict=True) != python.resolve(strict=True)
    ):
        raise ValueError("claude_pilot_build_interpreter_mismatch")
    # uv can invoke bin/python3. The helper deliberately owns only bin/python;
    # the selected alias must resolve through that exact private executable.
    prepare_private_interpreter(python, environment_root=prefix)
    if selected.resolve(strict=True) != python.resolve(strict=True):
        raise ValueError("claude_pilot_build_interpreter_alias_detached")
    return python


def build(*, target: str, platform_tag: str, destination: Path) -> Path:
    python = str(_prepare_build_interpreter())
    destination = destination.resolve()
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    version = _run([python, "scripts/sync_repo_version.py", "--check"]).splitlines()[-1]
    build_sha = _run(["git", "rev-parse", "HEAD"]).splitlines()[-1]
    _run([python, "-m", "build", "--wheel", "--outdir", str(destination / "pure")])
    environment = dict(os.environ)
    environment.update(HOL_GUARD_BUILD_SHA=build_sha, HOL_GUARD_PACKAGE_VERSION=version)
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
            "native-claude-launcher-pilot",
        ],
        environment=environment,
    )
    runtime = (
        _ROOT
        / "rust/target"
        / target
        / "release"
        / ("hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime")
    )
    capabilities = json.loads(_run([str(runtime), "capabilities", "--json"]))
    if capabilities.get("build_sha") != build_sha or "claude-launcher-pilot-v1" not in capabilities.get("features", []):
        raise ValueError("claude_pilot_build_capability_mismatch")
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
            build_sha,
            "--rule-digest",
            capabilities["rule_digest"],
        ]
    )
    wheels = tuple((destination / "native").glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("claude_pilot_build_wheel_count")
    _run(["uv", "pip", "uninstall", "--python", python, "hol-guard"])
    _run(["uv", "pip", "install", "--python", python, "--no-deps", "--force-reinstall", str(wheels[0])])
    return wheels[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-dormant-pilot", action="store_true", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform-tag", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    build(target=args.target, platform_tag=args.platform_tag, destination=args.destination)


if __name__ == "__main__":
    main()
