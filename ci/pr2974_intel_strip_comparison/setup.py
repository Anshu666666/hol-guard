"""Resolve one backend closure and one Rust dependency snapshot before both builds."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import time
import tomllib

from admission import capture_text, host_witness, reachable_cargo_configs
from common import (
    ARTIFACTS, CONFIG, REPORT, ROOT, SOURCE, command, deadline, file_identity,
    helper_argv, helper_environment, require, sha256, successful, write_json,
)


def secure_launchers(prefix: Path, base: Path) -> None:
    expected = file_identity(base)
    for name in ("python", "python3", "python3.12"):
        target = prefix / "bin" / name
        require(target.resolve(strict=True).read_bytes() == base.read_bytes(), "Unexpected venv interpreter")
        temporary = target.with_name(name + ".owned-copy")
        with base.open("rb") as source, temporary.open("xb") as output:
            shutil.copyfileobj(source, output)
        temporary.chmod(0o755)
        temporary.replace(target)
        actual = file_identity(target)
        require(actual["sha256"] == expected["sha256"], "Copied launcher differs")


def create_venv(context: dict, name: str) -> Path:
    prefix = ROOT / "venvs" / name
    require(not prefix.exists(), "Runtime/backend environment must start absent")
    row = command("create-venv-" + name, [context["tools"]["python"]["path"], "-I", "-B",
                  "-m", "venv", "--without-pip", "--copies", str(prefix)],
                  environment=context["environment"], timeout=90)
    require(successful(row), "Environment creation failed")
    secure_launchers(prefix, Path(context["tools"]["python"]["path"]))
    return prefix


def require_command(name: str, argv: list[str], context: dict, *, environment=None,
                    timeout: int = 120, cwd: Path = ROOT) -> dict:
    row = command(name, argv, environment=environment or context["environment"], timeout=timeout, cwd=cwd)
    require(successful(row), "Required setup command failed: " + name)
    return row


def lock_versions(raw: str) -> dict[str, str]:
    logical = raw.replace("\\\n", " ").splitlines()
    versions = {}
    for line in logical:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)((?:\s+--hash=sha256:[0-9a-f]{64})+)", line)
        require(match is not None, "Unaccounted backend lock syntax")
        name = re.sub(r"[-_.]+", "-", match[1]).lower()
        require(name not in versions, "Duplicate backend pin")
        versions[name] = match[2]
    require(versions.get("build") == "1.5.0" and "hatchling" in versions, "Missing required backend")
    require(len(versions) <= 64, "Backend closure exceeds bound")
    return versions


def prepare_backend(context: dict) -> None:
    build_system = tomllib.loads((SOURCE / "pyproject.toml").read_text())["build-system"]
    require(build_system == {"requires": ["hatchling<1.31"], "build-backend": "hatchling.build"},
            "Frozen backend declaration differs")
    required = REPORT / "backend.in"
    required.write_text("build==1.5.0\nhatchling<1.31\n", encoding="ascii")
    locked = REPORT / "backend.lock"
    uv = context["tools"]["uv"]["path"]
    python = context["tools"]["python"]["path"]
    require_command("backend-resolve", [
        uv, "--no-config", "pip", "compile", "--generate-hashes", "--no-build",
        "--python", python, "--output-file", str(locked), str(required),
    ], context, timeout=180)
    versions = lock_versions(locked.read_text())
    # Inventory every original pip tool RECORD member before this one download.
    require_command("pip-download-tool-bytes", helper_argv("tool_environment"),
                    context, environment=helper_environment(context["environment"]), timeout=60)
    # The base interpreter's pip is not installed into either runtime.
    require_command("pip-download-tool-version", [python, "-I", "-B", "-m", "pip", "--version"], context)
    require_command("backend-download", [
        python, "-I", "-B", "-m", "pip", "--isolated", "--disable-pip-version-check",
        "--no-cache-dir", "download", "--only-binary=:all:", "--require-hashes",
        "--dest", str(ROOT / "backend-wheels"), "-r", str(locked),
    ], context, timeout=180)
    archives = sorted((ROOT / "backend-wheels").glob("*"))
    require(archives and all(path.suffix == ".whl" for path in archives), "Backend wheels incomplete")
    wheel_pins = {path.name: file_identity(path, maximum=64 * 1024 * 1024) for path in archives}
    write_json(REPORT / "backend-lock-admission.json",
               {"passed": True, "versions": versions, "lock_sha256": sha256(locked.read_bytes()),
                "require_hashes": True, "original_wheels": wheel_pins})
    prefix = create_venv(context, "backend")
    primary = prefix / "bin/python"
    require_command("backend-install", [
        uv, "--no-config", "pip", "install", "--python", str(primary), "--no-index",
        "--find-links", str(ROOT / "backend-wheels"), "--require-hashes", "--no-build",
        "-r", str(locked),
    ], context, timeout=120)
    context.update(backend=prefix, backend_python=primary)
    require_command("version-sync", [str(primary), "-I", "-B",
                    str(SOURCE / "scripts/sync_repo_version.py"), "--check"], context, timeout=60)
    require_command("backend-environment-before",
                    helper_argv("environment", "--prefix", prefix, "--kind", "backend",
                                "--output", REPORT / "backend-environment-before.json",
                                "--archive", ARTIFACTS / "backend-environment.tar.gz", python=primary),
                    context, environment=helper_environment(context["environment"]), timeout=120)


def prepare_rust(context: dict) -> None:
    env, tools = context["environment"], context["tools"]
    require_command("rustup-version", [tools["rustup"]["path"], "--version"], context)
    require_command("rust-toolchain-install", [
        tools["rustup"]["path"], "toolchain", "install", "1.88.0", "--profile", "minimal",
        "--target", CONFIG["target"], "--no-self-update",
    ], context, timeout=360)
    for name in ("cargo", "rustc"):
        path = capture_text("resolve-" + name,
                            [tools["rustup"]["path"], "which", "--toolchain", "1.88.0", name], env)
        actual = Path(path).resolve(strict=True)
        require(actual.is_relative_to(ROOT / "rustup-home"), "Toolchain escaped its private root")
        tools[name] = file_identity(actual)
        version = capture_text(name + "-version", [str(actual), "--version", "--verbose"], env)
        require(version.split()[1] == "1.88.0", "Wrong admitted toolchain version")
    sysroot = Path(capture_text("rust-sysroot", [tools["rustc"]["path"], "--print", "sysroot"], env))
    objcopy = sysroot / "lib" / "rustlib" / CONFIG["target"] / "bin" / "rust-objcopy"
    tools["rust-objcopy"] = file_identity(objcopy)
    require_command("rust-objcopy-version", [str(objcopy), "--version"], context)
    developer = capture_text("developer-directory", ["/usr/bin/xcode-select", "-p"], env)
    sdk_path = capture_text("sdk-path", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], env)
    sdk_version = capture_text("sdk-version", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"], env)
    sdk_build = capture_text("sdk-build", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-build-version"], env)
    context["sdk"] = {"path": str(Path(sdk_path).resolve(strict=True)),
                      "version": sdk_version, "build": sdk_build, "developer_directory": developer}
    for name in ("clang", "ld", "otool"):
        path = capture_text("resolve-" + name, ["/usr/bin/xcrun", "--sdk", "macosx", "--find", name], env)
        tools[name] = file_identity(Path(path).resolve(strict=True))
    tools["codesign"] = file_identity(Path("/usr/bin/codesign"))
    require_command("clang-version", [tools["clang"]["path"], "--version"], context)
    require_command("ld-version", [tools["ld"]["path"], "-v"], context)
    # otool and codesign have different version/help exit conventions: preserve their actual results.
    command("otool-version", [tools["otool"]["path"], "-version"], environment=env, timeout=30)
    command("codesign-help", [tools["codesign"]["path"], "-h"], environment=env, timeout=30)
    env.update(
        RUSTC=tools["rustc"]["path"], PATH=str(Path(tools["cargo"]["path"]).parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        SDKROOT=context["sdk"]["path"], DEVELOPER_DIR=developer,
        CC=tools["clang"]["path"], MACOSX_DEPLOYMENT_TARGET="13.0",
    )
    reachable_cargo_configs(context)
    require_command("cargo-fetch-once", [
        tools["cargo"]["path"], "fetch", "--manifest-path", str(SOURCE / "rust/Cargo.toml"),
        "--locked", "--target", CONFIG["target"],
    ], context, timeout=180)
    context["registry_before"] = registry_witness("before")
    context["host_before_variants"] = host_witness("before-variants", context)


def registry_witness(label: str) -> dict:
    rows = {}
    roots = [ROOT / "cargo-home" / part for part in ("registry", "git")]
    total = 0
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_dir():
                continue
            require(not path.is_symlink(), "Unadmitted Rust dependency symlink")
            pin = file_identity(path)
            total += pin["bytes"]
            require(len(rows) < 100000 and total <= 2 * 1024**3, "Rust dependency census bound")
            rows[str(path.relative_to(ROOT / "cargo-home"))] = {
                key: pin[key] for key in ("sha256", "bytes", "mode")}
    require(rows, "Empty Rust dependency snapshot")
    write_json(REPORT / ("rust-dependencies-" + label + ".json"),
               {"files": rows, "bytes": total, "locked_offline_build_required": True})
    return rows


def prepare(context: dict) -> None:
    with deadline(CONFIG["bounds"]["environment_setup_seconds"]):
        started = time.monotonic()
        prepare_backend(context)
        prepare_rust(context)
        prepare_runtime_lock(context)
        prepare_runtime_pair(context)
        require(time.monotonic() - started <= CONFIG["bounds"]["environment_setup_seconds"],
                "Complete environment setup exceeded its frozen bound")
        write_json(REPORT / "preflight-admission.json",
                   {"tools": context["tools"], "sdk": context["sdk"], "environment": context["environment"],
                    "backend": str(context["backend"]), "passed": True, "qualification_complete": False})


def prepare_runtime_lock(context: dict) -> None:
    require_command("frozen-runtime-export", [
        context["tools"]["uv"]["path"], "--no-config", "export", "--project", str(SOURCE),
        "--frozen", "--extra", "dev", "--no-emit-project", "--no-hashes",
        "--format", "requirements-txt", "--output-file", str(REPORT / "runtime-export.txt"),
    ], context, timeout=120)
    require_command("runtime-lock-evaluation", helper_argv("lock_environment", python=context["backend_python"]),
                    context, environment=helper_environment(context["environment"]), timeout=30)


def runtime_environment(context: dict, variant: str) -> tuple[Path, dict[str, str]]:
    prefix = create_venv(context, variant)
    python = prefix / "bin/python"
    env = context["environment"] | {"UV_PROJECT_ENVIRONMENT": str(prefix), "UV_LINK_MODE": "copy"}
    require_command("runtime-sync-" + variant, [
        context["tools"]["uv"]["path"], "--no-config", "sync", "--project", str(SOURCE),
        "--frozen", "--extra", "dev", "--no-install-project", "--python", str(python),
    ], context, environment=env, timeout=180)
    secure_launchers(prefix, Path(context["tools"]["python"]["path"]))
    env = context["environment"] | {"PATH": str(prefix / "bin") + ":" + context["environment"]["PATH"]}
    return prefix, env


def prepare_runtime_pair(context: dict) -> None:
    from dependency_pair import compare_dependencies
    context["runtime_environments"] = {}
    for variant in ("baseline", "candidate"):
        prefix, environment = runtime_environment(context, variant)
        report = REPORT / variant / "dependencies-before.json"
        require_command("dependencies-before-" + variant,
                        helper_argv("environment", "--prefix", prefix, "--kind", "dependencies",
                                    "--output", report,
                                    "--archive", ARTIFACTS / (variant + "-dependencies.tar.gz"),
                                    python=prefix / "bin/python"),
                        context, environment=helper_environment(environment), timeout=120)
        context["runtime_environments"][variant] = {
            "prefix": prefix, "environment": environment, "dependency_inventory": report}
    compare_dependencies(REPORT / "baseline/dependencies-before.json",
                         REPORT / "candidate/dependencies-before.json")
