"""Install the exact existing Rust toolchain into private uncached directories."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat

from common import CONFIG, REPORT, SCRATCH, Run, sha256, write_json


def file_record(path: Path) -> dict:
    path = path.resolve(strict=True)
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
    assert 0 < info.st_size <= 256 * 1024 * 1024 and info.st_mode & 0o111
    raw = path.read_bytes()
    assert len(raw) == info.st_size
    return {"path": str(path), "sha256": sha256(raw), "bytes": len(raw),
            "uid": info.st_uid, "mode": oct(stat.S_IMODE(info.st_mode))}


def prepare_rust(run: Run, environment: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    assert os.uname().sysname == "Linux" and os.uname().machine == "x86_64"
    env = dict(environment)
    for name in list(env):
        if name.startswith(("CARGO_", "RUSTUP_", "RUSTC_", "HOL_GUARD_NATIVE")) or name in {
            "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC", "RUSTDOC", "CARGO", "RUSTFMT",
        }:
            env.pop(name, None)
    bootstrap = shutil.which("rustup")
    assert bootstrap is not None, "The pinned runner did not provide the recorded rustup bootstrap"
    provided = Path(bootstrap).resolve(strict=True)
    provided_info = provided.lstat()
    assert stat.S_ISREG(provided_info.st_mode) and provided_info.st_mode & 0o111
    assert 0 < provided_info.st_size <= 256 * 1024 * 1024
    provided_bytes = provided.read_bytes()
    assert len(provided_bytes) == provided_info.st_size
    bootstrap_directory = SCRATCH / "rustup-bootstrap"
    assert not bootstrap_directory.exists()
    bootstrap_directory.mkdir(mode=0o700)
    bootstrap = bootstrap_directory / "rustup"
    with bootstrap.open("xb") as stream:
        stream.write(provided_bytes)
    bootstrap.chmod(0o755)
    bootstrap_before = file_record(bootstrap)
    assert bootstrap_before["sha256"] == sha256(provided_bytes)
    for name in ("cargo-home", "rustup-home"):
        directory = SCRATCH / name
        assert not directory.exists() and not directory.is_symlink()
        directory.mkdir(mode=0o700)
    env.update(
        CARGO_HOME=str(SCRATCH / "cargo-home"), RUSTUP_HOME=str(SCRATCH / "rustup-home"),
        CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", CARGO_TERM_COLOR="never",
        CARGO_NET_RETRY="0", RUSTUP_TOOLCHAIN=CONFIG["rust_toolchain"],
        RUSTUP_NO_UPDATE_CHECK="1", HOL_GUARD_BUILD_SHA=CONFIG["source_sha"],
        HOL_GUARD_PACKAGE_VERSION=CONFIG["project_version"],
    )
    run.require(run.command("rustup-bootstrap-version", [str(bootstrap), "--version"],
                            cwd=SCRATCH, timeout=30, env=env), "Rustup identity failed")
    run.require(run.command("rust-toolchain-install", [
        str(bootstrap), "toolchain", "install", CONFIG["rust_toolchain"],
        "--profile", "minimal", "--component", "rustfmt", "--component", "clippy",
        "--no-self-update",
    ], cwd=SCRATCH, timeout=420, env=env), "Pinned owned Rust installation failed")
    run.require(run.command("rust-toolchain-cargo-path", [
        str(bootstrap), "which", "--toolchain", CONFIG["rust_toolchain"], "cargo",
    ], cwd=SCRATCH, timeout=30, env=env), "Owned Cargo path unavailable")
    cargo = Path((REPORT / "rust-toolchain-cargo-path.log").read_text().strip()).resolve(strict=True)
    root = (SCRATCH / "rustup-home").resolve(strict=True)
    assert cargo.is_relative_to(root) and cargo.name == "cargo"
    programs = {name: cargo.parent / name for name in
                ("cargo", "rustc", "rustdoc", "rustfmt", "cargo-fmt", "clippy-driver", "cargo-clippy")}
    records = {name: file_record(path) for name, path in programs.items()}
    assert all(Path(row["path"]).is_relative_to(root) for row in records.values())
    env.update(
        PATH=str(cargo.parent) + os.pathsep + environment["PATH"],
        RUSTC=str(programs["rustc"]), RUSTDOC=str(programs["rustdoc"]),
        CARGO=str(programs["cargo"]), RUSTFMT=str(programs["rustfmt"]),
    )
    for name, args in {
        "cargo": ["-vV"], "rustc": ["-vV"], "rustfmt": ["--version"],
        "clippy-driver": ["--version"],
    }.items():
        run.require(run.command("owned-" + name + "-version", [str(programs[name]), *args],
                                cwd=SCRATCH, timeout=30, env=env), "Owned Rust component version failed")
    for name in ("cargo", "rustc"):
        version = (REPORT / ("owned-" + name + "-version.log")).read_text()
        assert version.split()[:2] == [name, CONFIG["rust_toolchain"]], version
    components = cargo.parent.parent / "lib/rustlib/components"
    component_raw = components.read_bytes()
    assert all(name in component_raw.decode().splitlines()
               for name in ("cargo", "rustc", "rustfmt-preview", "clippy-preview"))
    assert file_record(bootstrap) == bootstrap_before, "Bootstrap changed despite no-self-update"
    record = {
        "toolchain": CONFIG["rust_toolchain"], "source_sha": CONFIG["source_sha"],
        "bootstrap": bootstrap_before, "bootstrap_version_is_observed_not_a_pinned_runner_binary": True,
        "provided_bootstrap": {"path": str(provided), "sha256": sha256(provided_bytes),
                               "bytes": len(provided_bytes), "uid": provided_info.st_uid},
        "programs": records, "components": component_raw.decode(),
        "component_manifest_sha256": sha256(component_raw),
        "cargo_home": env["CARGO_HOME"], "rustup_home": env["RUSTUP_HOME"],
        "fresh_private_install": True, "shared_cache_used": False,
        "rustup_download_checksums_are_toolchain_installer_verification": True,
        "qualification_complete": False,
    }
    write_json(REPORT / "rust-environment-before.json", record)
    return env, {name: str(path) for name, path in programs.items()}


def finish_rust(programs: dict[str, str]) -> None:
    before = json.loads((REPORT / "rust-environment-before.json").read_bytes())
    after = {name: file_record(Path(path)) for name, path in programs.items()}
    assert after == before["programs"], "Owned Rust compiler component changed"
    write_json(REPORT / "rust-environment-after.json", {
        "source_sha": CONFIG["source_sha"], "programs": after,
        "programs_unchanged": True, "qualification_complete": False,
    })
