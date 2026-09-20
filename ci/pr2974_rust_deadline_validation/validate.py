"""Validate the original managed Rust deadline in two immutable feature builds."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, sha256, source_witness, write_json

CARGO = ["cargo", "+1.88.0"]
MANIFEST = SOURCE / "rust" / "Cargo.toml"
EXPECTED = json.loads((HERE / "expected-tests.json").read_text(encoding="utf-8"))


def environment() -> dict[str, str]:
    env = dict(os.environ)
    for name in list(env):
        if (
            name.startswith(("CARGO_", "RUST_", "RUSTC_", "RUSTDOC_", "HOL_GUARD_", "GUARD_"))
            or name in {"RUSTC", "RUSTDOC", "RUSTFLAGS", "RUSTDOCFLAGS", "LD_PRELOAD", "LD_LIBRARY_PATH"}
        ):
            env.pop(name, None)
    env.update(CONFIG["fixed_rust_environment"])
    env["CARGO_HOME"] = str(SCRATCH / "cargo-home")
    env["CARGO_TARGET_DIR"] = str(SCRATCH / "target")
    env["TMPDIR"] = str(SCRATCH / "tmp")
    env["HOL_GUARD_BUILD_SHA"] = CONFIG["source_sha"]
    for key in ("CARGO_HOME", "CARGO_TARGET_DIR", "TMPDIR"):
        Path(env[key]).mkdir(mode=0o700, parents=True, exist_ok=False)
    return env


def host_receipt(env: dict[str, str]) -> None:
    assert sys.platform == "linux" and platform.machine() == "x86_64"
    assert platform.python_version() == "3.12.13" and __debug__ and sys.dont_write_bytecode
    files = {}
    for path in ("/proc/meminfo", "/proc/self/limits", "/etc/os-release",
                 "/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.swap.max"):
        candidate = Path(path)
        if candidate.is_file():
            raw = candidate.read_bytes()
            assert len(raw) <= 1024 * 1024
            files[path] = {"bytes": len(raw), "sha256": sha256(raw),
                           "content": raw.decode("utf-8")}
    executables = {}
    for name in ("rustup", "cargo", "rustc"):
        path = Path(shutil.which(name) or "").resolve(strict=True)
        raw = path.read_bytes()
        executables[name] = {"path": str(path), "bytes": len(raw), "sha256": sha256(raw)}
    write_json(REPORT / "host-and-build-environment.json", {
        "python": sys.version, "python_executable": sys.executable,
        "platform": platform.platform(), "machine": platform.machine(),
        "retained_host_files": files, "launcher_executables": executables,
        "fixed_rust_environment": {key: env[key] for key in CONFIG["fixed_rust_environment"]},
        "fresh_cargo_home": env["CARGO_HOME"], "fresh_target": env["CARGO_TARGET_DIR"],
        "temporary_directory": env["TMPDIR"], "build_source_sha": env["HOL_GUARD_BUILD_SHA"],
        "old_sigkill_cause_resolved": False, "qualification_complete": False,
    })


def binary_identity(path: Path) -> dict[str, object]:
    assert path.is_absolute() and path.is_relative_to(SCRATCH / "target" / "debug" / "deps")
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
    assert info.st_mode & 0o111 and not path.is_symlink()
    raw = path.read_bytes()
    assert len(raw) == info.st_size
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw),
            "mode": stat.S_IMODE(info.st_mode), "device": info.st_dev, "inode": info.st_ino}


def compiled_binary(name: str, features: list[str]) -> tuple[Path, dict[str, object]]:
    raw = (REPORT / (name + "-build.log")).read_bytes()
    messages = []
    for line in raw.decode("utf-8").splitlines():
        if line.startswith("{"):
            messages.append(json.loads(line))
    finished = [row for row in messages if row.get("reason") == "build-finished"]
    assert len(finished) == 1 and finished[0]["success"] is True
    selected = [row for row in messages
                if row.get("reason") == "compiler-artifact"
                and row.get("target", {}).get("name") == "hol-guard-runtime"
                and row.get("target", {}).get("kind") == ["bin"]
                and row.get("profile", {}).get("test") is True]
    assert len(selected) == 1, selected
    artifact = selected[0]
    assert sorted(artifact["features"]) == sorted(["default", *features]), artifact
    assert Path(artifact["target"]["src_path"]).resolve(strict=True) == MANIFEST.parent / "crates/guard-runtime/src/main.rs"
    path = Path(artifact["executable"])
    identity = binary_identity(path)
    report = {"compiler_artifact": artifact, "binary": identity, "features": features,
              "build_log_bytes": len(raw), "build_log_sha256": sha256(raw),
              "binary_bytes_are_retained_in_separate_artifact": False,
              "qualification_complete": False}
    write_json(REPORT / (name + "-binary.json"), report)
    return path, identity


def collection(name: str, expected: dict[str, object]) -> dict[str, object]:
    raw = (REPORT / (name + "-list.log")).read_bytes()
    lines = raw.decode("utf-8").splitlines()
    nodes = [line.removesuffix(": test") for line in lines if line.endswith(": test")]
    summaries = [line for line in lines if re.fullmatch(r"\d+ tests?, \d+ benchmarks?", line)]
    extras = [line for line in lines if line and not line.endswith(": test") and line not in summaries]
    report = {"nodes": nodes, "summaries": summaries, "unexpected_lines": extras,
              "raw_bytes": len(raw), "raw_sha256": sha256(raw), "passed": False,
              "source_expected_nodes": expected["nodes"],
              "source_ignored_nodes": expected["ignored_nodes"],
              "qualification_complete": False}
    try:
        assert len(nodes) == len(set(nodes)) == len(expected["nodes"])
        assert sorted(nodes) == expected["nodes"]
        assert summaries == [f"{len(nodes)} tests, 0 benchmarks"] and not extras
        report["passed"] = True
        return report
    finally:
        write_json(REPORT / (name + "-collection.json"), report)


def body_results(name: str, expected: dict[str, object], command_passed: bool) -> dict[str, object]:
    raw = (REPORT / (name + "-body.log")).read_bytes()
    lines = raw.decode("utf-8").splitlines()
    rows = []
    for line in lines:
        matched = re.fullmatch(r"test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED|ignored(?:, .*)?)", line)
        if matched:
            status = matched[2]
            rows.append({"node": matched[1], "status": "ignored" if status.startswith("ignored") else status,
                         "original_result_text": status})
    starts = [int(match[1]) for line in lines
              if (match := re.fullmatch(r"running (\d+) tests", line))]
    terminals = [match.groups() for line in lines if (match := re.fullmatch(
        r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s", line))]
    report = {"command_passed": command_passed, "rows": rows, "run_start_counts": starts,
              "terminal_summaries": terminals, "raw_bytes": len(raw), "raw_sha256": sha256(raw),
              "passed": False, "ignored_rows_are_body_unrun": True,
              "qualification_complete": False}
    try:
        nodes = [row["node"] for row in rows]
        assert len(nodes) == len(set(nodes)) == len(expected["nodes"])
        assert sorted(nodes) == expected["nodes"] and starts == [len(nodes)]
        assert sorted(row["node"] for row in rows if row["status"] == "ignored") == expected["ignored_nodes"]
        assert all(row["status"] == "ok" for row in rows if row["node"] not in expected["ignored_nodes"])
        assert len(terminals) == 1
        status, passed, failed, ignored, measured, filtered, elapsed = terminals[0]
        assert (status, int(passed), int(failed), int(ignored), int(measured), int(filtered)) == (
            "ok", len(nodes) - len(expected["ignored_nodes"]), 0, len(expected["ignored_nodes"]), 0, 0)
        assert command_passed
        report["passed"] = True
        report["actual_passed_bodies"] = int(passed)
        report["actual_ignored_bodies"] = int(ignored)
        return report
    finally:
        write_json(REPORT / (name + "-body-results.json"), report)


def main() -> int:
    run = Run("original-managed-rust-deadline")
    errors = []
    cohorts = {}
    controls = {"ordinary_child_reap": False}
    try:
        run.before = source_witness("before")
        env = environment()
        host_receipt(env)
        for source in CONFIG["control_source_paths"]:
            destination = REPORT / "control-source" / source
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((SOURCE / source).read_bytes())
        controls["ordinary_child_reap"] = run.command(
            "ordinary-child-reap-control", [sys.executable, "-I", "-B", str(HERE / "ordinary_child_reap_control.py")],
            timeout=30, env=env)
        run.require(controls["ordinary_child_reap"], "Real original-group retirement control failed")
        installed = run.command("rust-toolchain-install",
            ["rustup", "toolchain", "install", "1.88.0", "--profile", "minimal",
             "--component", "rustfmt", "--component", "clippy"], timeout=600, env=env)
        run.require(installed, "Pinned Rust toolchain installation failed")
        for name, args in (
            ("rustc-version", ["rustc", "+1.88.0", "--version", "--verbose"]),
            ("cargo-version", CARGO + ["--version", "--verbose"]),
            ("rustfmt-version", ["rustfmt", "+1.88.0", "--version"]),
            ("clippy-version", CARGO + ["clippy", "--version"]),
        ):
            run.require(run.command(name, args, timeout=30, env=env), name + " failed")
        run.require("rustc 1.88.0 " in (REPORT / "rustc-version.log").read_text(),
                    "Unexpected compiler version")
        run.require(run.command("locked-workspace-metadata",
            CARGO + ["metadata", "--manifest-path", str(MANIFEST), "--locked",
                     "--format-version", "1", "--no-deps"], timeout=60, env=env),
                    "Locked Cargo metadata failed")
        run.command("rustfmt-check",
            CARGO + ["fmt", "--manifest-path", str(MANIFEST), "--all", "--", "--check"],
            timeout=120, env=env)
        run.command("workspace-clippy",
            CARGO + ["clippy", "--manifest-path", str(MANIFEST), "--locked", "--workspace",
                     "--all-targets", "--", "-D", "warnings"], timeout=900, env=env)
        run.command("diagnostic-phases-clippy",
            CARGO + ["clippy", "--manifest-path", str(MANIFEST), "--locked", "-p",
                     "hol-guard-runtime", "--all-targets", "--features", "diagnostic-phases",
                     "--", "-D", "warnings"], timeout=600, env=env)
        for item in CONFIG["cohorts"]:
            name, features = item["name"], item["features"]
            cohorts[name] = {"passed": False, "status": "started", "features": features,
                             "expected": EXPECTED[name], "qualification_complete": False}
            try:
                args = CARGO + ["test", "--manifest-path", str(MANIFEST), "--locked", "-p",
                                "hol-guard-runtime", "--bin", "hol-guard-runtime", "--no-run",
                                "--message-format=json-render-diagnostics"]
                if features:
                    args += ["--features", ",".join(features)]
                run.require(run.command(name + "-build", args, timeout=item["build_seconds"], env=env),
                            name + " compilation failed")
                binary, identity = compiled_binary(name, features)
                run.require(run.command(name + "-list",
                    [str(binary), "--list", "--format=pretty", "--color=never"], timeout=30, env=env),
                            name + " collection failed")
                cohorts[name]["collection"] = collection(name, EXPECTED[name])
                run.require(binary_identity(binary) == identity, "Test binary changed during collection")
                passed = run.command(name + "-body",
                    [str(binary), "--test-threads=1", "--format=pretty", "--color=never", "--show-output"],
                    timeout=600, env=env)
                cohorts[name]["body"] = body_results(name, EXPECTED[name], passed)
                run.require(binary_identity(binary) == identity, "Test binary changed during bodies")
                cohorts[name]["passed"] = True
                cohorts[name]["status"] = "finished"
            except BaseException:
                cohorts[name]["error"] = traceback.format_exc()
                errors.append(cohorts[name]["error"])
            finally:
                write_json(REPORT / (name + "-cohort.json"), cohorts[name])
    except BaseException:
        errors.append(traceback.format_exc())
    finally:
        complete = len(cohorts) == len(CONFIG["cohorts"]) and all(row["passed"] for row in cohorts.values())
        if errors or not complete:
            run.error = "\n".join(errors) or "Required Rust populations did not complete"
        write_json(REPORT / "rust-validation-summary.json", {
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "cohorts": cohorts, "observer_controls": controls, "errors": errors,
            "required_cohorts_complete": complete, "original_preparation": CONFIG["original_preparation"],
            "default_and_diagnostic_feature_results_are_separate": True,
            "allocation_diagnostics_executed": False, "ignored_diagnostic_bodies_executed": False,
            "production_deadlines_changed": False, "source_normalized_or_modified": False,
            "linux_native_default_startup_cause_established": False,
            "qualification_complete": False,
        })
        passed = run.finish()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
