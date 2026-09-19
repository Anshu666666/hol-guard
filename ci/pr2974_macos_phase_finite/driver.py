"""Validate the exact corrected Mac source once; retain original finite failures."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, admit, digest, emit_file, git, source_map, write_json
from finite_summary import summarize

def secure_launchers(venv: Path) -> None:
    base = Path(sys.executable).resolve()
    data = base.read_bytes()
    assert venv.is_dir() and not venv.is_symlink() and venv.stat().st_uid == os.getuid()
    for name in ("python", "python3", "python3.12"):
        path = venv / "bin" / name
        assert path.resolve().read_bytes() == data
        temporary = path.with_name(name + ".owned-copy")
        assert not temporary.exists()
        shutil.copyfile(base, temporary)
        temporary.chmod(0o755)
        temporary.replace(path)
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        assert path.read_bytes() == data


def requirements() -> Path:
    data = (SOURCE / "uv.lock").read_bytes()
    assert digest(data) == CONFIG["source_inputs"]["uv.lock"]
    lock = tomllib.loads(data.decode())
    lines, selected = [], {}
    for name, version in sorted(CONFIG["installed_versions"].items()):
        matches = [package for package in lock["package"] if package["name"] == name
                   and package["version"] == version]
        assert len(matches) == 1, (name, version)
        hashes = sorted({wheel["hash"] for wheel in matches[0].get("wheels", [])})
        assert hashes and all(value.startswith("sha256:") and len(value) == 71 for value in hashes)
        lines.append(name + "==" + version + "".join(" --hash=" + value for value in hashes))
        selected[name] = {"version": version, "wheel_hashes": hashes}
    path = REPORT / "requirements.txt"
    path.write_text("\n".join(lines) + "\n")
    write_json(REPORT / "dependency-inputs.json", {
        "source_lock_sha256": digest(data), "selected_packages": selected,
        "requirements_sha256": digest(path.read_bytes()), "project_install_requested": False,
    })
    return path


def main() -> int:
    run = Run()
    before = None
    primary = None
    env_before = False
    source_unchanged = False
    environment_unchanged = False
    finite = None
    env = dict(os.environ)
    for name in ("PYTHONPATH", "PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
        env.pop(name, None)
    env.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
               UV_CACHE_DIR=str(SCRATCH / "uv-cache"), UV_LINK_MODE="copy", UV_NO_PROGRESS="1",
               UV_CONCURRENT_DOWNLOADS="1", UV_CONCURRENT_BUILDS="1", UV_CONCURRENT_INSTALLS="1",
               UV_PYTHON_DOWNLOADS="never", TMPDIR=str(SCRATCH / "tmp"), RAYON_NUM_THREADS="1",
               XDG_CACHE_HOME=str(SCRATCH / "cache"))
    (SCRATCH / "tmp").mkdir(exist_ok=False)
    try:
        admit()
        before = source_map("before", original=True)
        run.require(".".join(map(str, sys.version_info[:3])) == CONFIG["python_version"], "Wrong host Python")
        write_json(REPORT / "host.json", {
            "python_version": sys.version, "python_executable": sys.executable,
            "python_sha256": digest(Path(sys.executable).resolve().read_bytes()),
            "uid": os.getuid(), "gid": os.getgid(), "uname": list(os.uname()),
            "image": {name: os.environ.get(name) for name in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")},
        })
        uv = os.environ["VALIDATION_UV"]
        run.require(run.command("uv-version", [uv, "--version"], env), "uv query failed")
        version = (REPORT / "uv-version.log").read_text().strip()
        run.require(version == "uv " + CONFIG["uv_version"] or
                    version.startswith("uv " + CONFIG["uv_version"] + " "), "Wrong uv version")
        write_json(REPORT / "uv-binary.json", {
            "path": str(Path(uv).resolve()), "sha256": digest(Path(uv).resolve().read_bytes()), "version": version,
        })
        venv = SCRATCH / "validation-environment"
        run.require(not venv.exists(), "Refuse existing virtual environment")
        run.require(run.command("create-environment", [
            sys.executable, "-B", "-I", "-m", "venv", "--copies", "--without-pip", str(venv),
        ], env), "Virtual environment creation failed")
        secure_launchers(venv)
        primary = venv / "bin/python"
        env["VALIDATION_VENV"] = str(venv)
        pins = requirements()
        run.require(run.command("install-nine-locked-tools", [
            uv, "--no-config", "pip", "install", "--python", str(primary), "--no-deps", "--require-hashes",
            "--only-binary", ":all:", "--index-url", "https://pypi.org/simple", "-r", str(pins),
        ], env, 300), "Locked tool installation failed")
        secure_launchers(venv)
        run.require(run.command("dependency-compatibility", [
            uv, "--no-config", "pip", "check", "--python", str(primary),
        ], env), "Dependency compatibility failed")
        env_before = run.command("environment-before", [
            str(primary), "-B", "-I", str(HERE / "environment.py"), str(REPORT / "environment-before.json"),
        ], env, 120)
        run.require(env_before, "Environment identity failed")
        commands = [
            ("syntax-before", [str(primary), "-B", "-I", str(HERE / "source.py"), "before"]),
            ("original-admission-preservation", [str(primary), "-B", "-I", str(HERE / "source.py"), "preservation"]),
            ("git-diff-check", ["git", "diff", "--check", CONFIG["source_parent"]]),
            ("ruff-nine-files", [str(venv / "bin/ruff"), "check", "--no-cache", *CONFIG["python_files"]]),
            ("ruff-format-nine-files", [str(venv / "bin/ruff"), "format", "--no-cache", "--check",
                                       *CONFIG["python_files"]]),
            ("basedpyright-four-implementations", [str(venv / "bin/basedpyright"), "--level", "error",
                                                  "--pythonpath", str(primary), *CONFIG["type_files"]]),
        ]
        for name, args in commands:
            run.command(name, args, env, 120)
        compiler = shutil.which("cc")
        run.require(compiler is not None, "Portable C fixture compiler is unavailable")
        run.require(run.command("portable-c-compiler", [compiler, "--version"], env), "Compiler version query failed")
        compiler_path = Path(compiler).resolve(strict=True)
        write_json(REPORT / "portable-c-compiler.json", {
            "path": str(compiler_path), "sha256": digest(compiler_path.read_bytes()),
            "version_output": (REPORT / "portable-c-compiler.log").read_text(),
            "sdk": "deterministic dns_sd.h and C shim in the selected finite test",
            "native_qualification_credit": False,
        })
        basetemp = SCRATCH / "pytest-basetemp"
        run.require(not basetemp.exists(), "Refuse existing pytest temporary directory")
        pytest_env = dict(env, VALIDATION_PYTEST_BASETEMP=str(basetemp))
        run.command("all-thirteen-finite-modules", [
            str(primary), "-B", "-I", str(HERE / "pytest_capture.py"),
            "--noconftest", "-c", "/dev/null", "--rootdir", str(SOURCE), "-q", "-m", "",
            "-p", "no:cacheprovider", "--basetemp", str(basetemp),
            "--junitxml", str(REPORT / "finite-junit.xml"), *CONFIG["finite_modules"],
        ], pytest_env, 240)
        finite = summarize(REPORT, CONFIG, before)
        if not finite["passed"]:
            run.errors.extend(finite["errors"])
        run.command("syntax-and-source-after", [
            str(primary), "-B", "-I", str(HERE / "source.py"), "after",
        ], env, 120)
    except Exception as error:
        run.errors.append(repr(error))
    finally:
        if env_before and primary is not None:
            try:
                run.require(run.command("environment-after", [
                    str(primary), "-B", "-I", str(HERE / "environment.py"), str(REPORT / "environment-after.json"),
                ], env, 120), "Final environment identity failed")
                environment_unchanged = ((REPORT / "environment-before.json").read_bytes() ==
                                         (REPORT / "environment-after.json").read_bytes())
                run.require(environment_unchanged, "Environment changed during checks")
            except Exception as error:
                run.errors.append("environment finalization: " + repr(error))
        try:
            after = source_map("after", original=True)
            source_unchanged = before is not None and after == before
            run.require(source_unchanged, "Exact immutable source changed during validation")
        except Exception as error:
            run.errors.append("source finalization: " + repr(error))
        expected = {
            "uv-version", "create-environment", "install-nine-locked-tools", "dependency-compatibility",
            "environment-before", "syntax-before", "original-admission-preservation", "git-diff-check",
            "ruff-nine-files", "ruff-format-nine-files", "basedpyright-four-implementations",
            "portable-c-compiler", "all-thirteen-finite-modules", "syntax-and-source-after", "environment-after",
        }
        passed = (not run.errors and source_unchanged and environment_unchanged
                  and finite is not None and finite["passed"]
                  and {row["name"] for row in run.steps} == expected
                  and all(row["passed"] for row in run.steps))
        identities = {}
        for name in ("source-before.json", "source-after.json", "environment-before.json", "environment-after.json",
                     "pytest-capture.json", "finite-junit.xml"):
            path = REPORT / name
            if path.is_file():
                identities[name] = {"bytes": path.stat().st_size, "sha256": digest(path.read_bytes())}
        write_json(REPORT / "identity-summary.json", identities)
        junit = REPORT / "finite-junit.xml"
        if junit.is_file():
            write_json(REPORT / "finite-junit-log-copy.json", {
                "sha256": digest(junit.read_bytes()), "bytes": junit.stat().st_size, "xml": junit.read_text(),
            })
        outcome = {
            "schema": "hol-guard.macos-phase-finite-outcome.v1", "status": "finished", "passed": passed,
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "harness_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
            "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "errors": run.errors, "steps": run.steps,
            "source_unchanged": source_unchanged, "environment_unchanged": environment_unchanged,
            "actual_finite_results": finite, "finite_execution_credit": bool(passed),
            "native_qualification_credit": False, "installed_qualification_credit": False,
            "qualification_complete": False, "no_complete_descendant_cleanup_certificate": True,
        }
        write_json(REPORT / "job-outcome.json", outcome)
        for name in ("finite-results.json", "finite-junit-log-copy.json", "identity-summary.json",
                     "original-admission-preserved.json", "portable-c-compiler.json", "host.json", "job-outcome.json"):
            path = REPORT / name
            if path.is_file():
                emit_file(path, name, 262144)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
