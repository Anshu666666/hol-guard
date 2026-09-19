"""Format one immutable candidate and retain complete recoverable source; no finite execution."""

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


def source_delta(before, after) -> list[str]:
    assert before.keys() == after.keys()
    changed = [path for path in before if before[path] != after[path]]
    assert set(changed) <= set(CONFIG["format_files"]), changed
    return sorted(changed)


def export_source(tree, changed) -> dict[str, object]:
    files = []
    for relative in CONFIG["changed_files"]:
        data = (SOURCE / relative).read_bytes()
        files.append({"path": relative, "mode": "100644", "sha256": digest(data),
                      "bytes": len(data), "content": data.decode("utf-8")})
    value = {
        "schema": "hol-guard.macos-phase-formatted-source.v1", "input_commit": CONFIG["source_sha"],
        "input_tree": CONFIG["source_tree"], "public_parent": CONFIG["source_parent"],
        "post_format_tree": tree, "changed_from_input": changed, "files": files,
        "harness_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "finite_execution_credit": False,
        "native_qualification_credit": False, "installed_qualification_credit": False,
    }
    path = REPORT / "formatted-source-payload.json"
    write_json(path, value)
    emit_file(path, "formatted-source-payload")
    return {"path": path.name, "bytes": path.stat().st_size, "sha256": digest(path.read_bytes())}


def main() -> int:
    run = Run()
    before = formatted = None
    tree = None
    changed = []
    payload = None
    primary = None
    env_before = False
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
        run.require(run.command("syntax-before", [
            str(primary), "-B", "-I", str(HERE / "source.py"), "before",
        ], env), "Original candidate syntax failed")
        run.command("import-sort-eight-files", [
            str(venv / "bin/ruff"), "check", "--no-cache", "--select", "I", "--fix", *CONFIG["format_files"],
        ], env)
        run.command("format-eight-files", [
            str(venv / "bin/ruff"), "format", "--no-cache", *CONFIG["format_files"],
        ], env)
        formatted = source_map("formatted")
        changed = source_delta(before, formatted)
        git("add", "--", *CONFIG["format_files"])
        tree = git("write-tree").decode().strip()
        write_json(REPORT / "post-format-tree.json", {
            "input_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"],
            "post_format_tree": tree, "changed_from_input": changed,
            "source_before_map_sha256": digest((REPORT / "source-before.json").read_bytes()),
            "source_formatted_map_sha256": digest((REPORT / "source-formatted.json").read_bytes()),
            "immutable_formatted_commit": None, "finite_execution_credit": False,
        })
        commands = [
            ("syntax-and-format-equivalence", [str(primary), "-B", "-I", str(HERE / "source.py"), "after"]),
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
    except Exception as error:
        run.errors.append(repr(error))
    finally:
        if env_before and primary is not None:
            try:
                run.require(run.command("environment-after", [
                    str(primary), "-B", "-I", str(HERE / "environment.py"), str(REPORT / "environment-after.json"),
                ], env, 120), "Final environment identity failed")
                run.require((REPORT / "environment-before.json").read_bytes() ==
                            (REPORT / "environment-after.json").read_bytes(), "Environment changed during checks")
            except Exception as error:
                run.errors.append("environment finalization: " + repr(error))
        try:
            after = source_map("after")
            if formatted is not None:
                run.require(after == formatted, "Source changed during checks")
                run.require(git("write-tree").decode().strip() == tree, "Post-format index tree changed")
            elif before is not None:
                changed = source_delta(before, after)
            payload = export_source(tree, changed)
        except Exception as error:
            run.errors.append("source finalization: " + repr(error))
        expected = {
            "uv-version", "create-environment", "install-nine-locked-tools", "dependency-compatibility",
            "environment-before", "syntax-before", "import-sort-eight-files", "format-eight-files",
            "syntax-and-format-equivalence", "original-admission-preservation", "git-diff-check",
            "ruff-nine-files", "ruff-format-nine-files", "basedpyright-four-implementations", "environment-after",
        }
        passed = (not run.errors and payload is not None and tree is not None
                  and {row["name"] for row in run.steps} == expected
                  and all(row["passed"] for row in run.steps))
        outcome = {
            "schema": "hol-guard.macos-phase-format-outcome.v1", "status": "finished", "passed": passed,
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "post_format_tree": tree, "harness_sha": os.environ["GITHUB_SHA"],
            "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
            "payload": payload, "changed_from_input": changed, "errors": run.errors, "steps": run.steps,
            "finite_execution_credit": False, "native_qualification_credit": False,
            "installed_qualification_credit": False, "qualification_complete": False,
            "no_complete_descendant_cleanup_certificate": True,
        }
        write_json(REPORT / "job-outcome.json", outcome)
        for name in ("format-equivalence.json", "original-admission-preserved.json", "post-format-tree.json",
                     "host.json", "uv-binary.json", "job-outcome.json"):
            path = REPORT / name
            if path.is_file():
                emit_file(path, name, 65536)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
