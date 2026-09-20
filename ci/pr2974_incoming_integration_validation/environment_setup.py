"""Create and verify a fresh owned environment from the immutable project lock."""

from __future__ import annotations

import hashlib
import os
import pwd
from pathlib import Path
import shutil
import stat
import sys
import tempfile

from common import CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, write_json


def secure_launchers(venv: Path) -> None:
    base = Path(sys.executable).resolve(strict=True)
    data = base.read_bytes()
    assert venv.is_dir() and not venv.is_symlink() and venv.stat().st_uid == os.getuid()
    for name in ("python", "python3", "python3.12"):
        path = venv / "bin" / name
        assert path.resolve(strict=True).read_bytes() == data, str(path)
        temporary = path.with_name(name + ".owned-copy")
        assert not temporary.exists()
        shutil.copyfile(base, temporary)
        temporary.chmod(0o755)
        temporary.replace(path)
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        assert path.read_bytes() == data


def prepare_environment(run: Run):
    assert run.before is not None, "Bind the complete immutable source before environment creation"
    assert ".".join(map(str, sys.version_info[:3])) == CONFIG["python_version"], sys.version
    real_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    environment_home = Path.home().resolve(strict=True)
    test_tmp = Path(tempfile.mkdtemp(prefix="pr2974-native-phase-tests-", dir="/tmp"))
    info = test_tmp.lstat()
    assert stat.S_ISDIR(info.st_mode) and not test_tmp.is_symlink() and info.st_uid == os.getuid()
    assert stat.S_IMODE(info.st_mode) == 0o700
    test_tmp = test_tmp.resolve(strict=True)
    assert test_tmp.parent == Path("/tmp").resolve(strict=True)
    assert not test_tmp.is_relative_to(real_home) and not test_tmp.is_relative_to(environment_home)
    write_json(REPORT / "test-temp-root.json", {
        "path": str(test_tmp), "real_home": str(real_home), "environment_home": str(environment_home),
        "uid": info.st_uid, "mode": oct(stat.S_IMODE(info.st_mode)),
        "direct_child_of_tmp": True, "outside_real_and_environment_home": True,
        "passed": True, "qualification_complete": False,
    })
    env = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        env.pop(name, None)
    env.update(
        PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        UV_CACHE_DIR=str(SCRATCH / "uv-cache"), UV_LINK_MODE="copy", UV_NO_PROGRESS="1",
        UV_CONCURRENT_DOWNLOADS="1", UV_CONCURRENT_BUILDS="1", UV_CONCURRENT_INSTALLS="1",
        UV_PYTHON_DOWNLOADS="never", TMPDIR=str(test_tmp), VALIDATION_TEST_TMP=str(test_tmp), RAYON_NUM_THREADS="1",
        RUFF_CACHE_DIR=str(SCRATCH / "ruff-cache"),
    )
    write_json(REPORT / "host.json", {
        "python_version": sys.version, "python_executable": sys.executable,
        "python_sha256": hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
        "uid": os.getuid(), "gid": os.getgid(), "uname": list(os.uname()),
        "image": {name: os.environ.get(name) for name in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")},
        "qualification_complete": False,
    })
    uv = os.environ["VALIDATION_UV"]
    run.require(run.command("uv-version", [uv, "--version"], cwd=SCRATCH, env=env), "uv version query failed")
    version = (REPORT / "uv-version.log").read_text().strip()
    run.require(version.split()[:2] == ["uv", CONFIG["uv_version"]], "Wrong uv version")
    write_json(REPORT / "uv-binary.json", {
        "path": str(Path(uv).resolve()), "sha256": hashlib.sha256(Path(uv).resolve().read_bytes()).hexdigest(),
        "version_output": version,
    })

    def create_venv(name: str) -> Path:
        path = SCRATCH / name
        run.require(not path.exists() and not path.is_symlink(), "Refuse an existing environment")
        run.require(run.command("create-" + name, [
            sys.executable, "-I", "-B", "-m", "venv", "--copies", "--without-pip", str(path),
        ], cwd=SCRATCH, timeout=90, env=env), "Virtual environment creation failed")
        secure_launchers(path)
        return path

    venv = create_venv("validation-environment")
    primary = venv / "bin/python"
    env.update(UV_PROJECT_ENVIRONMENT=str(venv), VALIDATION_VENV=str(venv))
    run.require(run.command("frozen-project-install", [
        uv, "--no-config", "sync", "--frozen", "--extra", "dev", "--python", str(primary),
    ], timeout=420, env=env), "Frozen project installation failed")
    secure_launchers(venv)
    run.require(run.command("dependency-compatibility", [
        uv, "--no-config", "pip", "check", "--python", str(primary),
    ], env=env), "Installed dependencies are incompatible")
    run.require(run.command("environment-before", [
        str(primary), "-I", "-B", str(HERE / "environment.py"), str(REPORT / "environment-before.json"),
    ], env=env), "Owned environment identity failed")
    env["VALIDATION_PYTHON"] = str(primary)
    return env, primary, create_venv


def finish_environment(run: Run, env: dict[str, str], primary: Path) -> None:
    run.require(run.command("environment-after", [
        str(primary), "-I", "-B", str(HERE / "environment.py"), str(REPORT / "environment-after.json"),
    ], env=env), "Final environment observation failed")
    run.require((REPORT / "environment-before.json").read_bytes() ==
                (REPORT / "environment-after.json").read_bytes(), "Owned environment changed")
