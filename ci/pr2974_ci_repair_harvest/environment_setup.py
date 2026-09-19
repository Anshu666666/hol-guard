"""Create and verify a fresh owned environment from the immutable project lock."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pwd
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
    env = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        env.pop(name, None)
    env.update(
        PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        UV_CACHE_DIR=str(SCRATCH / "uv-cache"), UV_LINK_MODE="copy", UV_NO_PROGRESS="1",
        UV_CONCURRENT_DOWNLOADS="1", UV_CONCURRENT_BUILDS="1", UV_CONCURRENT_INSTALLS="1",
        UV_PYTHON_DOWNLOADS="never", RAYON_NUM_THREADS="1",
        RUFF_CACHE_DIR=str(SCRATCH / "ruff-cache"),
    )
    test_tmp = Path(tempfile.mkdtemp(prefix="pr2974-ci-repair-tests-", dir="/tmp")).resolve(strict=True)
    info = test_tmp.lstat()
    assert test_tmp.parent == Path("/tmp").resolve() and stat.S_ISDIR(info.st_mode)
    assert info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700
    path_home = Path.home().resolve(strict=True)
    passwd_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    assert not test_tmp.is_symlink() and not test_tmp.is_relative_to(path_home)
    assert not test_tmp.is_relative_to(passwd_home)
    env.update(TMPDIR=str(test_tmp), VALIDATION_TEST_TMP=str(test_tmp))
    write_json(REPORT / "owned-test-temporary-root.json", {
        "path": str(test_tmp), "uid": info.st_uid, "mode": oct(stat.S_IMODE(info.st_mode)),
        "path_home": str(path_home), "passwd_home": str(passwd_home),
        "outside_path_home": True, "outside_passwd_home": True,
        "outside_actual_home": True, "home_changed": False,
        "pytest_basetemp_required_beneath": str(test_tmp),
        "qualification_complete": False})

    write_json(REPORT / "host.json", {
        "python_version": sys.version, "python_executable": sys.executable,
        "python_sha256": hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
        "uid": os.getuid(), "gid": os.getgid(), "uname": list(os.uname()),
        "cpu_count": os.cpu_count(), "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "cpu_models": sorted({line.split(":", 1)[1].strip()
            for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")}),
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
    return env, primary, create_venv


def finish_environment(run: Run, env: dict[str, str], primary: Path) -> None:
    run.require(run.command("environment-after", [
        str(primary), "-I", "-B", str(HERE / "environment.py"), str(REPORT / "environment-after.json"),
    ], env=env), "Final environment observation failed")
    run.require((REPORT / "environment-before.json").read_bytes() ==
                (REPORT / "environment-after.json").read_bytes(), "Owned environment changed")
