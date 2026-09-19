"""Validate the exact source candidate under a fresh owned Python environment."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, git, source_witness, write_json
from packages import run_packages


def secure_launchers(venv: Path) -> None:
    base = Path(sys.executable).resolve()
    base_data = base.read_bytes()
    assert venv.is_dir() and not venv.is_symlink() and venv.stat().st_uid == os.getuid()
    for name in ("python", "python3", "python3.12"):
        path = venv / "bin" / name
        assert path.resolve().read_bytes() == base_data, str(path)
        temporary = path.with_name(name + ".owned-copy")
        assert not temporary.exists()
        shutil.copyfile(base, temporary)
        temporary.chmod(0o755)
        temporary.replace(path)
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        assert path.read_bytes() == base_data


def selected_files(family: str) -> list[str]:
    digits = "[0-9][0-9]" if family == "cli" else "[0-9][0-9][0-9]"
    pattern = "tests/test_guard_" + family + "_" + digits + "_*.py"
    facade = "tests/test_guard_" + family + ".py"
    paths = sorted(value.decode() for value in git("ls-files", "-z", "--", facade, pattern).split(b"\0") if value)
    count = 49 if family == "cli" else 62
    width = 2 if family == "cli" else 3
    expression = re.compile(r"tests/test_guard_" + family + r"_(\d{" + str(width) + r"})_.+\.py\Z")
    numbered = [path for path in paths if path != facade]
    matches = [expression.fullmatch(path) for path in numbered]
    assert facade in paths and len(paths) == count + 1 and all(matches), paths
    assert sorted(int(match[1]) for match in matches) == list(range(1, count + 1))
    return paths


def validate_collection(path: Path, expected: int, selected: list[str]) -> dict[str, object]:
    result = json.loads(path.read_text())
    nodes = result["nodeids"]
    assert result["pytest_exit_code"] == 0 and result["error"] is None
    assert len(nodes) == expected and len(set(nodes)) == expected, len(nodes)
    assert all(node.split("::", 1)[0] in selected for node in nodes)
    assert result["product_module_origins"], "No actual product source origins observed"
    return result


def validate_junit(path: Path, expected: int) -> dict[str, int]:
    root = ET.parse(path).getroot()
    cases = root.findall(".//testcase")
    counts = {"tests": len(cases), "failed": sum(case.find("failure") is not None for case in cases),
              "errored": sum(case.find("error") is not None for case in cases),
              "skipped": sum(case.find("skipped") is not None for case in cases)}
    assert counts == {"tests": expected, "failed": 0, "errored": 0, "skipped": 0}, counts
    return counts | {"passed": expected}


def main() -> int:
    run = Run("finite-and-package")
    errors = []
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.update(
        PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
        UV_CACHE_DIR=str(SCRATCH / "uv-cache"), UV_LINK_MODE="copy", UV_NO_PROGRESS="1",
        UV_CONCURRENT_DOWNLOADS="1", UV_CONCURRENT_BUILDS="1", UV_CONCURRENT_INSTALLS="1",
        UV_PYTHON_DOWNLOADS="never", TMPDIR=str(SCRATCH / "tmp"), RAYON_NUM_THREADS="1",
    )
    (SCRATCH / "tmp").mkdir(exist_ok=True)
    primary = None

    def create_venv(name: str) -> Path:
        path = SCRATCH / name
        run.require(not path.exists(), "Refuse existing virtual environment")
        run.require(run.command("create-" + name, [
            sys.executable, "-I", "-m", "venv", "--copies", "--without-pip", str(path),
        ], timeout=90, env=env), "Virtual environment creation failed")
        secure_launchers(path)
        return path

    try:
        run.before = source_witness("before")
        run.require(".".join(map(str, sys.version_info[:3])) == CONFIG["python_version"], "Wrong host Python")
        write_json(REPORT / "host.json", {
            "python_version": sys.version, "python_executable": sys.executable,
            "python_sha256": hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest(),
            "uid": os.getuid(), "gid": os.getgid(), "uname": list(os.uname()),
            "image": {name: os.environ.get(name) for name in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")},
            "qualification_complete": False,
        })
        uv = os.environ["VALIDATION_UV"]
        run.require(run.command("uv-version", [uv, "--version"], env=env), "uv version query failed")
        uv_version = (REPORT / "uv-version.log").read_text().strip()
        run.require(uv_version.startswith("uv " + CONFIG["uv_version"] + " ") or
                    uv_version == "uv " + CONFIG["uv_version"], "Wrong uv version")
        write_json(REPORT / "uv-binary.json", {
            "path": str(Path(uv).resolve()), "sha256": hashlib.sha256(Path(uv).resolve().read_bytes()).hexdigest(),
            "version_output": uv_version,
        })
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
            str(primary), "-I", str(HERE / "environment.py"), str(REPORT / "environment-before.json"),
        ], env=env), "Owned environment identity failed")
        families = {"cli": (261, 6), "runtime": (718, 4)}
        results = {}
        for family, (expected_collection, expected_tests) in families.items():
            paths = selected_files(family)
            write_json(REPORT / (family + "-selected-files.json"), paths)
            capture = REPORT / (family + "-collection.json")
            pytest_env = dict(env, VALIDATION_PYTEST_REPORT=str(capture))
            collection_ok = run.command(family + "-collection", [
                str(primary), "-I", str(HERE / "pytest_capture.py"), "--collect-only", "-q", "-m", "",
                "-o", "cache_dir=" + str(SCRATCH / ("pytest-cache-" + family)), *paths,
            ], timeout=240, env=pytest_env)
            try:
                assert collection_ok, "Collection command failed"
                validate_collection(capture, expected_collection, paths)
            except Exception as error:
                errors.append(family + " collection: " + repr(error))
            selected = CONFIG[family + "_selectors"]
            test_capture = REPORT / (family + "-affected-collection.json")
            junit = REPORT / (family + "-affected-junit.xml")
            pytest_env = dict(env, VALIDATION_PYTEST_REPORT=str(test_capture))
            tests_ok = run.command(family + "-affected-tests", [
                str(primary), "-I", str(HERE / "pytest_capture.py"), "-q", "-m", "", "--tb=short",
                "-o", "cache_dir=" + str(SCRATCH / ("pytest-cache-" + family)),
                "--basetemp", str(SCRATCH / (family + "-test-temporary")),
                "--junitxml", str(junit), *selected,
            ], timeout=240, env=pytest_env)
            try:
                assert tests_ok, "Affected test command failed"
                validate_collection(test_capture, expected_tests, paths)
                results[family] = validate_junit(junit, expected_tests)
            except Exception as error:
                errors.append(family + " affected tests: " + repr(error))
        write_json(REPORT / "finite-results.json", {
            "actual_junit_results": results, "required_collection": {"cli": 261, "runtime": 718},
            "errors": errors, "qualification_complete": False,
        })
        fixed = sorted(CONFIG["fixed_files"])
        run.command("ruff-five-files", [str(venv / "bin/ruff"), "check", *fixed], env=env)
        run.command("ruff-format-five-files", [str(venv / "bin/ruff"), "format", "--check", *fixed], env=env)
        try:
            run_packages(run, env, primary, create_venv)
        except Exception as error:
            errors.append("package validation: " + repr(error))
        run.require(run.command("environment-after", [
            str(primary), "-I", str(HERE / "environment.py"), str(REPORT / "environment-after.json"),
        ], env=env), "Final environment observation failed")
        run.require((REPORT / "environment-before.json").read_bytes() ==
                    (REPORT / "environment-after.json").read_bytes(), "Owned environment changed")
    except Exception as error:
        errors.append(repr(error))
    run.error = "; ".join(errors) if errors else None
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
