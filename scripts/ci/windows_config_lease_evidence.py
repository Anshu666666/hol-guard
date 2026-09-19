"""Bound a finite Windows directory-sharing control to installed source bytes."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import sysconfig
import zipfile
from pathlib import Path
from typing import Any

import tomllib

SOURCE_COMMIT = "8156ba5ec1e69908290d481bad421ba5f9bd93b2"
SOURCE_TREE = "1c551084cffda3f73ec410b432f0455579502754"
DRIVER_FILES = (
    ".github/workflows/windows-config-lease-diagnostic.yml",
    "scripts/ci/windows_config_lease_diagnostic.py",
    "scripts/ci/windows_config_lease_evidence.py",
    "tests/test_windows_config_lease_diagnostic.py",
)
MAX_REPORT_BYTES = 4 * 1024 * 1024


class DiagnosticError(RuntimeError):
    def __init__(self, code: str) -> None:
        if re.fullmatch(r"[a-z_]{1,96}", code) is None:
            raise ValueError("invalid diagnostic code")
        self.code = code
        super().__init__(code)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require(condition: bool, code: str) -> None:
    if not condition:
        raise DiagnosticError(code)


def checkout_binding(root: Path, expected: str) -> dict[str, object]:
    require(re.fullmatch(r"[0-9a-f]{40}", expected) is not None, "commit_invalid")

    def git(*args: str) -> str:
        return (
            subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.DEVNULL, timeout=30)
            .decode("utf-8")
            .strip()
        )

    commit = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    require(commit == expected, "checkout_commit_mismatch")
    require(not git("status", "--porcelain", "--untracked-files=all"), "checkout_changed")
    return {"commit": commit, "tree": tree, "tracked_files_unchanged": True, "untracked_files_absent": True}


def installed_binding(source: Path, wheel: Path, installed: Path) -> dict[str, object]:
    """Verify every installed package member against the wheel and clean source."""
    require(sys.prefix != sys.base_prefix, "isolated_environment_required")
    require(not os.environ.get("PYTHONPATH"), "pythonpath_must_be_unset")
    require(
        installed.resolve() == Path(sysconfig.get_path("purelib")).resolve() / "codex_plugin_scanner",
        "installed_package_location_mismatch",
    )
    require(not installed.resolve().is_relative_to((source / "src").resolve()), "source_package_not_installed")
    settings = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))
    included = settings["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    source_for_member = {destination: source / original for original, destination in included.items()}
    committed = set(
        subprocess.check_output(
            ["git", "-C", str(source), "ls-tree", "-rz", "--name-only", "HEAD"],
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        .decode("utf-8")
        .split("\0")
    )
    members: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as archive:
        require(len(archive.infolist()) <= 5000, "wheel_member_limit")
        for info in archive.infolist():
            if not info.filename.startswith("codex_plugin_scanner/") or info.is_dir():
                continue
            relative = Path(info.filename)
            require(".." not in relative.parts and "\\" not in info.filename, "wheel_member_invalid")
            require(info.file_size <= 32 * 1024 * 1024, "wheel_member_size_limit")
            require(info.filename not in members, "wheel_duplicate_member")
            payload = archive.read(info)
            original = source_for_member.get(info.filename, source / "src" / relative)
            require(original.relative_to(source).as_posix() in committed, "wheel_source_not_committed")
            require(original.read_bytes() == payload, "wheel_source_mismatch")
            require((installed.parent / relative).read_bytes() == payload, "installed_wheel_mismatch")
            members[info.filename] = digest(payload)
    require(bool(members), "wheel_package_missing")
    installed_python = {
        "codex_plugin_scanner/" + path.relative_to(installed).as_posix() for path in installed.rglob("*.py")
    }
    require(installed_python == {name for name in members if name.endswith(".py")}, "installed_python_set_mismatch")
    return {"wheel_sha256": digest(wheel.read_bytes()), "members": members, "installed_from_wheel": True}


def source_binding(source: Path, driver: Path, driver_commit: str, wheel: Path) -> dict[str, object]:
    import codex_plugin_scanner

    source_record = checkout_binding(source, SOURCE_COMMIT)
    require(source_record["tree"] == SOURCE_TREE, "source_tree_mismatch")
    driver_record = checkout_binding(driver, driver_commit)
    driver_record["files"] = {name: digest((driver / name).read_bytes()) for name in DRIVER_FILES}
    require(codex_plugin_scanner.__file__ is not None, "package_origin_missing")
    package = installed_binding(source, wheel, Path(codex_plugin_scanner.__file__).parent)
    versions: dict[str, list[str]] = {}
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata["Name"] or ""
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", name):
            versions.setdefault(name.lower(), []).append(distribution.version)
    require(all(len(values) == 1 for values in versions.values()), "duplicate_distribution_metadata")
    return {
        "source": source_record,
        "driver": driver_record,
        "package": package,
        "dependencies": versions,
        "python": platform.python_version(),
        "platform": platform.system(),
        "windows_version": list(platform.win32_ver()),
    }


def exception_record(error: BaseException) -> dict[str, object]:
    """Read only bounded code metadata; never messages, paths, args or locals."""
    chain: list[dict[str, object]] = []
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and len(chain) < 4 and id(current) not in seen:
        seen.add(id(current))
        category = type(current).__name__
        item: dict[str, object] = {
            "category": category if re.fullmatch(r"[A-Za-z_]{1,96}", category) else "other",
        }
        if type(current) is DiagnosticError:
            item["diagnostic_code"] = current.code
        if isinstance(current, OSError):
            for name in ("errno", "winerror"):
                value = getattr(current, name, None)
                if type(value) is int and 0 <= value <= 0xFFFFFFFF:
                    item[name] = value
        stack: list[dict[str, object]] = []
        traceback = current.__traceback__
        for _ in range(128):
            if traceback is None:
                break
            frame = traceback.tb_frame
            module = frame.f_globals.get("__name__", "")
            if isinstance(module, str) and module.startswith("codex_plugin_scanner."):
                origin = module.rsplit(".", 1)[-1] + "." + frame.f_code.co_name
                if re.fullmatch(r"[A-Za-z0-9_.]{1,128}", origin):
                    stack.append({"origin": origin, "line": traceback.tb_lineno})
                    stack = stack[-8:]
            traceback = traceback.tb_next
        item["stack"] = stack
        chain.append(item)
        current = current.__cause__
    return {"chain": chain, "chain_truncated": current is not None}


def write_report(path: Path, report: dict[str, Any]) -> None:
    payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
    require(len(payload) <= MAX_REPORT_BYTES, "report_size_limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(payload)


def _build_environment(python: str) -> dict[str, object]:
    program = (
        "import importlib.metadata,json,platform; "
        "print(json.dumps({'python':platform.python_version(),'distributions':"
        "sorted([{'name':d.metadata['Name'],'version':d.version} "
        "for d in importlib.metadata.distributions()],key=lambda d:d['name'])}))"
    )
    return json.loads(subprocess.check_output([python, "-I", "-c", program], timeout=30))


def build_wheel(source: Path, output: Path, report_path: Path) -> int:
    """Observe the real PEP517 build environment without calling it lock-bound."""
    report: dict[str, Any] = {
        "schema": "hol-guard.windows-config-lease-build.v1",
        "build_dependencies_fully_locked": False,
        "qualification": False,
        "passed": False,
    }
    try:
        from build import ProjectBuilder
        from build.env import DefaultIsolatedEnv

        report["source_before"] = checkout_binding(source, SOURCE_COMMIT)
        require(report["source_before"]["tree"] == SOURCE_TREE, "source_tree_mismatch")
        require(not output.exists(), "build_output_already_exists")
        report["frontend_version"] = importlib.metadata.version("build")
        report["installer_version"] = subprocess.check_output(["uv", "--version"], timeout=30).decode().strip()
        with DefaultIsolatedEnv(installer="uv") as environment:
            builder = ProjectBuilder.from_isolated_env(environment, str(source.resolve()))
            report["build_system_requires"] = sorted(builder.build_system_requires)
            environment.install(builder.build_system_requires)
            report["backend_before_requires_hook"] = _build_environment(environment.python_executable)
            requirements = builder.get_requires_for_build("wheel")
            report["additional_build_requires"] = sorted(requirements)
            environment.install(requirements)
            report["backend_before_wheel_hook"] = _build_environment(environment.python_executable)
            built = Path(builder.build("wheel", str(output.resolve())))
            report["backend_after_wheel_hook"] = _build_environment(environment.python_executable)
            require(built.resolve().parent == output.resolve(), "build_output_location_mismatch")
            report["wheel_name"] = built.name
            report["wheel_sha256"] = digest(built.read_bytes())
        report["source_after"] = checkout_binding(source, SOURCE_COMMIT)
        report["source_unchanged"] = report["source_before"] == report["source_after"]
        report["backend_unchanged_during_wheel_hook"] = (
            report["backend_before_wheel_hook"] == report["backend_after_wheel_hook"]
        )
        report["passed"] = report["source_unchanged"] and report["backend_unchanged_during_wheel_hook"]
    except Exception as error:
        report["failure"] = exception_record(error)
    write_report(report_path, report)
    print(f"windows_config_lease_build_passed={str(report['passed']).lower()}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the finite diagnostic wheel with observed backend versions.")
    parser.add_argument("--build-source", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    raise SystemExit(build_wheel(arguments.build_source, arguments.out_dir, arguments.output))
