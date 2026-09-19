"""Run only immutable-source Ruff checks and preserve complete diagnostics."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import tomllib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, REPORT, SCRATCH, SOURCE, Run, sha256, source_witness, write_json

PYTHON = SCRATCH / "ruff-venv/bin/python"
SCOPE_PATHS = CONFIG["lint_paths"]


def require_no_project_imports() -> None:
    loaded = sorted(name for name in sys.modules if name == "codex_plugin_scanner"
                    or name.startswith("codex_plugin_scanner.") or name == "tests"
                    or name.startswith("tests."))
    assert not loaded, loaded


def secure_launchers() -> dict[str, object]:
    source = Path(sys._base_executable).resolve(strict=True)
    source_info = source.stat()
    assert stat.S_ISREG(source_info.st_mode)
    original = source.read_bytes()
    records = {}
    for name in ("python", "python3", "python3.12"):
        path = PYTHON.parent / name
        if path.exists() or path.is_symlink():
            path.unlink()
        path.write_bytes(original)
        path.chmod(0o755)
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        assert sha256(path.read_bytes()) == sha256(original)
        records[name] = {"path": str(path), "sha256": sha256(original), "uid": info.st_uid,
                         "mode": oct(stat.S_IMODE(info.st_mode)), "regular": True}
    return {"base_python": str(source), "base_sha256": sha256(original), "launchers": records}


def locked_ruff_requirement() -> str:
    raw = (SOURCE / "uv.lock").read_bytes()
    assert sha256(raw) == CONFIG["source_inputs"]["uv.lock"]
    matches = [package for package in tomllib.loads(raw.decode())["package"] if package["name"] == "ruff"]
    assert len(matches) == 1 and matches[0]["version"] == CONFIG["ruff_version"]
    package = matches[0]
    hashes = sorted({artifact["hash"] for artifact in
                     [package["sdist"], *package["wheels"]] if artifact is not None})
    assert hashes and all(value.startswith("sha256:") and len(value) == 71 for value in hashes)
    write_json(REPORT / "locked-ruff-artifacts.json", package)
    return "ruff==" + CONFIG["ruff_version"] + " " + " ".join("--hash=" + value for value in hashes) + "\n"


ENVIRONMENT_PROBE = r'''
import importlib.metadata, json, os, pathlib, platform, stat, sys, hashlib
assert sys.version.split()[0] == "3.12.13", sys.version
assert sys.prefix != sys.base_prefix
distributions = {item.metadata["Name"].lower().replace("_", "-"): item.version
                 for item in importlib.metadata.distributions()}
assert distributions == {"ruff": "0.15.17"}, distributions
paths = {}
for name in ("python", "python3", "python3.12", "ruff"):
    path = pathlib.Path(sys.executable).parent / name
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
    paths[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                   "uid": info.st_uid, "mode": oct(stat.S_IMODE(info.st_mode)), "regular": True}
assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
               for name in sys.modules)
result = {"python": sys.version, "executable": sys.executable, "platform": platform.platform(),
          "distributions": distributions, "files": paths, "project_imports": [],
          "qualification_complete": False}
pathlib.Path(sys.argv[1]).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
'''


def main() -> int:
    run = Run("package-evaluator-read-only-ruff-diagnostics")
    environment_before = None
    environment_after = None
    diagnostics = []
    try:
        require_no_project_imports()
        run.before = source_witness("before")
        assert sys.version.split()[0] == CONFIG["python_version"], sys.version
        assert len(SCOPE_PATHS) == CONFIG["scope_file_count"] == 23
        assert SCOPE_PATHS == sorted(CONFIG["partition_input_files"])
        assert all(path.endswith(".py") for path in SCOPE_PATHS)
        write_json(REPORT / "lint-input.json", {
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "paths": SCOPE_PATHS, "files": CONFIG["partition_input_files"],
            "source_read_only": True, "configuration_path": "pyproject.toml",
            "configuration_sha256": CONFIG["source_inputs"]["pyproject.toml"],
            "no_autofix_or_rule_changes": True, "qualification_complete": False,
        })
        env = os.environ.copy()
        for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
            env.pop(name, None)
        env.update(
            PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", UV_PYTHON_DOWNLOADS="never",
            UV_CACHE_DIR=str(SCRATCH / "uv-cache"), UV_LINK_MODE="copy", UV_NO_PROGRESS="1",
            UV_CONCURRENT_DOWNLOADS="1", UV_CONCURRENT_BUILDS="1", UV_CONCURRENT_INSTALLS="1",
            RUFF_CACHE_DIR=str(SCRATCH / "ruff-cache"), TMPDIR=str(SCRATCH / "tmp"),
        )
        Path(env["TMPDIR"]).mkdir(mode=0o700)
        uv = Path(os.environ["VALIDATION_UV"]).resolve(strict=True)
        assert stat.S_ISREG(uv.stat().st_mode)
        write_json(REPORT / "uv-binary.json", {"path": str(uv), "sha256": sha256(uv.read_bytes())})
        run.require(run.command("uv-version", [str(uv), "--version"], cwd=SCRATCH, env=env, timeout=30),
                    "uv version command failed")
        assert (REPORT / "uv-version.log").read_text().split()[:2] == ["uv", CONFIG["uv_version"]]
        run.require(run.command("create-ruff-only-venv", [
            sys.executable, "-I", "-B", "-m", "venv", "--copies", "--without-pip", str(PYTHON.parent.parent)
        ], cwd=SCRATCH, env=env, timeout=60), "Ruff environment creation failed")
        write_json(REPORT / "owned-python-launchers.json", secure_launchers())
        requirement = REPORT / "ruff-locked-requirement.txt"
        requirement.write_text(locked_ruff_requirement(), encoding="utf-8")
        run.require(run.command("install-hash-locked-ruff-only", [
            str(uv), "--no-config", "pip", "install", "--python", str(PYTHON),
            "--no-deps", "--require-hashes", "--requirements", str(requirement)
        ], cwd=SCRATCH, env=env, timeout=300), "Hash-locked Ruff-only installation failed")
        write_json(REPORT / "owned-python-launchers-after-install.json", secure_launchers())
        environment_before = REPORT / "ruff-environment-before.json"
        run.require(run.command("ruff-environment-before", [
            str(PYTHON), "-I", "-B", "-c", ENVIRONMENT_PROBE, str(environment_before)
        ], cwd=SCRATCH, env=env, timeout=30), "Fresh Ruff environment did not match")
        ruff = str(PYTHON.parent / "ruff")
        commands = [
            ("ruff-check-json", [ruff, "check", "--no-cache", "--no-fix",
                                 "--output-format", "json", "--", *SCOPE_PATHS]),
            ("ruff-check-text", [ruff, "check", "--no-cache", "--no-fix",
                                 "--output-format", "full", "--", *SCOPE_PATHS]),
            ("ruff-format-check", [ruff, "format", "--no-cache", "--check", "--", *SCOPE_PATHS]),
            ("ruff-format-diff", [ruff, "format", "--no-cache", "--diff", "--", *SCOPE_PATHS]),
        ]
        for name, args in commands:
            passed = run.command(name, args, cwd=SOURCE, env=env, timeout=180)
            row = run.steps[-1]
            diagnostics.append({
                "name": name, "passed": passed, "returncode": row.get("returncode"),
                "timed_out": row.get("timed_out"), "command": args,
                "group_cleanup": row.get("group_cleanup"), "log_sha256": row.get("log_sha256"),
                "log_bytes": row.get("log_bytes"),
            })
        raw_json = (REPORT / "ruff-check-json.log").read_bytes()
        try:
            parsed = json.loads(raw_json)
            assert isinstance(parsed, list)
            assert all(isinstance(item, dict) for item in parsed)
            by_code = {}
            for item in parsed:
                code = str(item.get("code"))
                by_code[code] = by_code.get(code, 0) + 1
            write_json(REPORT / "ruff-diagnostic-summary.json", {
                "count": len(parsed), "by_code": by_code, "original_log_sha256": sha256(raw_json),
                "complete_json_retained": True, "qualification_complete": False,
            })
        except BaseException as error:
            write_json(REPORT / "ruff-diagnostic-json-error.json", {"error": repr(error)})
            run.error = run.error or "Original Ruff JSON diagnostic output could not be parsed"
        environment_after = REPORT / "ruff-environment-after.json"
        run.require(run.command("ruff-environment-after", [
            str(PYTHON), "-I", "-B", "-c", ENVIRONMENT_PROBE, str(environment_after)
        ], cwd=SCRATCH, env=env, timeout=30), "Final Ruff environment did not match")
        assert environment_before.read_bytes() == environment_after.read_bytes()
    except BaseException as error:
        run.error = run.error or repr(error)
    finally:
        write_json(REPORT / "lint-result.json", {
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "checks": diagnostics, "all_four_checks_completed": len(diagnostics) == 4,
            "all_four_checks_passed": len(diagnostics) == 4 and all(row["passed"] for row in diagnostics),
            "source_read_only": True, "no_project_imports_or_tests": True,
            "environment_fingerprints_equal": bool(environment_before and environment_after
                and environment_before.is_file() and environment_after.is_file()
                and environment_before.read_bytes() == environment_after.read_bytes()),
            "qualification_complete": False,
        })
        try:
            require_no_project_imports()
        except BaseException as error:
            run.error = run.error or repr(error)
        passed = run.finish()
        return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
