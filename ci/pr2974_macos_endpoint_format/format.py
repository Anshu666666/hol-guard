"""Harvest exact formatter output without importing or executing project code."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tomllib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HARNESS, REPORT, SCRATCH, SOURCE, Run, sha256, source_witness, write_json
from format_bridge import prove
from import_bridge import compare_imports

COPY = SCRATCH / "formatted-source"
PYTHON = SCRATCH / "ruff-venv/bin/python"
FORMAT_PATHS = CONFIG["format_paths"]
SORTED_PAYLOAD = REPORT / "payload/import-sorted"
SCOPE_PATHS = sorted(CONFIG["partition_input_files"])


def require_no_project_imports() -> None:
    loaded = sorted(name for name in sys.modules if name in {"codex_plugin_scanner", "scripts", "tests"}
                    or name.startswith(("codex_plugin_scanner.", "scripts.", "tests.")))
    assert not loaded, loaded


def git_tree(files: dict[str, dict[str, object]]) -> str:
    root = {}
    for path, record in files.items():
        parts = path.split("/")
        directory = root
        for part in parts[:-1]:
            directory = directory.setdefault(part, {})
        assert parts[-1] not in directory
        directory[parts[-1]] = (record["mode"], record["git_blob"])

    def encode(directory):
        body = bytearray()
        entries = sorted(directory.items(), key=lambda item: (
            item[0] + ("/" if isinstance(item[1], dict) else "")).encode("utf-8"))
        for name, value in entries:
            mode, identity = ("40000", encode(value)) if isinstance(value, dict) else value
            body.extend(mode.encode() + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(identity))
        return hashlib.sha1(b"tree " + str(len(body)).encode() + b"\0" + body).hexdigest()

    return encode(root)


def file_record(path: Path) -> dict[str, object]:
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), str(path)
    raw = path.read_bytes()
    return {"git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
            "sha256": sha256(raw), "bytes": len(raw),
            "mode": "100755" if info.st_mode & 0o111 else "100644"}


def preserve_payload(label: str, root: Path) -> None:
    for relative in SCOPE_PATHS:
        path = root / relative
        if path.is_file() and not path.is_symlink():
            target = REPORT / "payload" / label / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())


def copy_source(files: dict[str, dict[str, object]]) -> None:
    assert not COPY.exists()
    COPY.mkdir(mode=0o700)
    for relative, record in files.items():
        target = COPY / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((SOURCE / relative).read_bytes())
        target.chmod(0o755 if record["mode"] == "100755" else 0o644)
        assert file_record(target) == record, relative


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
assert not any(name in {"codex_plugin_scanner", "scripts", "tests"} or name.startswith(("codex_plugin_scanner.", "scripts.", "tests."))
               for name in sys.modules)
result = {"python": sys.version, "executable": sys.executable, "platform": platform.platform(),
          "distributions": distributions, "files": paths, "project_imports": [],
          "qualification_complete": False}
pathlib.Path(sys.argv[1]).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
'''


def observe_copy(label: str, before: dict[str, dict[str, object]]) -> dict[str, object]:
    result = {"input_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"],
              "passed": False, "qualification_complete": False,
              "fresh_immutable_formatted_commit_and_validation_required": True}
    result["stage_label"] = label
    result["snapshot_is_execution_credit"] = False
    preserve_payload(label, COPY)
    files = {}
    errors = []
    for relative in before:
        try:
            files[relative] = file_record(COPY / relative)
        except BaseException as error:
            errors.append({"path": relative, "type": type(error).__name__, "message": str(error)})
    actual_paths = set()
    for directory, names, filenames in os.walk(COPY, followlinks=False):
        for name in names:
            path = Path(directory) / name
            if path.is_symlink():
                errors.append({"path": str(path), "type": "UnexpectedSymlinkDirectory"})
        for name in filenames:
            actual_paths.add((Path(directory) / name).relative_to(COPY).as_posix())
    result["missing_paths"] = sorted(set(before) - actual_paths)
    result["unexpected_paths"] = sorted(actual_paths - set(before))
    result["files"] = files
    result["errors"] = errors
    result["changed_paths"] = sorted(path for path in before if files.get(path) != before[path])
    result["changed_paths_outside_format_scope"] = sorted(set(result["changed_paths"]) - set(FORMAT_PATHS))
    result["mode_changes"] = sorted(path for path in files if files[path]["mode"] != before[path]["mode"])
    result["post_format_tree"] = git_tree(files) if len(files) == len(before) else None
    result["passed"] = bool(
        not errors and not result["missing_paths"] and not result["unexpected_paths"]
        and not result["changed_paths_outside_format_scope"] and not result["mode_changes"])
    write_json(REPORT / ("formatter-stage-" + label + ".json"), result)
    return result


def harvest(before: dict[str, dict[str, object]], sorted_state: dict[str, object],
            import_bridges: list[dict[str, object]], phases: dict[str, object]) -> dict[str, object]:
    result = observe_copy("after", before)
    bridges = []
    patches = {"import-order": [], "format-only": [], "combined": []}
    for relative in FORMAT_PATHS:
        original = (SOURCE / relative).read_bytes()
        middle = SORTED_PAYLOAD / relative
        path = COPY / relative
        if not path.is_file() or path.is_symlink() or not middle.is_file() or middle.is_symlink():
            bridges.append({"path": relative, "passed": False, "error": "Missing regular source snapshot"})
            continue
        imported = middle.read_bytes()
        formatted = path.read_bytes()
        bridge = prove(imported, formatted, relative, REPORT / "format-bridges")
        bridge["physical_lines"] = len(formatted.decode("utf-8").splitlines())
        bridge["within_500_physical_lines"] = bridge["physical_lines"] <= 500
        bridges.append(bridge)
        for label, left, right in (("import-order", original, imported),
                                   ("format-only", imported, formatted),
                                   ("combined", original, formatted)):
            patches[label].extend(difflib.unified_diff(
                left.decode().splitlines(keepends=True), right.decode().splitlines(keepends=True),
                fromfile="a/" + relative, tofile="b/" + relative))
    for label, lines in patches.items():
        (REPORT / (label + "-output.patch")).write_text("".join(lines), encoding="utf-8")
    result.update(
        import_sorted_tree=sorted_state.get("post_format_tree"),
        import_bridges=import_bridges, format_bridges=bridges, phases=phases,
        complete_payload_phases=["before", "import-sorted", "after"],
        non_python_additions_unchanged=not result["changed_paths_outside_format_scope"],
        import_order_side_effect_equivalence_claimed=False)
    result["passed"] = bool(
        result["passed"] and sorted_state.get("passed")
        and len(import_bridges) == len(bridges) == 10
        and all(item["passed"] for item in import_bridges)
        and all(item["passed"] and item["within_500_physical_lines"] for item in bridges)
        and phases.get("import_sort_passed") is True
        and phases.get("format_passed") is True and phases.get("format_check_passed") is True)
    write_json(REPORT / "formatter-harvest.json", result)
    return result


def observe_final_environment(run: Run, env: dict[str, str] | None,
                              before: Path | None) -> None:
    result = {"attempted": False, "observed": False, "unchanged": False,
              "qualification_complete": False, "scope": "Owned Ruff-only environment"}
    try:
        if env is None or not PYTHON.is_file() or PYTHON.is_symlink():
            result["reason"] = "Owned interpreter was not established before the earlier failure"
            return
        result["attempted"] = True
        target = REPORT / "ruff-environment-after.json"
        passed = run.command("ruff-environment-after", [
            str(PYTHON), "-I", "-B", "-c", ENVIRONMENT_PROBE, str(target)
        ], cwd=SCRATCH, env=env, timeout=30)
        result["command_passed"] = passed
        result["observed"] = target.is_file()
        if target.is_file():
            result["after_sha256"] = sha256(target.read_bytes())
        result["before_available"] = before is not None and before.is_file()
        if result["before_available"] and target.is_file():
            result["unchanged"] = before.read_bytes() == target.read_bytes()
            result["before_sha256"] = sha256(before.read_bytes())
        run.require(passed and result["unchanged"], "Final Ruff environment observation did not match")
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
        run.error = run.error or repr(error)
    finally:
        write_json(REPORT / "ruff-environment-final-observation.json", result)


def main() -> int:
    run = Run("macos-endpoint-source-only-formatter-harvest")
    environment_before = None
    env = None
    sorted_state = None
    import_bridges = []
    phases = {"import_sort_attempted": False, "import_sort_passed": False,
              "format_attempted": False, "format_passed": False, "format_check_passed": False}
    try:
        require_no_project_imports()
        preserve_payload("before", SOURCE)
        run.before = source_witness("before")
        assert sys.version.split()[0] == CONFIG["python_version"], sys.version
        assert len(SCOPE_PATHS) == 16 and len(FORMAT_PATHS) == 10
        assert FORMAT_PATHS == sorted(path for path in SCOPE_PATHS if path.endswith(".py"))
        assert git_tree(run.before["files"]) == CONFIG["source_tree"]
        copy_source(run.before["files"])
        write_json(REPORT / "format-input.json", {
            "input_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"],
            "files": run.before["files"], "format_paths": FORMAT_PATHS,
            "all16_payload_paths": SCOPE_PATHS, "source_copy": str(COPY),
            "qualification_complete": False})
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
        run.require(run.command("import-bridge-stdlib-controls", [
            sys.executable, "-I", "-B", str(Path(__file__).with_name("import_bridge_controls.py"))
        ], cwd=SCRATCH, env=env, timeout=30), "Inert source-proof controls failed")
        phases["import_sort_attempted"] = True
        phases["import_sort_passed"] = run.command("sort-exact-ten-python-imports", [
            str(PYTHON.parent / "ruff"), "check", "--select", "I", "--fix", "--", *FORMAT_PATHS
        ], cwd=COPY, env=env, timeout=60)
        sorted_state = observe_copy("import-sorted", run.before["files"])
        run.require(phases["import_sort_passed"] and sorted_state["passed"],
                    "Import sorting or source-copy admission failed; partial bytes are retained")
        for relative in FORMAT_PATHS:
            import_bridges.append(compare_imports(
                (SOURCE / relative).read_bytes(), (SORTED_PAYLOAD / relative).read_bytes(),
                relative, REPORT / "import-bridges"))
        write_json(REPORT / "import-bridge-results.json", import_bridges)
        run.require(len(import_bridges) == 10 and all(item["passed"] for item in import_bridges),
                    "The exact import/non-import bridge did not pass for every target")
        phases["format_attempted"] = True
        phases["format_passed"] = run.command("format-exact-ten-python-files", [
            str(PYTHON.parent / "ruff"), "format", "--", *FORMAT_PATHS
        ], cwd=COPY, env=env, timeout=60)
        run.require(phases["format_passed"], "Formatter failed; actual output is retained")
        phases["format_check_passed"] = run.command("check-exact-ten-formatted-files", [
            str(PYTHON.parent / "ruff"), "format", "--check", "--", *FORMAT_PATHS
        ], cwd=COPY, env=env, timeout=60)
        run.require(phases["format_check_passed"], "Formatter output failed its format check")
    except BaseException as error:
        run.error = repr(error)
    finally:
        if COPY.is_dir() and run.before is not None:
            try:
                if sorted_state is None:
                    sorted_state = observe_copy("import-sorted", run.before["files"])
                result = harvest(run.before["files"], sorted_state, import_bridges, phases)
                run.require(result["passed"], "Formatter payload or two-stage source bridge did not pass")
            except BaseException as error:
                write_json(REPORT / "harvest-error.json", {"type": type(error).__name__, "message": str(error)})
                run.error = run.error or repr(error)
        write_json(REPORT / "formatter-phases.json", phases)
        observe_final_environment(run, env, environment_before)
        try:
            require_no_project_imports()
        except BaseException as error:
            run.error = run.error or repr(error)
        return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
