"""Harvest exact formatter output without importing or executing project code."""

from __future__ import annotations

import base64
import difflib
import gzip
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

COPY = SCRATCH / "formatted-source"
PYTHON = SCRATCH / "ruff-venv/bin/python"
FORMAT_PATHS = CONFIG["format_paths"]
SCOPE_PATHS = sorted(CONFIG["partition_input_files"])


def require_no_project_imports() -> None:
    loaded = sorted(name for name in sys.modules if name == "codex_plugin_scanner"
                    or name.startswith("codex_plugin_scanner."))
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
assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
               for name in sys.modules)
result = {"python": sys.version, "executable": sys.executable, "platform": platform.platform(),
          "distributions": distributions, "files": paths, "project_imports": [],
          "qualification_complete": False}
pathlib.Path(sys.argv[1]).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
'''


def harvest(before: dict[str, dict[str, object]]) -> dict[str, object]:
    result = {"input_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"],
              "passed": False, "qualification_complete": False,
              "fresh_immutable_formatted_commit_and_validation_required": True}
    preserve_payload("after", COPY)
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
    bridges = []
    patch = []
    for relative in FORMAT_PATHS:
        old = (SOURCE / relative).read_bytes()
        path = COPY / relative
        if not path.is_file() or path.is_symlink():
            bridges.append({"path": relative, "passed": False, "error": "Missing regular output file"})
            continue
        new = path.read_bytes()
        bridge = prove(old, new, relative, REPORT / "format-bridges")
        bridge["physical_lines"] = len(new.decode("utf-8").splitlines())
        bridge["within_500_physical_lines"] = bridge["physical_lines"] <= 500
        bridges.append(bridge)
        patch.extend(difflib.unified_diff(
            old.decode().splitlines(keepends=True), new.decode().splitlines(keepends=True),
            fromfile="a/" + relative, tofile="b/" + relative,
        ))
    (REPORT / "format-output.patch").write_text("".join(patch), encoding="utf-8")
    result["bridges"] = bridges
    result["passed"] = bool(
        not errors and not result["missing_paths"] and not result["unexpected_paths"]
        and not result["changed_paths_outside_format_scope"] and not result["mode_changes"]
        and len(bridges) == CONFIG["format_file_count"] and all(item["passed"] and item["within_500_physical_lines"] for item in bridges)
    )
    write_json(REPORT / "formatter-harvest.json", result)
    return result


def emit_log_projection() -> None:
    """Expose completed source evidence to native log readers during runtime outages."""
    harvest_path = REPORT / "formatter-harvest.json"
    harvested = json.loads(harvest_path.read_text()) if harvest_path.is_file() else None
    outcome = json.loads((REPORT / "job-outcome.json").read_text())
    files = {}
    for relative in SCOPE_PATHS:
        path = REPORT / "payload/after" / relative
        if path.is_file():
            raw = path.read_bytes()
            files[relative] = {
                "content": raw.decode("utf-8"), "sha256": sha256(raw), "bytes": len(raw),
                "mode": None if harvested is None else harvested["files"].get(relative, {}).get("mode"),
                "git_blob": None if harvested is None else harvested["files"].get(relative, {}).get("git_blob"),
                "input_sha256": CONFIG["partition_input_files"][relative]["sha256"],
            }
    packet = {
        "schema": "pr2974-package-evaluator-format-log-projection-v1",
        "source_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"],
        "harness_commit": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "post_format_tree": None if harvested is None else harvested["post_format_tree"],
        "harvest_passed": False if harvested is None else harvested["passed"],
        "bridges": [] if harvested is None else harvested["bridges"],
        "changed_paths": [] if harvested is None else harvested["changed_paths"],
        "files": files, "job_outcome": outcome, "qualification_complete": False,
        "fresh_immutable_formatted_commit_and_validation_required": True,
    }
    raw = (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    compressed = gzip.compress(raw, compresslevel=9, mtime=0)
    encoded = base64.b64encode(compressed).decode("ascii")
    chunks = [encoded[index:index + 6000] for index in range(0, len(encoded), 6000)]
    summary = {
        "schema": packet["schema"], "raw_sha256": sha256(raw), "raw_bytes": len(raw),
        "gzip_sha256": sha256(compressed), "gzip_bytes": len(compressed),
        "base64_chars": len(encoded), "parts": len(chunks), "files": len(files),
    }
    compressed_path = REPORT / "log-source-projection.json.gz"
    compressed_path.write_bytes(compressed)
    summary_path = REPORT / "log-source-projection-manifest.json"
    write_json(summary_path, summary)
    manifest_path = REPORT / "artifact-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for path in (compressed_path, summary_path):
        data = path.read_bytes()
        manifest[path.name] = {"sha256": sha256(data), "bytes": len(data)}
    write_json(manifest_path, manifest)
    print("PR2974_FORMAT_PAYLOAD_BEGIN " + json.dumps(summary, sort_keys=True), flush=True)
    for index, chunk in enumerate(chunks):
        print("PR2974_FORMAT_PAYLOAD_PART " + json.dumps({
            "part": index + 1, "parts": len(chunks), "data": chunk,
        }, sort_keys=True), flush=True)
    print("PR2974_FORMAT_PAYLOAD_END " + json.dumps(summary, sort_keys=True), flush=True)


def main() -> int:
    run = Run("package-evaluator-source-only-formatter-harvest")
    copied = False
    environment_before = None
    environment_after = None
    try:
        require_no_project_imports()
        run.before = source_witness("before")
        assert sys.version.split()[0] == CONFIG["python_version"], sys.version
        assert len(SCOPE_PATHS) == CONFIG["scope_file_count"]
        assert len(FORMAT_PATHS) == CONFIG["format_file_count"]
        assert FORMAT_PATHS == sorted(path for path in SCOPE_PATHS if path.endswith(".py"))
        assert git_tree(run.before["files"]) == CONFIG["source_tree"]
        preserve_payload("before", SOURCE)
        copy_source(run.before["files"])
        copied = True
        write_json(REPORT / "format-input.json", {
            "input_commit": CONFIG["source_sha"], "input_tree": CONFIG["source_tree"],
            "files": run.before["files"], "format_paths": FORMAT_PATHS, "source_copy": str(COPY),
            "qualification_complete": False,
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
        run.require(run.command("format-exact-manifest-files", [
            str(PYTHON.parent / "ruff"), "format", "--", *FORMAT_PATHS
        ], cwd=COPY, env=env, timeout=180), "Formatter failed; original output is retained")
        run.require(run.command("check-exact-manifest-formatted-files", [
            str(PYTHON.parent / "ruff"), "format", "--check", "--", *FORMAT_PATHS
        ], cwd=COPY, env=env, timeout=180), "Formatter output failed its format check")
        environment_after = REPORT / "ruff-environment-after.json"
        run.require(run.command("ruff-environment-after", [
            str(PYTHON), "-I", "-B", "-c", ENVIRONMENT_PROBE, str(environment_after)
        ], cwd=SCRATCH, env=env, timeout=30), "Final Ruff environment did not match")
        assert environment_before.read_bytes() == environment_after.read_bytes()
    except BaseException as error:
        run.error = repr(error)
    finally:
        if copied:
            try:
                result = harvest(run.before["files"])
                run.require(result["passed"], "Formatter payload or AST/token/literal bridge did not pass")
            except BaseException as error:
                write_json(REPORT / "harvest-error.json", {"type": type(error).__name__, "message": str(error)})
                run.error = run.error or repr(error)
        try:
            require_no_project_imports()
        except BaseException as error:
            run.error = run.error or repr(error)
        passed = run.finish()
        try:
            emit_log_projection()
        except BaseException as error:
            write_json(REPORT / "log-projection-error.json", {
                "type": type(error).__name__, "message": str(error), "qualification_complete": False,
            })
            passed = False
        return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
