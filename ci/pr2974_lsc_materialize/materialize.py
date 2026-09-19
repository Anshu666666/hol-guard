"""Materialize the reviewed source bytes without importing or testing the product."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HARNESS, HERE, REPORT, ROOT, SCRATCH, command, frame, harness_witness, sha256, witness, write_json
from source_inventory import inventory


def secure_launchers(venv: Path) -> None:
    source = Path(sys.executable).resolve()
    data = source.read_bytes()
    assert venv.is_dir() and not venv.is_symlink() and venv.stat().st_uid == os.getuid()
    for name in ("python", "python3", "python3.12"):
        path = venv / "bin" / name
        assert path.resolve().read_bytes() == data
        temporary = path.with_name(name + ".owned-copy")
        assert not temporary.exists()
        shutil.copyfile(source, temporary)
        temporary.chmod(0o755)
        temporary.replace(path)
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def git_tree(files: dict[str, dict[str, object]]) -> str:
    root = {}
    for path, row in files.items():
        target = root
        parts = path.split("/")
        for name in parts[:-1]:
            target = target.setdefault(name, {})
        assert parts[-1] not in target
        target[parts[-1]] = (row["mode"], row["git_blob"])
    def visit(node):
        rows = []
        for name, value in node.items():
            is_directory = isinstance(value, dict)
            mode, sha = ("40000", visit(value)) if is_directory else value
            rows.append((name + "/" if is_directory else name,
                         (mode + " " + name).encode() + b"\0" + bytes.fromhex(sha)))
        payload = b"".join(row[1] for row in sorted(rows, key=lambda row: row[0].encode()))
        return hashlib.sha1(b"tree " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
    return visit(root)


def copy_source(before: dict[str, object], destination: Path) -> None:
    assert not destination.exists()
    destination.mkdir(parents=True)
    for relative, row in before["files"].items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = (ROOT / "source" / relative).read_bytes()
        assert sha256(data) == row["sha256"], relative
        target.write_bytes(data)
        target.chmod(0o755 if row["mode"] == "100755" else 0o644)


def ruff_hashes() -> list[str]:
    lock = tomllib.loads((ROOT / "source" / "uv.lock").read_text())
    candidates = [row for row in lock["package"] if row["name"] == "ruff"]
    assert len(candidates) == 1 and candidates[0]["version"] == CONFIG["ruff_version"]
    package = candidates[0]
    hashes = sorted({row["hash"] for row in [package["sdist"], *package["wheels"]]})
    assert hashes and all(value.startswith("sha256:") and len(value) == 71 for value in hashes)
    return hashes


def collect_generated(before: dict[str, object], worktree: Path) -> dict[str, object]:
    historical = CONFIG["historical_review"]
    expected = {historical["path_prefix"] + path: digest for path, digest in historical["files"].items()}
    expected[CONFIG["test_path"]] = CONFIG["fresh_test_sha256"]
    actual = sorted(str(path.relative_to(worktree)) for path in
                    (worktree / "src/codex_plugin_scanner/guard").glob("local_supply_chain*.py"))
    assert set(actual) == set(expected) - {CONFIG["test_path"]}
    result = {}
    for relative, digest in expected.items():
        path = worktree / relative
        data = path.read_bytes()
        assert sha256(data) == digest, relative
        assert data.endswith(b"\n") and b"\r\n" not in data, relative
        assert len(data.splitlines()) <= 500, relative
        result[relative] = {"sha256": digest, "git_blob": git_blob(data), "bytes": len(data),
                            "physical_lines": len(data.splitlines()), "mode": "100644",
                            "complete_text": data.decode("utf-8"),
                            "historical_production_match": relative != CONFIG["test_path"]}
    expected_paths = set(before["files"]) | set(expected)
    actual_paths = {str(path.relative_to(worktree)) for path in worktree.rglob("*") if path.is_file()}
    assert actual_paths == expected_paths, sorted(actual_paths ^ expected_paths)
    for relative, row in before["files"].items():
        if relative not in result:
            assert sha256((worktree / relative).read_bytes()) == row["sha256"], relative
    all_files = {**before["files"], **result}
    return {"source_sha": CONFIG["sources"]["source"]["sha"],
            "source_tree": CONFIG["sources"]["source"]["tree"],
            "prospective_tree": git_tree(all_files), "prospective_files": len(all_files),
            "files": result, "historical_review": historical,
            "production_historical_byte_matches": len(expected) - 1,
            "fresh_test_historical_match_claim": False, "scope": CONFIG["scope"]}


def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    SCRATCH.mkdir(mode=0o700, parents=True, exist_ok=True)
    source = ROOT / "source"
    worktree = SCRATCH / "generated-source"
    rows = []
    errors = []
    before = None
    packet = None
    census_complete = False
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", UV_NO_PROGRESS="1",
               UV_LINK_MODE="copy", UV_PYTHON_DOWNLOADS="never", UV_CACHE_DIR=str(SCRATCH / "uv-cache"),
               RAYON_NUM_THREADS="1", RUFF_CACHE_DIR=str(SCRATCH / "ruff-cache"), LSC_SOURCE=str(source))
    try:
        assert ".".join(map(str, sys.version_info[:3])) == CONFIG["python_version"]
        harness_witness()
        before = witness("source", "before")
        assert git_tree(before["files"]) == CONFIG["sources"]["source"]["tree"]
        original = (HERE / "original_generator.py.txt").read_bytes()
        adapted = (HERE / "generator.py").read_bytes()
        assert sha256(original) == CONFIG["original_generator_sha256"]
        assert sha256(adapted) == CONFIG["adapted_generator_sha256"]
        assert sha256((HERE / "seam_test.py.txt").read_bytes()) == CONFIG["fresh_test_sha256"]
        census_complete = inventory(before)
        copy_source(before, worktree)
        uv = os.environ["LSC_UV"]
        assert command("uv-version", [uv, "--version"], source, env, 30, rows)
        version = (REPORT / "uv-version.log").read_text().strip()
        assert version == "uv " + CONFIG["uv_version"] or version.startswith("uv " + CONFIG["uv_version"] + " ")
        venv = SCRATCH / "ruff-environment"
        assert not venv.exists()
        assert command("create-ruff-environment", [sys.executable, "-I", "-m", "venv",
                       "--copies", "--without-pip", str(venv)], source, env, 90, rows)
        secure_launchers(venv)
        python = str(venv / "bin/python")
        hashes = ruff_hashes()
        requirement = "ruff==" + CONFIG["ruff_version"] + " " + " ".join("--hash=" + value for value in hashes) + "\n"
        requirements = REPORT / "ruff-requirement.txt"
        requirements.write_text(requirement)
        assert command("install-lock-bound-ruff", [uv, "--no-config", "pip", "install", "--python", python,
                       "--no-deps", "--require-hashes", "-r", str(requirements)], source, env, 180, rows)
        secure_launchers(venv)
        inventory_code = ("import importlib.metadata,json,sys;"
                          "print(json.dumps({'python':sys.version,'prefix':sys.prefix,"
                          "'versions':{d.metadata['Name'].lower():d.version for d in importlib.metadata.distributions()}},sort_keys=True))")
        assert command("owned-environment", [python, "-I", "-c", inventory_code], source, env, 30, rows)
        owned = json.loads((REPORT / "owned-environment.log").read_text())
        assert owned["versions"] == {"ruff": CONFIG["ruff_version"]}
        assert Path(owned["prefix"]).resolve() == venv
        assert command("generate-source", [python, "-I", str(HERE / "generator.py")], source, env, 60, rows)
        generation = json.loads((REPORT / "generation/generation-receipt.json").read_text())
        assert len(generation["mapping"]) == CONFIG["expected_moved_functions"]
        assert generation["live_facade_lookup_count"] == CONFIG["expected_live_facade_loads"]
        paths = sorted(str(path.relative_to(worktree)) for path in
                       (worktree / "src/codex_plugin_scanner/guard").glob("local_supply_chain*.py"))
        assert len(paths) == CONFIG["expected_production_files"]
        test = worktree / CONFIG["test_path"]
        test.write_bytes((HERE / "seam_test.py.txt").read_bytes())
        ruff = str(venv / "bin/ruff")
        facade = CONFIG["source_path"]
        assert command("format-production", [ruff, "format", *paths], worktree, env, 60, rows)
        assert command("facade-import-order", [ruff, "check", "--select", "I", "--fix", facade], worktree, env, 60, rows)
        assert command("facade-live-import-diagnostics", [ruff, "check", "--select", "F401",
                       "--output-format", "json", facade], worktree, env, 60, rows, expected_returncode=1)
        diagnostics = json.loads((REPORT / "facade-live-import-diagnostics.log").read_text())
        assert diagnostics and all(row["code"] == "F401" for row in diagnostics)
        suppressions = sorted({row["noqa_row"] for row in diagnostics})
        lines = (worktree / facade).read_text().splitlines(keepends=True)
        for row in suppressions:
            assert "#" not in lines[row - 1]
            lines[row - 1] = lines[row - 1].rstrip() + "  # noqa: F401\n"
        (worktree / facade).write_text("".join(lines))
        assert command("format-final", [ruff, "format", *paths, CONFIG["test_path"]], worktree, env, 60, rows)
        assert command("lint-final", [ruff, "check", *paths, CONFIG["test_path"]], worktree, env, 60, rows)
        packet = collect_generated(before, worktree)
        packet["live_facade_lookups"] = generation["live_facade_lookup_count"]
        packet["moved_functions"] = len(generation["mapping"])
        packet["fresh_test_unrun"] = True
        write_json(REPORT / "complete-source-payload.json", packet)
        frame("lsc-complete-source-payload", packet)
    except Exception as error:
        errors.append(repr(error))
    finally:
        if worktree.exists() and packet is None:
            try:
                partial = {}
                paths = sorted((worktree / "src/codex_plugin_scanner/guard").glob("local_supply_chain*.py"))
                test = worktree / CONFIG["test_path"]
                if test.exists():
                    paths.append(test)
                for path in paths:
                    data = path.read_bytes()
                    partial[str(path.relative_to(worktree))] = {
                        "bytes": len(data), "sha256": sha256(data), "git_blob": git_blob(data),
                        "complete_text": data.decode("utf-8"), "historical_match_verified": False}
                write_json(REPORT / "unverified-partial-source-payload.json", partial)
                frame("lsc-unverified-partial-source-payload", partial)
            except Exception as error:
                errors.append("partial source retention: " + repr(error))
        try:
            after = witness("source", "after")
            assert before is not None and after == before, "Original immutable source changed"
        except Exception as error:
            errors.append("source finalizer: " + repr(error))
        passed = not errors and packet is not None and census_complete and all(row["passed"] for row in rows)
        outcome = {"passed": passed, "errors": errors, "source_packet_complete": packet is not None,
                   "source_text_inventory_complete": census_complete, "commands": rows,
                   "scope": CONFIG["scope"], "qualification_complete": False}
        write_json(REPORT / "outcome.json", outcome)
        frame("lsc-materializer-outcome", outcome)
        files = {str(path.relative_to(REPORT)): {"bytes": path.stat().st_size, "sha256": sha256(path.read_bytes())}
                 for path in sorted(REPORT.rglob("*")) if path.is_file() and path.name != "artifact-manifest.json"}
        write_json(REPORT / "artifact-manifest.json", {"files": files})
        frame("lsc-materializer-artifact-manifest", {"files": files})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
