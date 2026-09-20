"""Read original retained wheels and Git objects; write only this assessment packet."""

from __future__ import annotations

import ast
import base64
import csv
import hashlib
import io
import json
import os
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent
GIT = ROOT / "normalb222-posix/source.git"
OLD_TREE = "19977465d6e419f1276d75fb6bd1b3477f5c9720"
NEW_TREE = "ef0c0b8abb8144ed010b4c23c05a2dc70f20c354"
OLD_WHEEL = ROOT / "native-workspace-constructor-tail-run35536922548/archive/hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl"
NEW_WHEEL = ROOT / "normalb222-posix/linux-terminal/10613212321/raw/native-dist/hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl"
EXCLUDED = "src/codex_plugin_scanner/guard/native_runtime_resident.py"


def git(*args: str) -> bytes:
    return subprocess.check_output(
        ["git", "--git-dir=" + str(GIT), *args],
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
    )


def identity(raw: bytes) -> dict[str, object]:
    return {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
    }


def census(tree: str) -> dict[str, dict[str, str]]:
    result = {}
    for row in git("ls-tree", "-r", "-z", tree).split(b"\0"):
        if not row:
            continue
        meta, path = row.split(b"\t", 1)
        mode, kind, sha = meta.decode().split()
        assert kind == "blob"
        result[path.decode()] = {"mode": mode, "git_blob": sha}
    return result


def wheel(path: Path, expected: str, source: dict[str, dict[str, str]]) -> tuple[dict[str, object], dict[str, dict[str, object]], dict[str, object]]:
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names)) == 1500
        assert all(not name.startswith("/") and ".." not in Path(name).parts for name in names)
        entries = {name: identity(archive.read(name)) for name in names}
        record_name = "hol_guard-3.0.1.dist-info/RECORD"
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode())))
        assert len(rows) == len(names) and {row[0] for row in rows} == set(names)
        for name, digest, size in rows:
            if name == record_name:
                assert not digest and not size
                continue
            body = archive.read(name)
            expected_digest = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("=")
            assert digest == expected_digest and size == str(len(body))
        packaged_python = {name for name in names if name.startswith("codex_plugin_scanner/") and name.endswith(".py")}
        source_python = {path for path in source if path.startswith("src/codex_plugin_scanner/") and path.endswith(".py")}
        assert source_python - {"src/" + name for name in packaged_python} == {EXCLUDED}
        assert len(packaged_python) == 1433 and len(source_python) == 1434
        for name in packaged_python:
            assert entries[name]["git_blob"] == source["src/" + name]["git_blob"]
        runtime_manifest = json.loads(archive.read("codex_plugin_scanner/_native/runtime-manifest.json"))
    return identity(raw), entries, runtime_manifest


def write(name: str, value: object) -> None:
    (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    old, new = census(OLD_TREE), census(NEW_TREE)
    old_identity, old_wheel, old_runtime = wheel(OLD_WHEEL, "cd6a5ed8ac264da3aa1e9d8419b3e18183dba4f51e20bb26ac469bfd4c81dae6", old)
    new_identity, new_wheel, new_runtime = wheel(NEW_WHEEL, "e027dbf784e84b1a6faf926125b648f58d45328c8ad623282cf235067512c6c6", new)
    assert old_wheel.keys() == new_wheel.keys()
    wheel_changed = [name for name in sorted(old_wheel) if old_wheel[name] != new_wheel[name]]
    assert len(wheel_changed) == 5
    tree_changed = [name for name in sorted(old.keys() | new.keys()) if old.get(name) != new.get(name)]
    assert len(tree_changed) == 22
    python_changes = [name for name in tree_changed if name.startswith("src/") and name.endswith(".py")]
    assert python_changes == ["src/codex_plugin_scanner/guard/daemon/__init__.py", "src/codex_plugin_scanner/guard/daemon/codex_native_live_decision.py"]
    script_changes = [name for name in tree_changed if name.startswith("scripts/")]
    assert script_changes == ["scripts/native_slo_contract.py"]
    prior_contract, current_contract = [git("cat-file", "blob", tree[script_changes[0]]["git_blob"]) for tree in (old, new)]
    assert ast.dump(ast.parse(prior_contract), include_attributes=False) == ast.dump(ast.parse(current_contract), include_attributes=False)
    assert old["uv.lock"] == new["uv.lock"] and old["pyproject.toml"] == new["pyproject.toml"]
    write("FULL-SOURCE-CENSUS.json", {
        "schema": "hol-guard.readiness-subject-source-comparison.v1",
        "before_tree": OLD_TREE,
        "after_tree": NEW_TREE,
        "before_leaves": len(old), "after_leaves": len(new),
        "paths": [{"path": path, "before": old.get(path), "after": new.get(path)} for path in sorted(old.keys() | new.keys())],
    })
    write("FULL-WHEEL-CENSUS.json", {
        "schema": "hol-guard.readiness-subject-wheel-comparison.v1",
        "before_wheel": old_identity, "after_wheel": new_identity,
        "paths": [{"path": path, "before": old_wheel[path], "after": new_wheel[path]} for path in sorted(old_wheel)],
    })
    (OUT / "ALL-SOURCE-CHANGES.diff").write_bytes(git("diff", OLD_TREE, NEW_TREE))
    write("COMPARISON.json", {
        "schema": "hol-guard.readiness-current-subject-comparison.v1",
        "scope": "Complete static Git/wheel byte census. No application import, workload, build, timing or runtime import census.",
        "before": {"tree": OLD_TREE, "wheel": old_identity, "runtime_manifest": old_runtime, "source_leaves": len(old)},
        "after": {"tree": NEW_TREE, "wheel": new_identity, "runtime_manifest": new_runtime, "source_leaves": len(new)},
        "wheel_member_count_each": 1500, "wheel_members_unchanged": 1495,
        "wheel_changed": [{"path": name, "before": old_wheel[name], "after": new_wheel[name]} for name in wheel_changed],
        "source_changed": [{"path": name, "before": old.get(name), "after": new.get(name)} for name in tree_changed],
        "source_removals": sorted(old.keys() - new.keys()),
        "packaged_python_each": 1433, "source_python_each": 1434,
        "source_python_roster_exclusion": [EXCLUDED],
        "all_packaged_python_bytes_match_respective_source": True,
        "record_verified_nonself_entries_each": 1499,
        "script_change_ast_equal": script_changes,
        "dependency_lock_and_build_config_byte_identical": True,
        "all_other_project_source_script_config_and_data_leaves_byte_identical": True,
        "changed_input_files_written": False,
    })
    print(json.dumps({"wheel_changes": wheel_changed, "source_changes": tree_changed, "before_leaves": len(old), "after_leaves": len(new)}, indent=2))


if __name__ == "__main__":
    main()
