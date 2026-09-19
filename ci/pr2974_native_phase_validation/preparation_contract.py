"""Check the complete prepared source and exact original-expression inverses."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def verify_preparation(config: dict, here: Path, source: Path) -> dict:
    raw = (here / "prepared-source.json").read_bytes()
    assert digest(raw) == config["preparation_sha256"]
    prepared = json.loads(raw)
    assert prepared["source_sha"] == config["source_sha"]
    assert prepared["source_tree"] == config["source_tree"]
    assert prepared["source_parent"] == config["source_parent"]
    raw_entries = subprocess.check_output(
        ["git", "ls-tree", "-rz", "--full-tree", config["source_parent"]],
        cwd=source, timeout=60, stderr=subprocess.PIPE,
    )
    parent = {}
    for entry in raw_entries.split(b"\0"):
        if not entry:
            continue
        prefix, path = entry.split(b"\t", 1)
        mode, kind, blob = prefix.decode().split()
        parent[path.decode()] = {"mode": mode, "kind": kind, "blob": blob}
    closure = prepared["parent_rust_and_native_slo_inputs"]
    actual_paths = {path for path in parent if path.startswith("rust/") or path.startswith("scripts/native_slo")}
    assert len(closure) == 281 and {row["path"] for row in closure} == actual_paths
    for row in closure:
        assert parent[row["path"]] == {"mode": row["mode"], "kind": "blob", "blob": row["blob"]}
    report = {
        "source_sha": config["source_sha"], "source_tree": config["source_tree"],
        "exact_parent_input_closure": 281, "files": {}, "original_inverses": {},
        "python_syntax_only": True, "python_parser_version": sys.version,
        "rust_compilation_in_this_proof": False,
        "qualification_complete": False,
    }
    for path, expected in prepared["source_files"].items():
        current = (source / path).read_bytes()
        text = current.decode("utf-8")
        assert len(current) == expected["bytes"] and digest(current) == expected["sha256"], path
        assert git_blob(current) == expected["git_blob"], path
        lines = len(text.splitlines())
        assert lines == expected["physical_lines"] and lines <= 500, (path, lines)
        row = {"sha256": digest(current), "git_blob": git_blob(current),
               "bytes": len(current), "physical_lines": lines, "within_500": True}
        if path.endswith(".py"):
            module = ast.parse(text, filename=path, type_comments=True)
            row["python_ast_parsed"] = True
            row["function_definitions"] = sum(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(module)
            )
        report["files"][path] = row
    assert len(report["files"]) == 22
    for path, original in prepared["originals"].items():
        base = subprocess.check_output(
            ["git", "cat-file", "blob", config["source_parent"] + ":" + path],
            cwd=source, timeout=20, stderr=subprocess.PIPE,
        )
        assert base == original["content"].encode("utf-8")
        assert git_blob(base) == original["blob"] and digest(base) == original["sha256"]
        edits = [row for row in prepared["whole_file_inverse_edits"] if row["path"] == path]
        forward = base.decode("utf-8")
        for row in edits:
            assert forward.count(row["before"]) == 1, path
            forward = forward.replace(row["before"], row["after"], 1)
        current = (source / path).read_text(encoding="utf-8")
        assert forward == current, path
        reverse = current
        for row in reversed(edits):
            assert reverse.count(row["after"]) == 1, path
            reverse = reverse.replace(row["after"], row["before"], 1)
        assert reverse.encode("utf-8") == base
        report["original_inverses"][path] = {
            "original_blob": original["blob"], "edits": len(edits),
            "complete_forward_and_inverse_equal": True,
        }
    assert sum(row["edits"] for row in report["original_inverses"].values()) == 13
    report["passed"] = True
    return report
