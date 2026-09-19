"""Bind exact reviewed repairs to the complete historical formatted source tree."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

CANDIDATE = "1578e609636cf0460b23dfbe083759097a635be0"
CANDIDATE_TREE = "4a7ea105c53d0eb68ed8a037e3e38288b32ff407"
PARENT = "44353b20262f1ca56b56204f4c764b047710454f"
HISTORICAL = "e655b80b2d81610a925d08051c061f4c23eb9f0b"
HISTORICAL_TREE = "79341eeb7fdb9684685beffbdcf6852d33fd54b6"
CONTRACT_SHA256 = "9a17be0af6a7fe8d74fdfc03e04cf5a8bf4fcdfdaf1d50e5f48b315fc8e3fad3"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE, timeout=60)


def tree_hash(files: dict[str, dict]) -> str:
    root = {}
    for relative, record in files.items():
        parts = relative.split("/")
        assert all(part and part not in {".", ".."} for part in parts), relative
        directory = root
        for part in parts[:-1]:
            directory = directory.setdefault(part, {})
            assert isinstance(directory, dict), relative
        assert parts[-1] not in directory, relative
        directory[parts[-1]] = (record["mode"], record["git_blob"])

    def visit(directory):
        result = bytearray()
        for name in sorted(directory, key=lambda key: (
            key + ("/" if isinstance(directory[key], dict) else "")
        ).encode("utf-8")):
            value = directory[name]
            mode, identity = ("40000", visit(value)) if isinstance(value, dict) else value
            result.extend(mode.encode() + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(identity))
        return hashlib.sha1(b"tree " + str(len(result)).encode() + b"\0" + result).hexdigest()

    return visit(root)


def capture_source(root: Path) -> dict[str, dict]:
    files = {}
    for entry in git(root, "ls-tree", "-rz", "--full-tree", CANDIDATE).split(b"\0"):
        if not entry:
            continue
        prefix, raw_path = entry.split(b"\t", 1)
        mode, kind, identity = prefix.decode().split()
        relative = raw_path.decode("utf-8")
        assert relative not in files and kind == "blob" and mode in {"100644", "100755"}, relative
        path = root / relative
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), relative
        raw = path.read_bytes()
        assert blob(raw) == identity and bool(info.st_mode & 0o111) == (mode == "100755"), relative
        files[relative] = {"mode": mode, "git_blob": identity, "sha256": digest(raw), "bytes": len(raw)}
    return files


def verify_source(root: Path, contract_path: Path, reconstruction_path: Path,
                  files: dict[str, dict] | None = None) -> tuple[dict, dict]:
    root = root.resolve(strict=True)
    contract_raw = contract_path.read_bytes()
    assert digest(contract_raw) == CONTRACT_SHA256
    contract = json.loads(contract_raw)
    assert contract["schema"] == "pr2974-reviewed-source-repair-bridge-v1"
    assert contract["candidate_commit"] == CANDIDATE and contract["candidate_tree"] == CANDIDATE_TREE
    assert contract["candidate_parent"] == PARENT and contract["candidate_files"] == 4575
    assert contract["historical_formatted_commit"] == HISTORICAL
    assert contract["historical_formatted_tree"] == HISTORICAL_TREE
    assert contract["historical_formatted_files"] == 4574 and contract["qualification_complete"] is False
    assert git(root, "rev-parse", "HEAD").decode().strip() == CANDIDATE
    header = git(root, "cat-file", "-p", CANDIDATE).split(b"\n\n", 1)[0].decode().splitlines()
    assert [line[5:] for line in header if line.startswith("tree ")] == [CANDIDATE_TREE]
    assert [line[7:] for line in header if line.startswith("parent ")] == [PARENT]
    assert not git(root, "status", "--porcelain", "--untracked-files=no").strip()
    current = capture_source(root) if files is None else files
    assert len(current) == 4575 and tree_hash(current) == CANDIDATE_TREE
    reconstruction_raw = reconstruction_path.read_bytes()
    assert digest(reconstruction_raw) == contract["original_formatter_receipt_sha256"]
    reconstruction = json.loads(reconstruction_raw)
    assert reconstruction["source_commit"] == "ad40ceec7c9eb3ee50cffff827db8f54c7522fb1"
    assert reconstruction["independently_verified_post_format_tree"] == HISTORICAL_TREE
    assert reconstruction["full_tracked_files"] == 4574 and reconstruction["complete_payload_file_count"] == 33
    assert reconstruction["actual_driver_outcome"]["passed"] is True
    assert reconstruction["actual_driver_outcome"]["source_unchanged"] is True
    assert reconstruction["actual_run_conclusion"] == "success"
    bridges = reconstruction["actual_32_ast_literal_token_comment_bridges"]
    assert len(bridges) == len({row["path"] for row in bridges}) == 32
    bridge_by_path = {row["path"]: row for row in bridges}
    restored = {path: dict(record) for path, record in current.items()}
    assert len(contract["changes"]) == 6 and len(contract["added_files"]) == 1
    assert len({row["path"] for row in contract["changes"]}) == 6
    inverse_rows = []
    for change in contract["changes"]:
        path = change["path"]
        raw = (root / path).read_bytes()
        assert current[path] == change["after"], path
        assert digest(raw) == change["after"]["sha256"] and blob(raw) == change["after"]["git_blob"], path
        text = raw.decode("utf-8")
        for operation in change["inverse_operations"]:
            old, new = operation["current"], operation["reconstructed"]
            assert old and text.count(old) == operation["expected_occurrences"], path
            text = text.replace(old, new)
        original = text.encode("utf-8")
        expected = change["before"]
        actual = {"mode": current[path]["mode"], "git_blob": blob(original),
                  "sha256": digest(original), "bytes": len(original)}
        assert actual == expected, path
        assert expected == {key: reconstruction["output_files"][path][key] for key in actual}, path
        old_ast = ast.dump(ast.parse(text, filename=path, type_comments=True), include_attributes=False)
        new_ast = ast.dump(ast.parse(raw.decode("utf-8"), filename=path, type_comments=True), include_attributes=False)
        assert digest(old_ast.encode()) == bridge_by_path[path]["full_ast_sha256"]["after"], path
        if change["kind"] == "comment_only":
            assert old_ast == new_ast, path
        restored[path] = actual
        inverse_rows.append({
            "path": path, "current": current[path], "reconstructed": actual,
            "reviewed_change_kind": change["kind"],
            "whole_file_inverse_exact": True, "historical_formatter_ast_hash_matches": True,
            "current_full_ast_sha256": digest(new_ast.encode()),
            "reconstructed_full_ast_sha256": digest(old_ast.encode()),
            "full_ast_equal": old_ast == new_ast,
        })
    added_rows = []
    for addition in contract["added_files"]:
        path = addition["path"]
        assert path not in {row["path"] for row in contract["changes"]}
        raw = (root / path).read_bytes()
        assert current[path] == addition["record"], path
        assert digest(raw) == addition["record"]["sha256"] and blob(raw) == addition["record"]["git_blob"]
        tree = ast.parse(raw.decode("utf-8"), filename=path, type_comments=True)
        assert len(tree.body) == 2 and not tree.type_ignores
        assert isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant)
        assert type(tree.body[0].value.value) is str
        assignment = tree.body[1]
        assert isinstance(assignment, ast.Assign) and len(assignment.targets) == 1
        assert isinstance(assignment.targets[0], ast.Name) and assignment.targets[0].id == addition["binding"]
        assert isinstance(assignment.value, ast.Constant) and type(assignment.value.value) is str
        value = assignment.value.value.encode("utf-8")
        assert len(value) == addition["value_bytes"] == 74 and digest(value) == addition["value_sha256"]
        del restored[path]
        added_rows.append({"path": path, "record": current[path], "value_bytes": len(value),
                           "value_sha256": digest(value), "single_immutable_test_value": True})
    assert len(restored) == 4574 and tree_hash(restored) == HISTORICAL_TREE
    assert len(reconstruction["output_files"]) == 33
    for path, expected in reconstruction["output_files"].items():
        assert restored[path] == {key: expected[key] for key in ("mode", "git_blob", "sha256", "bytes")}, path
    for row in bridges:
        assert all(row[key] is True for key in (
            "passed", "full_ast_equal_including_type_comments_and_type_ignore_line_fields",
            "canonical_tokens_equal", "comments_and_statement_token_anchors_equal", "within_500_physical_lines",
        )), row["path"]
        assert restored[row["path"]]["sha256"] == row["after_sha256"]
    report = {
        "schema": "pr2974-executed-source-repair-inverse-v1", "passed": True,
        "candidate_commit": CANDIDATE, "candidate_tree": CANDIDATE_TREE, "candidate_files": len(current),
        "candidate_parent": PARENT, "historical_formatted_commit": HISTORICAL,
        "reconstructed_historical_tree": HISTORICAL_TREE, "reconstructed_historical_files": len(restored),
        "repair_contract_sha256": digest(contract_raw),
        "bridge_script_sha256": digest(Path(__file__).read_bytes()),
        "historical_formatter_receipt_sha256": digest(reconstruction_raw),
        "exact_inverse_rows": inverse_rows, "added_support_rows": added_rows,
        "historical_32_formatter_bridges_bound_to_reconstructed_bytes": True,
        "current_ruff_or_format_or_test_pass_inferred": False,
        "original_failed_run": contract["historical_failure"],
        "product_imports_or_tests_executed_by_bridge": False, "qualification_complete": False,
    }
    return restored, report
