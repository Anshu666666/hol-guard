"""Inspect source text and syntax only; never import the inspected modules."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re

from common import CONFIG, REPORT, ROOT, frame, sha256, write_json


def alias_uses(tree: ast.AST, text: str, aliases: set[str]) -> list[dict[str, object]]:
    result = []
    for node in ast.walk(tree):
        targets = []
        category = None
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            category = "assignment_target"
        elif isinstance(node, ast.Call):
            callee = ast.unparse(node.func)
            if any(part in callee for part in ("setattr", "delattr", "patch")):
                targets = [*node.args, *(keyword.value for keyword in node.keywords)]
                category = "patch_or_attribute_call"
        if category is None:
            continue
        found = set()
        for target in targets:
            for value in ast.walk(target):
                name = value.id if isinstance(value, ast.Name) else value.attr if isinstance(value, ast.Attribute) else None
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    name = value.value
                if name in aliases:
                    found.add(name)
        if found:
            result.append({"category": category, "line": node.lineno, "end_line": node.end_lineno,
                           "aliases": sorted(found), "source": ast.get_source_segment(text, node)})
    return sorted(result, key=lambda row: (row["line"], row["category"]))


def inventory(before: dict[str, object]) -> bool:
    source = ROOT / "source"
    patterns = CONFIG["source_text_inventory"]
    compiled = {name: re.compile(patterns[name]) for name in ("metadata", "stores")}
    aliases = set(patterns["storeAnnotationAliases"])
    all_paths = sorted(path for path in before["files"] if path.endswith(".py"))
    scanned = []
    matched = {}
    errors = []
    for relative in all_paths:
        data = (source / relative).read_bytes()
        expected = before["files"][relative]
        assert sha256(data) == expected["sha256"], relative
        scanned.append({"path": relative, "sha256": expected["sha256"], "bytes": len(data)})
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            errors.append({"path": relative, "error": type(error).__name__})
            continue
        matches = {name: [{"line": index + 1, "text": line}
                          for index, line in enumerate(text.splitlines()) if pattern.search(line)]
                   for name, pattern in compiled.items()}
        if not any(matches.values()):
            continue
        row = {"sha256": expected["sha256"], "git_blob": expected["git_blob"], "bytes": len(data),
               "matches": matches, "complete_file_text": text, "alias_assignment_or_patch_uses": []}
        if matches["stores"]:
            try:
                row["alias_assignment_or_patch_uses"] = alias_uses(ast.parse(text), text, aliases)
            except SyntaxError as error:
                row["syntax_error"] = {"line": error.lineno, "message": error.msg}
                errors.append({"path": relative, "error": "SyntaxError"})
        matched[relative] = row
    result = {"source_sha": CONFIG["sources"]["source"]["sha"],
              "source_tree": CONFIG["sources"]["source"]["tree"], "patterns": patterns,
              "tracked_python_files": len(all_paths), "scanned_files": scanned,
              "matched_file_count": len(matched), "matched_files": matched,
              "errors": errors, "source_scan_complete": not errors and len(scanned) == len(all_paths),
              "scope": "Source text and assignment/patch syntax only; no imports or runtime alias claim",
              "qualification_complete": False}
    path = REPORT / "source-text-inventory.json"
    write_json(path, result)
    summary = {"source_sha": result["source_sha"], "tracked_python_files": len(all_paths),
               "matched_file_count": len(matched), "complete": result["source_scan_complete"],
               "bytes": path.stat().st_size, "sha256": sha256(path.read_bytes()),
               "maximum_framed_bytes": 8 * 1024 * 1024, "errors": errors}
    write_json(REPORT / "source-text-inventory-summary.json", summary)
    if path.stat().st_size > summary["maximum_framed_bytes"]:
        summary["oversized"] = True
        summary["framed_complete"] = False
        write_json(REPORT / "source-text-inventory-summary.json", summary)
        frame("lsc-source-text-inventory-refused", summary)
        return False
    frame("lsc-source-text-inventory", result, max_bytes=summary["maximum_framed_bytes"])
    return bool(result["source_scan_complete"])
