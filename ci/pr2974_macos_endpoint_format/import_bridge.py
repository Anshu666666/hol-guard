"""Expose import-order changes and prove every non-import AST/token/comment remains exact."""

from __future__ import annotations

import ast
import copy
import io
import json
import tokenize
from pathlib import Path
from typing import Any

from format_bridge import digest, dumped, literal_values, prove, syntax


def import_record(node: ast.Import | ast.ImportFrom) -> list[dict[str, Any]]:
    result = []
    for alias in node.names:
        if isinstance(node, ast.Import):
            bound = alias.asname or alias.name.split(".")[0]
            row = {"kind": "import", "module": None, "level": 0, "name": alias.name, "asname": alias.asname}
        else:
            assert alias.name != "*", "Wildcard import sorting is not admitted"
            bound = alias.asname or alias.name
            row = {"kind": "from", "module": node.module, "level": node.level, "name": alias.name, "asname": alias.asname}
        result.append(row | {"binding": bound})
    return result


def masked(raw: bytes, relative: str) -> tuple[bytes, list[dict[str, Any]], str]:
    tree = syntax(raw, relative)
    original = copy.deepcopy(tree)
    groups: list[dict[str, Any]] = []
    replacements = []
    lines = raw.splitlines(keepends=True)
    comments = [token for token in tokenize.tokenize(io.BytesIO(raw).readline) if token.type == tokenize.COMMENT]

    def sortable(node: ast.AST) -> bool:
        return isinstance(node, (ast.Import, ast.ImportFrom)) and not (
            isinstance(node, ast.ImportFrom) and node.module == "__future__"
        )

    def visit(node: ast.AST) -> None:
        for field, value in ast.iter_fields(node):
            if isinstance(value, list) and value and all(isinstance(item, ast.stmt) for item in value):
                result = []
                index = 0
                while index < len(value):
                    item = value[index]
                    if not sortable(item):
                        visit(item)
                        result.append(item)
                        index += 1
                        continue
                    group = []
                    while index < len(value) and sortable(value[index]):
                        group.append(value[index])
                        index += 1
                    first, last = group[0], group[-1]
                    assert first.end_lineno is not None and last.end_lineno is not None
                    assert last.end_col_offset is not None
                    start, stop = first.lineno - 1, last.end_lineno
                    assert not lines[start][:first.col_offset].strip(), "Import begins inside another statement"
                    assert not lines[stop - 1][last.end_col_offset:].strip(), "Import ends beside another statement"
                    assert all(item.col_offset == first.col_offset for item in group)
                    assert not any(first.lineno <= token.start[0] <= last.end_lineno for token in comments), (
                        "Import-group comments require an explicit separately reviewed source edit", relative
                    )
                    records = [record for item in group for record in import_record(item)]
                    bindings = [record["binding"] for record in records]
                    assert len(bindings) == len(set(bindings)), ("Colliding import bindings", relative, bindings)
                    groups.append({
                        "group": len(groups), "start_line": first.lineno, "end_line": last.end_lineno,
                        "column": first.col_offset, "ordered_imports": records,
                    })
                    replacements.append((start, stop, b" " * first.col_offset + b"pass\n"))
                    result.append(ast.Pass())
                setattr(node, field, result)
            elif isinstance(value, ast.AST):
                visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        visit(item)

    visit(tree)
    for start, stop, replacement in sorted(replacements, reverse=True):
        lines[start:stop] = [replacement]
    result = b"".join(lines)
    assert dumped(syntax(result, relative)) == dumped(tree), "Masked source does not reconstruct the normalized AST"
    assert literal_values(original) == literal_values(tree), "Imports unexpectedly carried literal values"
    return result, groups, dumped(original)


def compare_imports(before: bytes, sorted_source: bytes, relative: str, evidence_root: Path) -> dict[str, Any]:
    target = evidence_root / (relative + ".json")
    target.parent.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {
        "path": relative, "before_sha256": digest(before), "import_sorted_sha256": digest(sorted_source),
        "passed": False, "imports_or_test_bodies_executed": False,
        "import_order_side_effect_equivalence_claimed": False,
    }
    try:
        old_mask, old_groups, old_ast = masked(before, relative)
        new_mask, new_groups, new_ast = masked(sorted_source, relative)
        evidence["groups"] = {"before": old_groups, "after": new_groups}
        evidence["raw_ast_sha256"] = {"before": digest(old_ast.encode()), "after": digest(new_ast.encode())}
        assert len(old_groups) == len(new_groups)
        comparisons = []
        for old, new in zip(old_groups, new_groups, strict=True):
            key = lambda row: json.dumps(row, sort_keys=True)
            equal = sorted(map(key, old["ordered_imports"])) == sorted(map(key, new["ordered_imports"]))
            comparisons.append({"group": old["group"], "binding_population_equal": equal,
                                "actual_order_equal": old["ordered_imports"] == new["ordered_imports"]})
            assert equal and old["column"] == new["column"], relative
        evidence["group_comparisons"] = comparisons
        evidence["non_import_bridge"] = prove(
            old_mask, new_mask, relative, evidence_root / "strict-masked",
        )
        assert evidence["non_import_bridge"]["passed"]
        evidence["passed"] = True
    except BaseException as error:
        evidence["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        target.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {key: value for key, value in evidence.items() if key != "groups"}
