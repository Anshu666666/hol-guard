"""Prove the actual package facade reconstructs every original ordered declaration."""

from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASELINE, CONFIG, HERE, REPORT, SOURCE, sha256, write_json
from preparation_contract import verify_preparation
import source_globals as lexical


def dump(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=True, include_attributes=False)


class Unqualify(ast.NodeTransformer):
    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name) and node.value.id == "_eval":
            assert isinstance(node.ctx, ast.Load), dump(node)
            return ast.copy_location(ast.Name(id=node.attr, ctx=ast.Load()), node)
        return self.generic_visit(node)


class Qualify(ast.NodeTransformer):
    def __init__(self, positions):
        self.positions = positions
        self.seen = {}

    def visit_Name(self, node):
        offset = lexical.OFFSETS[node.lineno - 1] + node.col_offset
        if offset not in self.positions:
            return node
        assert isinstance(node.ctx, ast.Load) and self.positions[offset] == node.id
        self.seen[offset] = node.id
        return ast.copy_location(
            ast.Attribute(value=ast.Name(id="_eval", ctx=ast.Load()), attr=node.id, ctx=ast.Load()), node)


def main() -> None:
    assert sys.flags.isolated == 1 and sys.dont_write_bytecode is True
    assert isinstance(CONFIG["source_sha"], str) and len(CONFIG["source_sha"]) == 40
    assert isinstance(CONFIG["source_tree"], str) and len(CONFIG["source_tree"]) == 40
    assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                   for name in sys.modules), "Source proof must precede product imports"
    preparation = verify_preparation(CONFIG, HERE, SOURCE)
    relative = CONFIG["facade_path"]
    original_bytes = (BASELINE / relative).read_bytes()
    assert sha256(original_bytes) == CONFIG["original_facade_sha256"]
    original = lexical.prepare(original_bytes, relative)
    assert not original.type_ignores
    candidate = ast.parse((SOURCE / relative).read_text(), filename=relative, type_comments=True)
    originals = {node.name: node for node in original.body if isinstance(node, ast.FunctionDef)}
    assert len(originals) == 161
    owners = {}
    imported = []
    for node in candidate.body:
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module and node.module.startswith("package_eval_"):
            path = str(Path(relative).with_name(node.module + ".py"))
            assert path in CONFIG["production_paths"]
            owners[node.module] = path
            for alias in node.names:
                assert alias.asname in (None, alias.name) and alias.name not in {row["name"] for row in imported}
                imported.append({"name": alias.name, "owner": node.module, "node": node})
    assert len(owners) == 19 and len(imported) == 160
    helpers = {}
    for owner, path in owners.items():
        raw = (SOURCE / path).read_bytes()
        module = ast.parse(raw.decode("utf-8"), filename=path, type_comments=True)
        assert not module.type_ignores
        assert isinstance(module.body[0], ast.Expr) and isinstance(module.body[0].value, ast.Constant)
        assert isinstance(module.body[0].value.value, str)
        assert dump(module.body[1]) == dump(ast.parse("from __future__ import annotations").body[0])
        assert dump(module.body[-1]) == dump(ast.parse("from . import supply_chain_package_eval as _eval").body[0])
        functions = module.body[2:-1]
        assert functions and all(isinstance(node, ast.FunctionDef) and not node.decorator_list for node in functions)
        assert len({node.name for node in functions}) == len(functions)
        for node in functions:
            for default in [*node.args.defaults, *[value for value in node.args.kw_defaults if value is not None]]:
                ast.literal_eval(default)
        helpers[owner] = {node.name: node for node in functions}
        assert len(raw.splitlines()) <= 500
    by_node = {}
    for row in imported:
        by_node.setdefault(id(row["node"]), []).append(row)
    rebuilt = []
    actual_exports = []
    lexical_loads = []
    functions = {}
    seen = set()
    for node in candidate.body:
        entries = by_node.get(id(node))
        if entries is None:
            rebuilt.append(copy.deepcopy(node))
            continue
        for entry in entries:
            name, owner = entry["name"], entry["owner"]
            assert name not in seen
            current = helpers[owner][name]
            before = originals[name]
            assert not before.decorator_list
            assert not any(isinstance(value, ast.ClassDef) for value in ast.walk(before))
            inverse = Unqualify().visit(copy.deepcopy(current))
            assert dump(inverse) == dump(before), "Original function inverse differs: " + name
            visitor = lexical.Globals()
            visitor.visit(before)
            transformer = Qualify(visitor.positions)
            forward = transformer.visit(copy.deepcopy(before))
            assert transformer.seen == visitor.positions
            assert dump(forward) == dump(current), "Live facade forward binding differs: " + name
            assert sum(isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name)
                       and value.value.id == "_eval" for value in ast.walk(current)) == len(visitor.positions)
            lexical_loads.extend({"function": name, "name": value, "source_offset": offset}
                                 for offset, value in sorted(visitor.positions.items()))
            functions[name] = {"owner_path": owners[owner], "global_loads": len(visitor.positions),
                               "original_ast_sha256": sha256(dump(before).encode()),
                               "current_ast_sha256": sha256(dump(current).encode())}
            rebuilt.append(inverse)
            actual_exports.append({
                "facade_module": "codex_plugin_scanner.guard.runtime.supply_chain_package_eval",
                "facade_attribute": name, "original_source": relative, "original_qualname": name,
                "candidate_module": "codex_plugin_scanner.guard.runtime." + owner,
                "candidate_source": owners[owner], "candidate_qualname": name,
                "static_descriptor": False, "explicit_receiver_annotation": False,
            })
            seen.add(name)
    assert seen == {name for group in helpers.values() for name in group}
    assert len(seen) == 160 and len(lexical_loads) == 923
    assert set(originals) - seen == {"_download_external_tarball"}
    restored = ast.Module(body=rebuilt, type_ignores=[])
    assert dump(restored) == dump(original), "Whole ordered original module differs"
    original_classes = [node.name for node in original.body if isinstance(node, ast.ClassDef)]
    assert original_classes == ["SupplyChainUserCopy", "PackageRequestEvaluation", "_EvaluationDraft"]
    assert len((SOURCE / relative).read_bytes().splitlines()) <= 500
    collection = json.loads((Path(__file__).with_name("collection-manifest.json")).read_bytes())
    assert sorted(actual_exports, key=lambda row: row["facade_attribute"]) == sorted(
        collection["approved_export_map"], key=lambda row: row["facade_attribute"])
    write_json(REPORT / "package-eval-source-contract-asts.json", {
        "original_ordered_module": dump(original), "restored_ordered_module": dump(restored),
        "functions": functions, "live_global_loads": lexical_loads,
    })
    write_json(REPORT / "package-eval-source-contract.json", {
        "baseline": CONFIG["baseline_sha"], "candidate": CONFIG["source_sha"], "candidate_tree": CONFIG["source_tree"],
        "original_facade_sha256": sha256(original_bytes), "moved_functions": 160, "owner_modules": 19,
        "live_global_loads": 923, "retained_function": "_download_external_tarball",
        "retained_records": original_classes, "whole_ordered_original_module_equal": True,
        "precise_forward_and_inverse_ast_equal": True, "actual_export_map": actual_exports,
        "single_contextvar_original_declaration_and_reset_bodies_preserved": True,
        "captured_download_default_preserved_in_retained_facade_function": True,
        "current_source_comment_inverse_rows": preparation["source_inverse_rows"],
        "corpus_provenance_sha256": preparation["corpus_provenance_sha256"],
        "known_corpus_performance_contract": "failed",
        "product_imports": [], "passed": True, "qualification_complete": False,
    })


if __name__ == "__main__":
    main()
