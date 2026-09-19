"""Prove the actual facade exports reconstruct the entire original ordered module."""

from __future__ import annotations

import ast
import collections
import copy
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASELINE, CONFIG, REPORT, SOURCE, git, sha256, write_json
import source_globals as lexical


def dump(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=True, include_attributes=False)


class Unqualify(ast.NodeTransformer):
    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name) and node.value.id == "_api":
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
            ast.Attribute(value=ast.Name(id="_api", ctx=ast.Load()), attr=node.id, ctx=ast.Load()), node)


def main() -> None:
    relative = CONFIG["facade_path"]
    original_bytes = (BASELINE / relative).read_bytes()
    assert sha256(original_bytes) == CONFIG["original_facade_sha256"]
    original = lexical.prepare(original_bytes, relative)
    candidate = ast.parse((SOURCE / relative).read_text(), filename=relative)
    owners = {}
    imported = {}
    facade_import_nodes = []
    for node in candidate.body:
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module is None:
            for name in node.names:
                if not name.name.startswith("local_supply_chain_"):
                    continue
                assert len(node.names) == 1 and name.asname and name.asname not in owners
                path = str(Path(relative).with_name(name.name + ".py"))
                assert path in CONFIG["production_paths"]
                owners[name.asname] = path
                facade_import_nodes.append(node)
    assert len(owners) == 17
    helper_functions = {}
    for alias, path in owners.items():
        data = (SOURCE / path).read_bytes()
        module = ast.parse(data.decode(), filename=path)
        assert isinstance(module.body[0], ast.Expr) and isinstance(module.body[0].value, ast.Constant)
        assert isinstance(module.body[0].value.value, str)
        assert dump(module.body[1]) == dump(ast.parse("from __future__ import annotations").body[0])
        assert dump(module.body[-1]) == dump(ast.parse("from . import local_supply_chain as _api").body[0])
        functions = module.body[2:-1]
        assert functions and all(isinstance(node, ast.FunctionDef) and not node.decorator_list for node in functions)
        assert len({node.name for node in functions}) == len(functions)
        helper_functions[alias] = {node.name: node for node in functions}
        assert len(data.splitlines()) <= 500 and sum(bool(line.strip()) for line in data.splitlines()) <= 500
    baseline_functions = {node.name: node for node in original.body if isinstance(node, ast.FunctionDef)}
    assert len(baseline_functions) == 148
    reconstructed = []
    exports = []
    seen = set()
    lexical_loads = []
    forward_records = {}
    for node in candidate.body:
        if node in facade_import_nodes:
            continue
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Attribute)
                and isinstance(node.value.value, ast.Name) and node.value.value.id in owners):
            name, alias = node.targets[0].id, node.value.value.id
            assert node.value.attr == name and name not in seen
            helper = helper_functions[alias][name]
            original_function = baseline_functions[name]
            assert not original_function.decorator_list
            inverse = Unqualify().visit(copy.deepcopy(helper))
            assert dump(inverse) == dump(original_function), name
            visitor = lexical.Globals()
            visitor.visit(original_function)
            transform = Qualify(visitor.positions)
            forward = transform.visit(copy.deepcopy(original_function))
            assert transform.seen == visitor.positions
            assert dump(forward) == dump(helper), "Forward lexical binding mismatch: " + name
            assert sum(isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name)
                       and value.value.id == "_api" for value in ast.walk(helper)) == len(visitor.positions)
            lexical_loads.extend({"function": name, "name": value, "source_offset": offset}
                                 for offset, value in sorted(visitor.positions.items()))
            forward_records[name] = {"owner_path": owners[alias], "global_loads": len(visitor.positions),
                                     "original_ast_sha256": sha256(dump(original_function).encode()),
                                     "helper_ast_sha256": sha256(dump(helper).encode())}
            reconstructed.append(inverse)
            exports.append({"name": name, "owner_path": owners[alias]})
            seen.add(name)
        else:
            assert not any(isinstance(value, ast.Name) and value.id in owners for value in ast.walk(node))
            reconstructed.append(copy.deepcopy(node))
    assert seen == {name for functions in helper_functions.values() for name in functions}
    assert len(seen) == 143 and len(lexical_loads) == 832
    assert set(baseline_functions) - seen == set(CONFIG["retained_functions"])
    rebuilt = ast.Module(body=reconstructed, type_ignores=[])
    assert dump(rebuilt) == dump(original), "Entire original ordered module differs"
    assert sum(isinstance(node, ast.ClassDef) for node in original.body) == 2
    facade_data = (SOURCE / relative).read_bytes()
    assert len(facade_data.splitlines()) <= 500
    all_paths = [value.decode() for value in git("ls-files", "-z", cwd=BASELINE).split(b"\0") if value]
    python_paths = [path for path in all_paths if path.endswith(".py")]
    assert len(python_paths) == CONFIG["baseline_python_files"] == 3110
    consumers = {}
    selected = []
    for path in python_paths:
        data = (BASELINE / path).read_bytes()
        if b"local_supply_chain" not in data:
            continue
        assert (SOURCE / path).read_bytes() == data or path == relative, path
        consumers[path] = {"sha256": sha256(data), "bytes": len(data)}
        if path.startswith("tests/test_") and path.endswith(".py"):
            selected.append(path)
    selected.sort()
    assert set(CONFIG["existing_test_seeds"]) <= set(selected)
    assert 24 <= len(selected) <= 128
    for path in selected:
        assert (SOURCE / path).read_bytes() == (BASELINE / path).read_bytes()
    write_json(REPORT / "existing-test-selection.json", {
        "files": selected, "rule": "Every tracked baseline tests/test_*.py containing local_supply_chain",
        "baseline_python_files_scanned": len(python_paths), "source_consumers": consumers,
        "seed_files_independently_read": sorted(CONFIG["existing_test_seeds"]),
        "selection_is_fresh": True, "collection_or_runtime_claim": False})
    write_json(REPORT / "source-contract-asts.json", {
        "original_ordered_module": dump(original), "reconstructed_ordered_module": dump(rebuilt),
        "functions": forward_records, "live_facade_loads": lexical_loads})
    write_json(REPORT / "source-contract.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "original_facade_sha256": sha256(original_bytes), "original_top_level_functions": 148,
        "moved_functions": 143, "retained_functions": sorted(set(baseline_functions) - seen),
        "retained_classes": 2, "actual_owner_modules": 17, "live_facade_loads": len(lexical_loads),
        "actual_exports": exports, "whole_ordered_ast_equal": True, "forward_lexical_bindings_equal": True,
        "source_only": True, "qualification_complete": False})


if __name__ == "__main__":
    main()
