"""Check StoreBase's exact source partition without importing product modules."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import io
import json
import symtable
import tokenize
from pathlib import Path

ORIGINAL_SHA256 = "b9e65beb32cb567bbd8ff11582648e2c4d6dc63770f99cb28f61751359ff088f"
FACADE = "src/codex_plugin_scanner/guard/store_base.py"
PACKAGE = "src/codex_plugin_scanner/guard/"
LAYOUT_TOKENS = {
    tokenize.ENCODING, tokenize.ENDMARKER, tokenize.NEWLINE, tokenize.NL,
    tokenize.INDENT, tokenize.DEDENT,
}


def dump(node):
    return ast.dump(node, include_attributes=False)


def names_bound(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Import):
        return [alias.asname or alias.name.split(".")[0] for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        assert all(alias.name != "*" for alias in node.names)
        return [alias.asname or alias.name for alias in node.names]
    targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
    return [item.id for target in targets for item in ast.walk(target) if isinstance(item, ast.Name)]


def annotations_in(node):
    for item in ast.walk(node):
        if isinstance(item, ast.arg) and item.annotation is not None:
            yield item.annotation
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.returns is not None:
            yield item.returns
        elif isinstance(item, ast.AnnAssign):
            yield item.annotation


def named_definitions(node):
    return [item for item in ast.walk(node) if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]


class Forward(ast.NodeTransformer):
    def __init__(self, table, bound):
        self.table, self.bound = table, bound
        self.globals = []
        self.definitions = []

    def scope(self, node, name=None):
        matches = [
            item for item in self.table.get_children()
            if item.get_name() == (node.name if name is None else name) and item.get_lineno() == node.lineno
        ]
        assert len(matches) == 1, (getattr(node, "name", name), node.lineno, len(matches))
        return matches[0]

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load) and node.id in self.bound and self.table.lookup(node.id).is_global():
            self.globals.append({"line": node.lineno, "column": node.col_offset, "name": node.id})
            return ast.copy_location(ast.Attribute(value=ast.Name(id="_base", ctx=ast.Load()),
                                                   attr=node.id, ctx=ast.Load()), node)
        return node

    def visit_AnnAssign(self, node):
        node.target = self.visit(node.target)
        if node.value is not None:
            node.value = self.visit(node.value)
        return node

    def visit_FunctionDef(self, node):
        assert all(isinstance(value, ast.Constant) for value in node.args.defaults)
        assert all(value is None or isinstance(value, ast.Constant) for value in node.args.kw_defaults)
        old = self.table
        self.table = self.scope(node)
        node.body = [self.visit(item) for item in node.body]
        self.table = old
        self.definitions.append({"kind": type(node).__name__, "line": node.lineno, "name": node.name})
        node.decorator_list.append(ast.Name(id="_preserve_module", ctx=ast.Load()))
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        assert not node.keywords and not node.decorator_list
        assert not node.bases or (
            node.name == "MigratingFallbackSecretStore" and len(node.bases) == 1
            and isinstance(node.bases[0], ast.Name) and node.bases[0].id == "FallbackSecretStore"
        )
        for item in node.body:
            if isinstance(item, ast.Assign):
                assert isinstance(item.value, ast.Constant)
            elif isinstance(item, ast.AnnAssign):
                assert item.value is None or isinstance(item.value, ast.Constant)
        old = self.table
        self.table = self.scope(node)
        node.body = [self.visit(item) for item in node.body]
        self.table = old
        self.definitions.append({"kind": "ClassDef", "line": node.lineno, "name": node.name})
        node.decorator_list.append(ast.Name(id="_preserve_module", ctx=ast.Load()))
        return node

    def comprehension(self, node, name):
        first = node.generators[0]
        first.iter = self.visit(first.iter)
        old = self.table
        children = [item for item in old.get_children()
                    if item.get_name() == name and item.get_lineno() == node.lineno]
        assert len(children) <= 1
        if children:
            self.table = children[0]
        first.target = self.visit(first.target)
        first.ifs = [self.visit(item) for item in first.ifs]
        for generator in node.generators[1:]:
            generator.iter = self.visit(generator.iter)
            generator.target = self.visit(generator.target)
            generator.ifs = [self.visit(item) for item in generator.ifs]
        if isinstance(node, ast.DictComp):
            node.key, node.value = self.visit(node.key), self.visit(node.value)
        else:
            node.elt = self.visit(node.elt)
        self.table = old
        return node

    def visit_ListComp(self, node):
        return self.comprehension(node, "listcomp")

    def visit_SetComp(self, node):
        return self.comprehension(node, "setcomp")

    def visit_DictComp(self, node):
        return self.comprehension(node, "dictcomp")

    def visit_GeneratorExp(self, node):
        return self.comprehension(node, "genexpr")


def significant(text):
    return [(token.type, token.string) for token in tokenize.generate_tokens(io.StringIO(text).readline)
            if token.type not in LAYOUT_TOKENS]


def source_fragment(source, node, *, inverse=False):
    lines = source.splitlines(keepends=True)
    starts, total = [], 0
    for line in lines:
        starts.append(total)
        total += len(line)

    def position(line, column=0):
        return starts[line - 1] + len(lines[line - 1].encode("utf-8")[:column].decode("utf-8"))

    begin_line = min([node.lineno, *(item.lineno for item in node.decorator_list)])
    begin, end = position(begin_line), position(node.end_lineno, node.end_col_offset)
    text = source[begin:end]
    if not inverse:
        return text
    edits = []
    for item in ast.walk(node):
        if isinstance(item, ast.Attribute) and isinstance(item.value, ast.Name) and item.value.id == "_base":
            start, stop = position(item.lineno, item.col_offset), position(item.end_lineno, item.end_col_offset)
            prefix = source[start:stop - len(item.attr)]
            assert "".join(prefix.split()) == "_base."
            edits.append((start - begin, stop - len(item.attr) - begin, ""))
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            decorator = item.decorator_list[-1]
            assert isinstance(decorator, ast.Name) and decorator.id == "_preserve_module"
            start = position(decorator.lineno)
            stop = start + len(lines[decorator.lineno - 1])
            assert lines[decorator.lineno - 1].strip() == "@_preserve_module"
            edits.append((start - begin, stop - begin, ""))
    for start, stop, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[stop:]
    return text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.baseline.read_text(encoding="utf-8")
    assert hashlib.sha256(source.encode()).hexdigest() == ORIGINAL_SHA256
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    assert manifest["original_sha256"] == ORIGINAL_SHA256
    for relative, record in manifest["files"].items():
        actual = (args.candidate_root / relative).read_bytes()
        assert hashlib.sha256(actual).hexdigest() == record["sha256"], relative
        assert len(actual.decode("utf-8").splitlines()) <= 500, relative
    baseline = ast.parse(source, type_comments=True)
    table = symtable.symtable(source, str(args.baseline), "exec")
    ordered = list(dict.fromkeys(name for node in baseline.body for name in names_bound(node)
                                if not (name.startswith("__") and name.endswith("__"))))
    assert "annotations" in ordered
    bound = set(ordered)
    originals = {node.name: node for node in baseline.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    owner = {name: group["module"] for group in manifest["groups"] for name in group["members"]}
    assert len(owner) == sum(len(group["members"]) for group in manifest["groups"]) == 57
    assert set(originals) - set(owner) == {
        "_RecoveredOAuthLocalCredentialInputs", "PolicyDecisionLookupResult", "SecretStore",
    }
    records, forward_globals, forward_definitions = [], [], []
    available = set()
    group_available = {}
    for node in baseline.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in owner:
            group_available.setdefault(owner[node.name], set(available))
        available.update(names_bound(node))
    for group in manifest["groups"]:
        relative = PACKAGE + group["module"] + ".py"
        candidate_source = (args.candidate_root / relative).read_text(encoding="utf-8")
        assert hashlib.sha256(candidate_source.encode()).hexdigest() == manifest["files"][relative]["sha256"]
        assert len(candidate_source.splitlines()) <= 500
        candidate = ast.parse(candidate_source, type_comments=True)
        original_nodes = [originals[name] for name in group["members"]]
        assert [item.lineno for item in original_nodes] == sorted(item.lineno for item in original_nodes)
        aliases = sorted({item.id for node in original_nodes for annotation in annotations_in(node)
                          for item in ast.walk(annotation) if isinstance(item, ast.Name) and item.id in bound})
        assert aliases == group["annotation_aliases"]
        assert set(aliases) <= group_available[group["module"]]
        rewriter = Forward(table, bound)
        transformed = [rewriter.visit(copy.deepcopy(node)) for node in original_nodes]
        header = (
            '"""Implementation definitions reexported by the StoreBase facade."""\n'
            'from __future__ import annotations\n'
            'from .store_base_definition import preserve_store_base_module as _preserve_module\n'
        )
        footer = (
            ("from . import store_base as _base\n" if rewriter.globals else "")
            + ("from .store_base import " + ", ".join(aliases) + "\n" if aliases else "")
        )
        expected = ast.parse(header, type_comments=True)
        expected.body.extend(transformed)
        expected.body.extend(ast.parse(footer, type_comments=True).body)
        assert dump(candidate) == dump(expected), relative
        actual_nodes = [node for node in candidate.body
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        assert len(actual_nodes) == len(original_nodes)
        for old, new in zip(original_nodes, actual_nodes, strict=True):
            assert significant(source_fragment(source, old)) == significant(
                source_fragment(candidate_source, new, inverse=True)), (relative, old.name)
        forward_globals.extend(rewriter.globals)
        forward_definitions.extend(rewriter.definitions)
        records.append({"path": relative, "definitions": len(actual_nodes),
                        "qualified_globals": len(rewriter.globals), "metadata_definitions": len(rewriter.definitions)})
    expected_facade = copy.deepcopy(baseline)
    expected_facade.body = [
        ast.ImportFrom(module=owner[node.name], names=[ast.alias(name=node.name)], level=1)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in owner else node
        for node in expected_facade.body
    ]
    actual_facade_source = (args.candidate_root / FACADE).read_text(encoding="utf-8")
    assert len(actual_facade_source.splitlines()) <= 500
    actual_facade = ast.parse(actual_facade_source, type_comments=True)
    assert dump(actual_facade) == dump(expected_facade)
    actual_ordered = list(dict.fromkeys(name for node in actual_facade.body for name in names_bound(node)
                                       if not (name.startswith("__") and name.endswith("__"))))
    assert actual_ordered == ordered
    metadata_path = PACKAGE + "store_base_definition.py"
    metadata_source = (args.candidate_root / metadata_path).read_text(encoding="utf-8")
    assert hashlib.sha256(metadata_source.encode()).hexdigest() == manifest["files"][metadata_path]["sha256"]
    metadata = ast.parse(metadata_source, type_comments=True)
    function = next(node for node in metadata.body if isinstance(node, ast.FunctionDef))
    assert function.name == "preserve_store_base_module"
    assert len(function.body) == 3
    assert isinstance(function.body[0], ast.Expr)
    assert isinstance(function.body[0].value, ast.Constant)
    assert function.body[0].value.value == "Keep the original object and its facade-based import and pickle identity."
    body = function.body[1:]
    assert dump(ast.Module(body=body, type_ignores=[])) == dump(ast.parse(
        'definition.__module__ = "codex_plugin_scanner.guard.store_base"\nreturn definition\n'
    ))
    assert len(forward_globals) == 201
    assert len(forward_definitions) == 117
    result = {"schema": "store-base-source-partition-proof.v1", "source_only": True,
              "product_imports": False, "groups": records, "ordered_exports": ordered,
              "global_loads": forward_globals, "metadata_definitions": forward_definitions,
              "function_and_class_asts_match_precise_forward_transform": True,
              "inverse_significant_tokens_including_strings_comments_exact": True,
              "facade_statement_order_and_exports_exact": True,
              "helper_definitions_precede_live_facade_and_annotation_imports": True,
              "runtime_validation": "not performed by this source checker"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
