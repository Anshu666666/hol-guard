"""Bind package lexical scopes from exact original bytes, preserving nested nonlocal callbacks."""

from __future__ import annotations

import ast
import symtable

SYMBOLS = None
MODULE_NAMES = set()
ANNOTATED_NAMES = set()
OFFSETS = []


def prepare(data: bytes, filename: str):
    global SYMBOLS, MODULE_NAMES, ANNOTATED_NAMES, OFFSETS
    tree = ast.parse(data.decode("utf-8"), filename=filename, type_comments=True)
    assert not tree.type_ignores
    SYMBOLS = symtable.symtable(data.decode("utf-8"), filename, "exec")
    MODULE_NAMES = {symbol.get_name() for symbol in SYMBOLS.get_symbols()
                    if symbol.is_imported() or symbol.is_assigned()}
    ANNOTATED_NAMES = set()
    for node in ast.walk(tree):
        for annotation in (getattr(node, "annotation", None), getattr(node, "returns", None)):
            if annotation is not None:
                ANNOTATED_NAMES.update(id(value) for value in ast.walk(annotation) if isinstance(value, ast.Name))
    OFFSETS = [0]
    for line in data.splitlines(keepends=True):
        OFFSETS.append(OFFSETS[-1] + len(line))
    assert not any(isinstance(node, ast.Global) for node in ast.walk(tree))
    nonlocals = [name for node in ast.walk(tree) if isinstance(node, ast.Nonlocal) for name in node.names]
    assert sorted(nonlocals) == ["cloud_entitlement", "fail_closed_decision"]

    def refuse_prefix_shadow(table):
        assert "_eval" not in table.get_identifiers(), "Reserved facade alias is shadowed"
        for child in table.get_children():
            refuse_prefix_shadow(child)

    refuse_prefix_shadow(SYMBOLS)
    for node in ast.walk(tree):
        if isinstance(node, (ast.ListComp, ast.DictComp, ast.SetComp)):
            targets = {target.id for generator in node.generators for target in ast.walk(generator.target)
                       if isinstance(target, ast.Name)}
            assert not (targets & MODULE_NAMES), targets & MODULE_NAMES
    return tree


class Globals(ast.NodeVisitor):
    def __init__(self):
        self.table = SYMBOLS
        self.positions = {}

    def enter(self, node, name):
        matches = [
            table
            for table in self.table.get_children()
            if table.get_name() == name and table.get_lineno() == node.lineno
        ]
        assert len(matches) == 1, (name, node.lineno, matches)
        previous = self.table
        self.table = matches[0]
        return previous

    def visit_Name(self, node):
        if not isinstance(node.ctx, ast.Load) or node.id not in MODULE_NAMES:
            return
        try:
            symbol = self.table.lookup(node.id)
        except KeyError:
            assert id(node) in ANNOTATED_NAMES, (node.id, node.lineno, self.table.get_name())
            symbol = SYMBOLS.lookup(node.id)
        if self.table is SYMBOLS or symbol.is_global():
            self.positions[OFFSETS[node.lineno - 1] + node.col_offset] = node.id

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in node.args.defaults:
            self.visit(default)
        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)
        arguments = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        if node.args.vararg is not None:
            arguments.append(node.args.vararg)
        if node.args.kwarg is not None:
            arguments.append(node.args.kwarg)
        for argument in arguments:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if node.returns is not None:
            self.visit(node.returns)
        previous = self.enter(node, node.name)
        for statement in node.body:
            self.visit(statement)
        self.table = previous

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        for default in node.args.defaults:
            self.visit(default)
        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)
        previous = self.enter(node, "lambda")
        self.visit(node.body)
        self.table = previous

    def visit_GeneratorExp(self, node):
        self.visit(node.generators[0].iter)
        previous = self.enter(node, "genexpr")
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
            self.visit(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        self.visit(node.elt)
        self.table = previous
