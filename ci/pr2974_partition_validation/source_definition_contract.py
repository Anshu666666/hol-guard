"""Resolve Python definitions and scopes from complete source files."""
from __future__ import annotations

import ast
import hashlib
import inspect
import io
import symtable
import tokenize
from functools import lru_cache
from pathlib import Path

IGNORED_TOKENS = {
    tokenize.ENCODING, tokenize.ENDMARKER, tokenize.NL, tokenize.NEWLINE,
    tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT,
}


class SourceFile:
    def __init__(self, path: Path):
        self.path = path.resolve(strict=True)
        self.raw = self.path.read_bytes()
        self.sha256 = hashlib.sha256(self.raw).hexdigest()
        self.text = self.raw.decode("utf-8")
        self.tree = ast.parse(self.text, filename=str(self.path))
        self.table = symtable.symtable(self.text, str(self.path), "exec")
        self.definitions = []
        self.scopes = []
        self._walk_nodes(self.tree, "", False)
        self._walk_scopes(self.table, "", False, is_root=True)

    def _walk_nodes(self, node, parent, function_parent):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            name = "<lambda>" if isinstance(node, ast.Lambda) else node.name
            qualifier = parent + (".<locals>." if function_parent else ".") if parent else ""
            qualified = qualifier + name
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                decorators = getattr(node, "decorator_list", [])
                self.definitions.append({
                    "qualname": qualified, "name": name, "node": node,
                    "decorator_start": min([node.lineno, *[item.lineno for item in decorators]]),
                    "defline": node.lineno,
                })
            if not isinstance(node, ast.Lambda):
                for decorator in node.decorator_list:
                    self._walk_nodes(decorator, parent, function_parent)
                eager = ([*node.bases, *[item.value for item in node.keywords]] if isinstance(node, ast.ClassDef)
                         else [*node.args.defaults, *[item for item in node.args.kw_defaults if item is not None]])
                for expression in eager:
                    self._walk_nodes(expression, parent, function_parent)
            if isinstance(node, ast.Lambda):
                self._walk_nodes(node.body, qualified, True)
            else:
                for child in node.body:
                    self._walk_nodes(child, qualified, isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)))
            return
        for child in ast.iter_child_nodes(node):
            self._walk_nodes(child, parent, function_parent)

    def _walk_scopes(self, table, parent, function_parent, is_root=False):
        if is_root:
            qualified = ""
        else:
            name = "<lambda>" if table.get_name() == "lambda" else table.get_name()
            qualifier = parent + (".<locals>." if function_parent else ".") if parent else ""
            qualified = qualifier + name
            self.scopes.append({"qualname": qualified, "line": table.get_lineno(), "table": table})
        for child in table.get_children():
            self._walk_scopes(child, qualified, table.get_type() == "function")

    def scope_for(self, definition):
        matches = [entry["table"] for entry in self.scopes
                   if entry["qualname"] == definition["qualname"]
                   and entry["line"] == definition["defline"]
                   and entry["table"].get_type() == "function"]
        if len(matches) != 1:
            raise ValueError("Ambiguous or missing complete-file scope: " + definition["qualname"])
        return matches[0]

    def definition_for(self, function):
        raw = inspect.unwrap(getattr(function, "__func__", function))
        code = getattr(raw, "__code__", None)
        if code is None or Path(code.co_filename).resolve() != self.path:
            raise ValueError("Function has no matching readable Python source code")
        matches = [entry for entry in self.definitions
                   if entry["qualname"] == code.co_qualname
                   and entry["name"] == code.co_name
                   and entry["decorator_start"] <= code.co_firstlineno <= entry["defline"]]
        if len(matches) != 1:
            raise ValueError("Ambiguous or missing complete-file definition: " + code.co_qualname)
        return raw, matches[0]

    def globals_for(self, definition):
        names = set()
        def visit(scope):
            for symbol in scope.get_symbols():
                if symbol.is_global() and symbol.is_referenced():
                    names.add(symbol.get_name())
            for child in scope.get_children():
                visit(child)
        visit(self.scope_for(definition))
        return sorted(names)

    def tokens_for(self, node):
        start = min([node.lineno, *[item.lineno for item in getattr(node, "decorator_list", [])]])
        return [(token.type, token.string)
                for token in tokenize.tokenize(io.BytesIO(self.raw).readline)
                if token.type not in IGNORED_TOKENS
                and start <= token.start[0] and token.end[0] <= node.end_lineno]

    def named_definition(self, qualname, node):
        matches = [entry for entry in self.definitions if entry["qualname"] == qualname and entry["node"] is node]
        if len(matches) != 1:
            raise ValueError("Ambiguous named definition: " + qualname)
        return matches[0]


@lru_cache(maxsize=None)
def source_file(path):
    return SourceFile(Path(path))


def callable_source(function):
    raw = inspect.unwrap(getattr(function, "__func__", function))
    code = getattr(raw, "__code__", None)
    if code is None:
        raise ValueError("Callable has no Python code object")
    source = source_file(str(Path(code.co_filename).resolve(strict=True)))
    raw, definition = source.definition_for(raw)
    return source, raw, definition


def outer_units(tree):
    result = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result.append((node.name, node))
        elif isinstance(node, ast.ClassDef):
            assert not node.bases and not node.keywords and not node.decorator_list
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    result.append((node.name + "." + member.name, member))
                else:
                    assert isinstance(member, ast.Expr) and isinstance(member.value, ast.Constant)
                    assert isinstance(member.value.value, str)
        else:
            assert isinstance(node, (ast.Import, ast.ImportFrom)) or (
                isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ), type(node).__name__
    return result
