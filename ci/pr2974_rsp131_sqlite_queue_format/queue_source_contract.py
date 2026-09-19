"""Prove the frozen queue patch from complete source without product imports."""

from __future__ import annotations

import argparse
import ast
import builtins
import copy
import hashlib
import json
from pathlib import Path
import symtable
import sys
import traceback

PACKET_SHA256 = "79d982d7328f0b552a9eeeecd797fb4ebcac5518167b234747cae6d2ce0448e7"
WRITER = "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py"
OPERATIONS = "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_operations.py"
OBSERVER = "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_queue_observation.py"
METHODS = (
    "submit_command_activity", "submit_native_decision_receipt",
    "_derive_correlation", "_persist_command_activity",
)
EARLY_IMPORT = "\nfrom . import runtime_hook_evidence_operations as _evidence_operations\n"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def dump(node: ast.AST) -> str:
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def parse(source: str, path: str) -> ast.Module:
    tree = ast.parse(source, filename=path, type_comments=True)
    assert not tree.type_ignores, (path, "Unexpected TypeIgnore")
    return tree


def replace_once(source: str, old: str, new: str) -> str:
    assert old and source.count(old) == 1, ("Nonunique exact replacement", old[:100])
    return source.replace(old, new, 1)


def class_node(tree: ast.Module) -> ast.ClassDef:
    matches = [
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "RuntimeHookEvidenceWriter"
    ]
    assert len(matches) == 1
    return matches[0]


def functions(nodes: list[ast.stmt]) -> dict[str, ast.FunctionDef]:
    result = {}
    for node in nodes:
        if isinstance(node, ast.FunctionDef):
            assert node.name not in result
            result[node.name] = node
    return result


def imports(tree: ast.Module) -> dict[str, ast.AST]:
    result = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                assert name not in result
                result[name] = node
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                continue
            for alias in node.names:
                assert alias.name != "*"
                name = alias.asname or alias.name
                assert name not in result
                result[name] = node
    return result


def table_child(table, name: str, line: int):
    matches = [
        child for child in table.get_children()
        if child.get_name() == name and child.get_lineno() == line
    ]
    assert len(matches) == 1, (name, line)
    return matches[0]


def signature(node: ast.FunctionDef) -> tuple[str, str | None, list[str], str | None]:
    return (
        dump(node.args), dump(node.returns) if node.returns else None,
        [dump(item) for item in node.decorator_list], node.type_comment,
    )


def whole_inverse(packet: dict, current: dict[str, str]) -> tuple[str, str, dict]:
    proof = packet["exact_writer_inverse"]
    correction = proof["before_prior_inverse_apply_exact_reflection_correction_inverse"]
    for path, before in correction["prior"].items():
        value = before
        for edit in correction["edits"]:
            if edit["path"] == path:
                value = replace_once(value, edit["old"], edit["new"])
        assert value == correction["current"][path] == current[path]
    source = correction["prior"][WRITER]
    for edit in reversed(proof["facade_layout_edits"]):
        offset = edit["offset"]
        assert source[offset:offset + len(edit["new"])] == edit["new"], edit["label"]
        source = source[:offset] + edit["old"] + source[offset + len(edit["new"]):]
    for move in reversed(proof["method_moves"]):
        source = replace_once(source, move["wrapper"], move["original"])
    source = replace_once(source, EARLY_IMPORT, "")
    hooked = source
    for edit in reversed(proof["hook_edits"]):
        source = replace_once(source, edit["new"], edit["old"])
    original = packet["original_writer"]
    assert source == original["content"]
    raw = source.encode()
    assert sha(raw) == original["sha256"] == packet["baseline"]["writer_sha256"]
    assert git_blob(raw) == original["git_blob"] == packet["baseline"]["writer_blob"]
    assert len(raw) == original["bytes"] == packet["baseline"]["writer_bytes"]
    forward = source
    for edit in proof["hook_edits"]:
        forward = replace_once(forward, edit["old"], edit["new"])
    assert forward == hooked
    return source, hooked, {
        "complete_original_byte_inverse": True,
        "original_git_blob": git_blob(raw), "original_sha256": sha(raw),
        "reflection_delta_paths": sorted(correction["prior"]),
        "hook_edits": len(proof["hook_edits"]),
        "layout_edits": len(proof["facade_layout_edits"]),
    }


class Qualify(ast.NodeTransformer):
    def __init__(self, names: set[str]) -> None:
        self.names = names
        self.rows: list[dict] = []

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load) and node.id in self.names:
            self.rows.append({"name": node.id, "line": node.lineno, "column": node.col_offset})
            return ast.copy_location(
                ast.Attribute(value=ast.Name(id="_writer", ctx=ast.Load()), attr=node.id, ctx=ast.Load()),
                node,
            )
        return node


def method_proof(original: str, hooked: str, current: dict[str, str], trees: dict) -> dict:
    original_tree = parse(original, "original/" + WRITER)
    hooked_tree = parse(hooked, "hooked/" + WRITER)
    original_class = class_node(original_tree)
    hooked_class = class_node(hooked_tree)
    facade_class = class_node(trees[WRITER])
    original_functions = functions(original_class.body)
    hooked_functions = functions(hooked_class.body)
    facade_functions = functions(facade_class.body)
    helper_functions = functions(trees[OPERATIONS].body)
    assert tuple(helper_functions) == METHODS
    assert [name for name in original_functions if name in METHODS] == list(METHODS)
    assert [name for name in facade_functions if name in METHODS] == list(METHODS)
    assert [dump(item) for item in original_class.bases] == [dump(item) for item in facade_class.bases]
    assert [dump(item) for item in original_class.decorator_list] == [
        dump(item) for item in facade_class.decorator_list
    ]
    original_imports = imports(original_tree)
    current_imports = imports(trees[WRITER])
    for name, declaration in original_imports.items():
        assert dump(current_imports[name]) == dump(declaration), name
    module_table = symtable.symtable(hooked, "hooked/" + WRITER, "exec")
    owner_table = table_child(module_table, hooked_class.name, hooked_class.lineno)
    helper_module_table = symtable.symtable(current[OPERATIONS], OPERATIONS, "exec")
    rows = []
    total = 0
    for name in METHODS:
        before, source, facade, helper = (
            original_functions[name], hooked_functions[name],
            facade_functions[name], helper_functions[name],
        )
        assert signature(before) == signature(source) == signature(facade)
        assert ast.get_docstring(before, clean=False) == ast.get_docstring(facade, clean=False)
        assert not source.decorator_list
        assert not source.args.posonlyargs and not source.args.vararg and not source.args.kwarg
        assert source.args.args[0].arg == "self" and source.args.args[0].annotation is None
        for default in [*source.args.defaults, *source.args.kw_defaults]:
            assert default is None or isinstance(default, ast.Constant)
        nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
                  ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        body_nodes = [item for statement in source.body for item in ast.walk(statement)]
        assert not any(isinstance(item, nested) for item in body_nodes), name
        assert not any(isinstance(item, (ast.Global, ast.Nonlocal)) for item in body_nodes), name
        assert not any(
            isinstance(item, ast.Name) and item.id in {
                "__class__", "super", "globals", "locals", "eval", "exec",
                "__name__", "__file__", "__package__", "__spec__",
            } for item in body_nodes
        ), name
        scope = table_child(owner_table, name, source.lineno)
        assert not scope.get_frees()
        runtime = []
        for node in body_nodes:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                symbol = scope.lookup(node.id)
                if node.id in original_imports:
                    assert symbol.is_global(), (name, node.id)
                if symbol.is_global():
                    assert node.id in original_imports or node.id in vars(builtins), (name, node.id)
                    runtime.append({
                        "name": node.id, "line": node.lineno,
                        "column": node.col_offset,
                        "binding": "live-facade-import" if node.id in original_imports else "builtin",
                    })
        qualifier = Qualify(set(original_imports))
        expected = qualifier.visit(copy.deepcopy(source))
        expected.args.args[0].annotation = ast.parse(
            "_writer.RuntimeHookEvidenceWriter", mode="eval"
        ).body
        assert dump(expected) == dump(helper), name
        helper_scope = table_child(helper_module_table, name, helper.lineno)
        assert helper_scope.lookup("_writer").is_global()
        body = list(facade.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            assert isinstance(body[0].value.value, str)
            body.pop(0)
        assert len(body) == 1 and isinstance(body[0], (ast.Return, ast.Expr)), name
        call = body[0].value
        assert isinstance(call, ast.Call)
        assert isinstance(call.func, ast.Attribute) and call.func.attr == name
        assert isinstance(call.func.value, ast.Name) and call.func.value.id == "_evidence_operations"
        assert [dump(item) for item in call.args] == [
            dump(ast.Name(id=arg.arg, ctx=ast.Load())) for arg in source.args.args
        ]
        assert [(item.arg, dump(item.value)) for item in call.keywords] == [
            (arg.arg, dump(ast.Name(id=arg.arg, ctx=ast.Load()))) for arg in source.args.kwonlyargs
        ]
        assert isinstance(body[0], ast.Expr) == (name == "_persist_command_activity")
        total += len(qualifier.rows)
        rows.append({
            "method": name, "full_function_ast_after_exact_forward_map_equal": True,
            "public_signature_doc_and_descriptor_owner_retained": True,
            "literal_eager_defaults": True, "runtime_global_loads": runtime,
            "all_live_qualifications_including_deferred_annotations": qualifier.rows,
            "exact_argument_delegate": True, "extra_helper_call_frame": True,
        })
    assert total == 32
    return {"methods": rows, "live_qualifications": total, "receiver_annotations": 4}


def mutation_sites(trees: dict) -> list[dict]:
    expected = {
        (OPERATIONS, "submit_command_activity", "append"): "admission",
        (OPERATIONS, "submit_native_decision_receipt", "append"): "admission",
        (WRITER, "_record_persistence_failure", "append"): "retry",
        (WRITER, "_recover_journal", "append"): "recovery",
        (WRITER, "_next_batch", "popleft"): None,
    }
    found = []
    for path in (WRITER, OPERATIONS):
        nodes = class_node(trees[path]).body if path == WRITER else trees[path].body
        for name, function in functions(nodes).items():
            for parent in ast.walk(function):
                for _, value in ast.iter_fields(parent):
                    if not isinstance(value, list):
                        continue
                    for index, statement in enumerate(value):
                        call = statement.value if isinstance(statement, (ast.Expr, ast.Assign)) else None
                        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                            continue
                        target = call.func.value
                        if not (
                            isinstance(target, ast.Attribute) and target.attr == "_records"
                            and isinstance(target.value, ast.Name) and target.value.id == "self"
                        ):
                            continue
                        key = (path, name, call.func.attr)
                        assert key in expected, key
                        origin = expected[key]
                        argument = "" if origin is None else ", " + repr(origin)
                        template = ast.parse(
                            "if self._queue_observation is not None:\n"
                            "    self._observe_queue(record" + argument + ")\n"
                        ).body[0]
                        assert index + 1 < len(value) and dump(value[index + 1]) == dump(template), key
                        found.append({"path": path, "function": name, "operation": call.func.attr, "origin": origin})
    assert len(found) == 5 and len({(r["path"], r["function"]) for r in found}) == 5
    return found


def declaration_order_proof(trees: dict) -> dict:
    writer, operations, observer = trees[WRITER], trees[OPERATIONS], trees[OBSERVER]
    expected_writer_tail = ast.parse(
        "from . import runtime_hook_evidence_operations as _evidence_operations\n"
        "from .runtime_hook_evidence_queue_observation import EvidenceQueueObservation\n"
    ).body
    assert [dump(node) for node in writer.body[-2:]] == [dump(node) for node in expected_writer_tail]
    assert dump(operations.body[-1]) == dump(ast.parse(
        "from . import runtime_hook_evidence_writer as _writer\n"
    ).body[0])
    for node in observer.body:
        if isinstance(node, ast.ImportFrom):
            assert node.module != "runtime_hook_evidence_writer"
    writer_imports = imports(writer)
    assert "EvidenceQueueObservation" in writer_imports
    initial = functions(class_node(writer).body)["__init__"]
    assert dump(initial.args.kwonlyargs[-1].annotation) == dump(ast.parse(
        "EvidenceQueueObservation | None", mode="eval"
    ).body)
    assert initial.args.kwonlyargs[-1].arg == "queue_observation"
    assert isinstance(initial.args.kw_defaults[-1], ast.Constant)
    assert initial.args.kw_defaults[-1].value is None
    return {
        "all_operation_definitions_precede_live_facade_import": True,
        "facade_definitions_precede_operation_and_observer_imports": True,
        "observer_no_direct_runtime_writer_import": True,
        "constructor_runtime_observer_binding_present": True,
        "cold_import_and_runtime_type_hint_controls": "prepared; not executed by source checker",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    output = args.output.resolve()
    assert not output.is_relative_to(root), "Evidence output must be outside immutable source"
    result = {"schema": "pr2974-queue-source-contract-v1", "passed": False,
              "product_imports": False, "runtime_tests_executed": False,
              "qualification_complete": False}
    checked = []
    try:
        assert __debug__, "Source proof assertions must remain enabled"
        raw = args.packet.read_bytes()
        assert sha(raw) == PACKET_SHA256
        packet = json.loads(raw)
        current, trees = {}, {}
        for record in packet["files"]:
            path = record["path"]
            target = (root / path).resolve(strict=True)
            assert target.is_relative_to(root) and not (root / path).is_symlink()
            data = target.read_bytes()
            assert sha(data) == record["sha256"] and git_blob(data) == record["git_blob"]
            assert len(data) == record["bytes"] and data.decode() == record["content"]
            assert len(data.decode().splitlines()) == record["physical_lines"] <= 500
            checked.append((target, record["sha256"]))
            current[path] = data.decode()
            trees[path] = parse(current[path], path)
        original, hooked, inverse = whole_inverse(packet, current)
        result["source_files"] = [{key: value for key, value in r.items() if key != "content"}
                                  for r in packet["files"]]
        result["whole_byte_inverse"] = inverse
        result["method_ast_and_full_file_symtable"] = method_proof(original, hooked, current, trees)
        result["actual_adjacent_deque_hooks"] = mutation_sites(trees)
        result["declaration_order"] = declaration_order_proof(trees)
        test_counts = {
            path: len([node for node in tree.body if isinstance(node, ast.FunctionDef)
                       and node.name.startswith("test_")])
            for path, tree in trees.items() if path.startswith("tests/")
        }
        assert sorted(test_counts.values()) == [7, 13]
        result["test_definitions"] = test_counts
        result["case_design"] = {"expected": 30, "actual_pytest_collection": False}
        result["passed"] = True
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
        result["traceback"] = traceback.format_exc()
    finally:
        result["all_checked_source_bytes_unchanged"] = all(
            target.is_file() and sha(target.read_bytes()) == digest for target, digest in checked
        )
        result["passed"] = result["passed"] and result["all_checked_source_bytes_unchanged"]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
