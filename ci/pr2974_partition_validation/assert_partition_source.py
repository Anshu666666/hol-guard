"""Check exact existing test bodies and static import bindings for the two partitions."""
from __future__ import annotations

import argparse
import ast
import builtins
import hashlib
import json
from pathlib import Path

import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_definition_contract import SourceFile, outer_units

SUFFIXES = (
    "", "_01_dashboard", "_02_settings", "_03_hook_requests", "_04_hook_temporary_workspaces",
    "_05_hook_capacity", "_06_hook_authority", "_07_cloud_identity", "_08_cloud_recovery",
    "_09_hook_responses_idle", "_10_surface_contracts", "_11_surface_operations",
    "_12_approval_browser", "_13_surface_clients", "_14_fast_hook_path",
)
BASELINES = {
    "command": "3ed9645fc09cbf491b41b022987b604dd032ec549488f46e1eb127baf1c9a3c2",
    "surface": "aefc229d8cc717aecb100aa48f2f2a890349dd46bed8075ac1bf2d93e98f8ddf",
}

def dump(node):
    return ast.dump(node, include_attributes=False)

def imports(tree):
    result = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = ("import", alias.name, bool(alias.asname))
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for alias in node.names:
                assert alias.name != "*"
                result[alias.asname or alias.name] = ("from", "." * node.level + (node.module or ""), alias.name)
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lane", choices=("command", "surface"), required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--baseline-guide", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    original_raw = args.baseline.read_bytes()
    assert hashlib.sha256(original_raw).hexdigest() == BASELINES[args.lane]
    original_source = SourceFile(args.baseline)
    original = original_source.tree
    original_units = outer_units(original)
    original_imports = imports(original)
    original_helpers = {node.name: node for node in original.body
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if args.lane == "command":
        paths = ["tests/test_guard_command_extensions" + suffix + ".py"
                 for suffix in ("", "_runtime", "_runtime_policy")]
        module_name = "tests.test_guard_command_extensions"
        expected_units, expected_tests = 37, 36
    else:
        paths = ["tests/test_guard_surface_server" + suffix + ".py" for suffix in SUFFIXES]
        module_name = "tests.test_guard_surface_server"
        expected_units, expected_tests = 112, 107
    assert len(original_units) == expected_units
    candidate_units = []
    file_records = {}
    modules = {}
    for path in paths:
        raw = (args.candidate_root / path).read_bytes()
        text = raw.decode()
        assert len(text.splitlines()) <= 500, path
        source = SourceFile(args.candidate_root / path)
        tree = source.tree
        modules[path] = (source, tree, imports(tree))
        file_records[path] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                              "physical_lines": len(text.splitlines())}
        candidate_units.extend((name, node, path) for name, node in outer_units(tree))
    assert [name for name, _ in original_units] == [name for name, _, _ in candidate_units]
    bindings_checked = 0
    for (name, before), (_, after, path) in zip(original_units, candidate_units, strict=True):
        assert dump(before) == dump(after), name
        assert original_source.tokens_for(before) == modules[path][0].tokens_for(after), name
        current_imports = modules[path][2]
        current_helpers = {node.name: node for node in modules[path][1].body
                           if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        original_definition = original_source.named_definition(name, before)
        for global_name in original_source.globals_for(original_definition):
            if global_name == before.name:
                continue
            expected = original_imports.get(global_name)
            actual = current_imports.get(global_name)
            if actual and actual[0] == "from" and actual[1] == module_name:
                origin = actual[2]
                actual = original_imports.get(origin)
                if actual is None and origin in original_helpers:
                    actual = ("helper", dump(original_helpers[origin]))
            if expected is None and global_name in original_helpers:
                expected = ("helper", dump(original_helpers[global_name]))
                if actual is None and global_name in current_helpers:
                    actual = ("helper", dump(current_helpers[global_name]))
            if expected is None:
                assert hasattr(builtins, global_name), (name, global_name, "unresolved original binding")
                assert actual is None, (name, global_name, "builtin shadowed")
            else:
                assert actual == expected, (name, global_name, expected, actual)
                bindings_checked += 1
    if args.lane == "surface":
        old_header = [dump(node) for node in original.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        new_header = [dump(node) for node in modules[paths[0]][1].body
                      if isinstance(node, (ast.Import, ast.ImportFrom))]
        assert old_header == new_header
        old_fast = next(node for node in original.body if isinstance(node, ast.ClassDef)
                        and node.name == "TestGuardDaemonFastHookPath")
        new_fast = next(node for node in modules[paths[-1]][1].body if isinstance(node, ast.ClassDef)
                        and node.name == "TestGuardDaemonFastHookPath")
        assert dump(old_fast) == dump(new_fast)
        for name, node in original_helpers.items():
            match = next(item for item in modules[paths[0]][1].body if isinstance(item, ast.FunctionDef)
                         and item.name == name) if name != "test_unauthorized_response_waits_for_audit_recording" else None
            if match is not None:
                assert dump(node) == dump(match)
        assert args.baseline_guide is not None
        guide_raw = args.baseline_guide.read_bytes()
        assert hashlib.sha256(guide_raw).hexdigest() == "77931b08cc9f9570fcabccd6f3af1ad48734ffcb117d7013d4468ba084a338f1"
        before = guide_raw.decode()
        old = "test_guard_surface_server.py::TestGuardDaemonFastHookPath"
        new = "test_guard_surface_server_14_fast_hook_path.py::TestGuardDaemonFastHookPath"
        assert before.count(old) == 1
        assert (args.candidate_root / "docs/guard/all-harness-hook-review.md").read_text() == before.replace(old, new)
    test_count = sum(name.rsplit(".", 1)[-1].startswith("test_") for name, _ in original_units)
    assert test_count == expected_tests
    result = {"lane": args.lane, "files": file_records, "ordered_outer_definitions": expected_units,
              "test_definitions": test_count, "ordered_full_function_asts_equal": True,
              "function_tokens_equal_except_layout_comments": True, "static_global_bindings_checked": bindings_checked,
              "actual_collection_or_runtime_performed": False, "source_only": True}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
