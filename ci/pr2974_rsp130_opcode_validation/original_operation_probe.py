"""Count exact join key-load opcodes; this is not a latency benchmark."""

from __future__ import annotations

import argparse
import ast
import dis
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import CodeType


def digest(path: Path) -> dict[str, object]:
    content = path.read_bytes()
    return {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}


def dump(node: ast.AST) -> str:
    return ast.dump(node, include_attributes=False)


def function(module: ast.Module, name: str) -> ast.FunctionDef:
    matches = [node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(matches) != 1:
        raise ValueError(f"Expected one complete-file function: {name}")
    return matches[0]


def original_join(module: ast.Module) -> list[ast.stmt]:
    body = function(module, "sync_aibom_snapshots").body
    matches = [
        index for index, node in enumerate(body)
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "content_sources_by_snapshot"
    ]
    if len(matches) != 1:
        raise ValueError("Original join boundary is ambiguous")
    index = matches[0]
    if not isinstance(body[index + 1], ast.For):
        raise ValueError("Original ordered nested loop is missing")
    return body[index:index + 2]


def codes(root: CodeType) -> list[CodeType]:
    result = [root]
    for item in root.co_consts:
        if isinstance(item, CodeType):
            result.extend(codes(item))
    return result


def counted(callback, *args, **kwargs):
    if sys.gettrace() is not None or sys.getprofile() is not None:
        raise RuntimeError("Operation probe requires an otherwise untraced process")
    maps = {
        code: {item.offset: item for item in dis.get_instructions(code)}
        for code in codes(callback.__code__)
    }
    counts = {"snapshot_id_load_attr": 0, "explicit_equal_comparisons": 0}

    def trace(frame, event, _arg):
        instructions = maps.get(frame.f_code)
        if instructions is None:
            return None
        if event == "call":
            frame.f_trace_lines = False
            frame.f_trace_opcodes = True
        elif event == "opcode":
            item = instructions[frame.f_lasti]
            if item.opname == "LOAD_ATTR" and item.argval == "snapshot_id":
                counts["snapshot_id_load_attr"] += 1
            if item.opname == "COMPARE_OP" and item.argval == "==":
                counts["explicit_equal_comparisons"] += 1
        return trace

    sys.settrace(trace)
    try:
        result = callback(*args, **kwargs)
    finally:
        sys.settrace(None)
    return result, counts


def main() -> int:
    if sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 12, 13):
        raise RuntimeError("Opcode accounting is scoped to reviewed CPython 3.12.13")
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-file", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    root = args.candidate_root.resolve(strict=True)
    test = root / "tests/test_aibom_primary_content_join_contract.py"
    cli = root / "src/codex_plugin_scanner/guard/aibom_cli.py"
    helper = root / "src/codex_plugin_scanner/guard/aibom_content_upload.py"
    output = args.output.resolve()
    if output.is_relative_to(root):
        raise ValueError("Operation evidence must remain outside the candidate checkout")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    watched = [args.baseline_file.resolve(strict=True), cli, helper, test,
               Path(__file__).resolve(), args.manifest.resolve(strict=True)]
    before = {str(path): digest(path) for path in watched}
    report = {
        "schema": "pr2974-rsp130-join-operation-probe.v1",
        "operation_count_only": True,
        "runtime_or_performance_qualification": False,
        "before": before,
        "cells": [],
    }
    try:
        if digest(args.baseline_file) != manifest["baseline_cli"]:
            raise ValueError("Baseline full source bytes differ from the reviewed join input")
        for path in (cli, helper, test):
            if digest(path) != manifest["candidate_files"][path.relative_to(root).as_posix()]:
                raise ValueError(f"Candidate full source bytes differ: {path.name}")
        baseline_ast = ast.parse(args.baseline_file.read_text(encoding="utf-8"), type_comments=True)
        test_ast = ast.parse(test.read_text(encoding="utf-8"), type_comments=True)
        wrapper = function(test_ast, "_original_join")
        if list(map(dump, wrapper.body[:-1])) != list(map(dump, original_join(baseline_ast))):
            raise ValueError("Original probe wrapper differs from actual production join AST")
        if not isinstance(wrapper.body[-1], ast.Return):
            raise ValueError("Probe wrapper must return only the original join result")
        candidate_ast = ast.parse(cli.read_text(encoding="utf-8"), type_comments=True)
        body = function(candidate_ast, "sync_aibom_snapshots").body
        branches = [
            node for node in body if isinstance(node, ast.If)
            and dump(node.test) == dump(ast.parse("indexed_content_sources is None", mode="eval").body)
        ]
        if len(branches) != 1 or list(map(dump, branches[0].body)) != list(map(dump, original_join(baseline_ast))):
            raise ValueError("Candidate inline fallback differs from original ordered join AST")
        sys.path.insert(0, str(root / "src"))
        spec = importlib.util.spec_from_file_location("rsp130_join_probe_contracts", test)
        if spec is None or spec.loader is None:
            raise ValueError("Cannot bind exact test source")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        actual_helper = module.upload._indexed_primary_content_sources
        if Path(actual_helper.__code__.co_filename).resolve(strict=True) != helper:
            raise ValueError("Loaded join helper is outside candidate source")
        product_origins = {}
        for name, loaded in tuple(sys.modules.items()):
            if not name.startswith("codex_plugin_scanner"):
                continue
            location = getattr(loaded, "__file__", None)
            if location is None:
                continue
            path = Path(location).resolve(strict=True)
            path.relative_to(root / "src")
            product_origins[name] = {"path": str(path), **digest(path)}
        report["product_origins"] = product_origins
        cells = [(1, 0), (1, 1), (2, 4), (4, 32), (8, 128), (16, 512)]
        for snapshot_count, source_count in cells:
            snapshots = tuple(module._snapshot(f"key-{index}") for index in range(snapshot_count))
            sources = [module._source(f"key-{index % snapshot_count}", index) for index in range(source_count)]
            original, old_counts = counted(module._original_join, snapshots, sources)
            indexed, new_counts = counted(actual_helper, snapshots, sources, tuple_factory=tuple)
            if indexed is None:
                raise ValueError("Stock plain records unexpectedly refused the proposed index")
            module._same(original, indexed)
            expected_old = 2 * snapshot_count * source_count + snapshot_count
            expected_new = snapshot_count + source_count
            row = {
                "snapshots": snapshot_count,
                "sources": source_count,
                "original": old_counts,
                "candidate": new_counts,
                "expected_original_key_loads": expected_old,
                "expected_candidate_key_loads": expected_new,
                "exact_key_and_source_object_order_equal": True,
            }
            report["cells"].append(row)
            if old_counts != {"snapshot_id_load_attr": expected_old, "explicit_equal_comparisons": snapshot_count * source_count}:
                raise ValueError("Original actual opcode count differs from source-derived count")
            if new_counts != {"snapshot_id_load_attr": expected_new, "explicit_equal_comparisons": 0}:
                raise ValueError("Candidate actual opcode count differs from source-derived count")
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        report["after"] = {str(path): digest(path) for path in watched}
        report["sources_unchanged"] = report["after"] == before
        report["passed"] = bool(report.get("passed")) and report["sources_unchanged"]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
