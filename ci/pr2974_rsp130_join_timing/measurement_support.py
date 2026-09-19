"""Prepare source-bound join measurements; no timers or product calls at import."""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib
import json
import os
import sys
from pathlib import Path
from types import FunctionType


def hashed(path: Path) -> dict:
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def admitted(path: Path, manifest: dict) -> dict:
    assert manifest["measurement_status"] == "final_evidence_bound", "Measurement evidence is not admitted"
    pin = manifest["operation_admission"]
    assert isinstance(pin, dict) and isinstance(pin.get("sha256"), str), "Actual six-cell evidence not bound"
    assert hashed(path) == {"sha256": pin["sha256"], "bytes": pin["bytes"]}
    functional_path = Path(__file__).with_name("original-functional-terminal.json")
    old_pin = manifest["functional_admission"]
    assert hashed(functional_path) == {"sha256": old_pin["sha256"], "bytes": old_pin["bytes"]}
    functional = json.loads(functional_path.read_bytes())
    assert functional["source_sha"] == manifest["candidate"]["sha"]
    assert functional["source_tree"] == manifest["candidate"]["tree"]
    assert functional["original_outcome"]["passed"] is False
    assert functional["original_outcome"]["source_unchanged"] is True
    assert functional["complete_original_frame_and_case_audit"] is True
    audit = functional["independent_data_audit"]
    assert audit["actual_candidate_body_passes"] == 45 and audit["actual_ordered_passing_phases"] == 135
    assert audit["source_and_environment_unchanged"] and audit["full_baseline_candidate_existing_rows_equal"]
    receipt = json.loads(path.read_bytes())
    assert receipt["source_sha"] == manifest["candidate"]["sha"]
    assert receipt["source_tree"] == manifest["candidate"]["tree"]
    outcome, operations = receipt["original_outcome"], receipt["operations_results"]
    assert outcome["source_sha"] == manifest["candidate"]["sha"] and outcome["passed"] is True
    assert outcome["source_unchanged"] is True and outcome["error"] is None
    assert outcome["harness_sha"] == pin["harness_sha"]
    assert outcome["all_original_owned_groups_retired"] is True
    assert operations["errors"] == [] and operations["fresh_functional_test_bodies"] == 0
    results = operations["results"]
    assert results["prior_functional"]["original_failure_preserved"] is True
    assert results["prior_functional"]["original_functional_results"] == functional["finite_results"]["results"]
    for key, count in (("existing-execution", 23), ("new-execution", 22)):
        row = functional["finite_results"]["results"][key]
        assert row["tests"] == row["passed"] == count
        assert row["failed"] == row["errored"] == row["skipped"] == 0
        assert row["all_cases_without_skip"] and row["ordered_junit_and_node_phase_outcomes_equal"]
    calibrations = results["calibrations"]
    assert [row["case"] for row in calibrations] == [
        "unprimed-negative", "first-load", "nested-comparison", "exception-cleanup"]
    assert all(row["passed"] and row["sources_unchanged"] and row["product_callbacks_executed"] == 0
               for row in calibrations)
    cells = results["operation_cells"]
    assert cells["passed"] and cells["sources_unchanged"] and len(cells["cells"]) == 6
    for row, expected in zip(cells["cells"], manifest["operation_cells"], strict=True):
        count, supplied = expected
        assert [row["snapshots"], row["sources"]] == expected
        assert row["original"] == {"snapshot_id_load_attr": 2 * count * supplied + count,
                                   "explicit_equal_comparisons": count * supplied}
        assert row["candidate"] == {"snapshot_id_load_attr": count + supplied,
                                    "explicit_equal_comparisons": 0}
        assert row["exact_key_and_source_object_order_equal"] is True
    assert receipt["complete_original_frame_and_operation_audit"] is True
    return {"functional": functional, "operations": receipt}

def runtime_settings(seed: int) -> dict:
    flags = sys.flags
    assert flags.safe_path and flags.no_user_site and flags.dont_write_bytecode
    assert not flags.isolated and not flags.ignore_environment and flags.optimize == 0
    python_environment = {key: value for key, value in os.environ.items() if key.startswith("PYTHON")}
    assert python_environment == {"PYTHONHASHSEED": str(seed)}
    assert "" not in sys.path and str(Path.cwd()) not in sys.path
    # These distinct public sentinels never occur in any measured key population.
    sentinels = [str(hash("rsp130-hash-admission:first:public-sentinel")),
                 str(hash("rsp130-hash-admission:second:public-sentinel"))]
    return {"python_flags": {name: getattr(flags, name) for name in (
                "safe_path", "no_user_site", "dont_write_bytecode", "isolated",
                "ignore_environment", "optimize", "hash_randomization")},
            "python_environment": python_environment, "hash_sentinels": sentinels,
            "startup_sys_path": list(sys.path)}

def one_function(module: ast.Module, name: str) -> ast.FunctionDef:
    matches = [node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == name]
    assert len(matches) == 1, name
    return matches[0]


def dumped(value: ast.AST) -> str:
    return ast.dump(value, include_attributes=False)


def join_nodes(source: bytes, arm: str) -> list[ast.stmt]:
    function = one_function(ast.parse(source, type_comments=True), "sync_aibom_snapshots")
    if arm == "baseline":
        positions = [index for index, node in enumerate(function.body)
                     if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                     and node.target.id == "content_sources_by_snapshot"]
    else:
        positions = [index for index, node in enumerate(function.body)
                     if isinstance(node, ast.Assign) and len(node.targets) == 1
                     and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "indexed_content_sources"]
    assert len(positions) == 1
    nodes = function.body[positions[0]:positions[0] + 2]
    assert len(nodes) == 2
    return nodes


def load_join(root: Path, baseline_file: Path, candidate_file: Path, arm: str, manifest: dict):
    assert arm in ("baseline", "candidate")
    source = root / "src/codex_plugin_scanner/guard/aibom_cli.py"
    expected = manifest[arm]["cli"]
    assert hashed(source) == expected
    old, new = join_nodes(baseline_file.read_bytes(), "baseline"), join_nodes(candidate_file.read_bytes(), "candidate")
    assert isinstance(old[1], ast.For) and isinstance(new[1], ast.If)
    assert [dumped(node) for node in new[1].body] == [dumped(node) for node in old]
    assert dumped(new[1].test) == dumped(ast.parse("indexed_content_sources is None", mode="eval").body)
    assert [dumped(node) for node in new[1].orelse] == [
        dumped(ast.parse("content_sources_by_snapshot = indexed_content_sources").body[0])]
    expected_call = ast.parse(
        "indexed_content_sources = _indexed_primary_content_sources("
        "snapshots, primary_content_sources, tuple_factory=tuple)").body[0]
    assert dumped(new[0]) == dumped(expected_call)
    sys.path.insert(0, str(root / "src"))
    module = importlib.import_module("codex_plugin_scanner.guard.aibom_cli")
    upload = importlib.import_module("codex_plugin_scanner.guard.aibom_content_upload")
    assert Path(module.__file__).resolve() == source.resolve()
    assert module.__dict__.get("tuple", tuple) is tuple
    assert Path(upload.__file__).resolve() == (root / "src/codex_plugin_scanner/guard/aibom_content_upload.py").resolve()
    if arm == "candidate":
        assert module._indexed_primary_content_sources is upload._indexed_primary_content_sources
        assert Path(upload._indexed_primary_content_sources.__code__.co_filename).resolve() == Path(upload.__file__).resolve()
    original_upload = baseline_file.with_name("aibom_content_upload.py").read_bytes()
    current_upload = candidate_file.with_name("aibom_content_upload.py").read_bytes()
    def record_class(raw, name):
        matches = [node for node in ast.parse(raw, type_comments=True).body
                   if isinstance(node, ast.ClassDef) and node.name == name]
        assert len(matches) == 1 and not matches[0].bases
        # Both exact constructors are generated dataclass setters; no custom hook hashes a key.
        assert all(isinstance(node, ast.AnnAssign) for node in matches[0].body)
        return dumped(matches[0])
    assert record_class(original_upload, "GuardAibomPrimaryContentSource") == record_class(
        current_upload, "GuardAibomPrimaryContentSource")
    models_path = Path("src/codex_plugin_scanner/guard/inventory_contract_models.py")
    baseline_models = baseline_file.parents[3] / models_path
    candidate_models = candidate_file.parents[3] / models_path
    assert hashed(baseline_models) == hashed(candidate_models) == manifest["record_models"]
    snapshot_class_ast = record_class(baseline_models.read_bytes(), "GuardAgentInventorySnapshot")
    assert snapshot_class_ast == record_class(candidate_models.read_bytes(), "GuardAgentInventorySnapshot")
    models = importlib.import_module("codex_plugin_scanner.guard.inventory_contract_models")
    assert Path(models.__file__).resolve() == (root / models_path).resolve()
    syntax = ast.parse("def measured_join(snapshots, primary_content_sources):\n    pass\n")
    wrapper = syntax.body[0]
    wrapper.body = copy.deepcopy(old if arm == "baseline" else new)
    wrapper.body.append(ast.Return(value=ast.Name(id="content_sources_by_snapshot", ctx=ast.Load())))
    ast.fix_missing_locations(syntax)
    scratch = {}
    exec(compile(syntax, str(source), "exec"), scratch)
    # Preserve actual module-global lookups without publishing a helper onto the module.
    callback = FunctionType(scratch["measured_join"].__code__, module.__dict__, "measured_join")
    snapshot_type = module.GuardAgentInventorySnapshot
    source_type = upload.GuardAibomPrimaryContentSource
    assert type(snapshot_type) is type and type(source_type) is type
    assert snapshot_type.__dataclass_params__.frozen and source_type.__dataclass_params__.frozen
    assert snapshot_type is models.GuardAgentInventorySnapshot is upload.GuardAgentInventorySnapshot
    assert "__post_init__" not in snapshot_type.__dict__ and "__post_init__" not in source_type.__dict__
    return callback, module, upload, snapshot_type, source_type


def origins(root: Path) -> dict:
    result = {}
    for name, module in tuple(sys.modules.items()):
        if name != "codex_plugin_scanner" and not name.startswith("codex_plugin_scanner."):
            continue
        filename = getattr(module, "__file__", None)
        if filename is None:
            continue
        path = Path(filename).resolve(strict=True)
        relative = path.relative_to(root / "src")
        result[name] = {"path": relative.as_posix(), **hashed(path)}
    assert result
    return result
