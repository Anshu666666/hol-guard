"""Run only the four immutable RSP-100 witnesses in one serial isolated test process."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, sha256, source_witness, write_json
from environment_setup import finish_environment, prepare_environment
from finite_contract import collected, execution


def prepared_source() -> dict[str, dict]:
    path = SOURCE / CONFIG["witness_path"]
    raw = path.read_bytes()
    assert sha256(raw) == CONFIG["evidence_files"][CONFIG["witness_path"]]["sha256"]
    tree = ast.parse(raw, filename=str(path))
    functions = {
        node.name: node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }
    first = "test_constructor_replacement_retains_the_purepath_name_counterexample"
    second = "test_later_risk_changes_are_not_bound_by_input_only_facts"
    assert set(functions) == {first, second} and not functions[first].decorator_list
    decorators = functions[second].decorator_list
    assert len(decorators) == 1
    parameter = decorators[0]
    assert isinstance(parameter, ast.Call) and not parameter.keywords
    assert ast.unparse(parameter.func) == "pytest.mark.parametrize"
    assert len(parameter.args) == 2 and ast.literal_eval(parameter.args[0]) == "mutation"
    variants = ast.literal_eval(parameter.args[1])
    assert variants == ["function_binding", "function_code", "closure_contents"]
    nodes = [CONFIG["witness_path"] + "::" + first] + [
        CONFIG["witness_path"] + "::" + second + "[" + value + "]" for value in variants]
    assert nodes == CONFIG["expected_nodes"]
    records = {
        name: {"path": "@tests/" + CONFIG["witness_path"], "name": name,
               "first_line": min([node.lineno, *[item.lineno for item in node.decorator_list]]),
               "function_ast_sha256": sha256(ast.dump(node, include_attributes=False).encode()),
               "whole_file_sha256": sha256(raw)}
        for name, node in functions.items()
    }
    write_json(REPORT / "prepared-witness-source.json", {
        "path": CONFIG["witness_path"], "sha256": sha256(raw), "bytes": len(raw),
        "full_module_ast_sha256": sha256(ast.dump(tree, include_attributes=False).encode()),
        "functions": records, "expected_nodes": nodes,
        "source_parsed_without_import": True, "source_changed": False,
        "negative_control_divergence_required": True, "qualification_complete": False,
    })
    return records


def run_pytest(run, env, python, name, *, prior=None):
    snapshot = REPORT / (name + ".json")
    junit = REPORT / (name + "-junit.xml")
    child_env = dict(env, LSC_TEST_ROOT=str(SOURCE), LSC_PRODUCT_ROOT=str(SOURCE / "src"),
                     LSC_TEST_REPORT=str(snapshot), LSC_COLLECTION_ONLY="0" if prior else "1")
    if prior is not None:
        child_env["LSC_PRIOR_COLLECTION"] = str(prior)
    args = [
        str(python), "-I", "-B", str(HERE / "pytest_capture.py"),
        "--noconftest", "-c", "/dev/null", "--rootdir", str(SOURCE),
        "-q", "-m", "", "--tb=long", "-o", "cache_dir=" + str(SCRATCH / "pytest-cache" / name),
        "--basetemp", str(SCRATCH / "tmp" / name),
    ]
    if prior is None:
        args += ["--collect-only"]
    else:
        args += ["--junitxml", str(junit)]
    args += CONFIG["expected_nodes"]
    passed = run.command(name, args, env=child_env, timeout=180 if prior else 120)
    if prior is None:
        run.require(passed, "The original four-witness collection failed; all logs and snapshots retained")
    return snapshot, junit


def bind_origins(run, path: Path, functions: dict[str, dict]) -> dict:
    data = json.loads(path.read_bytes())
    assert [case["nodeid"] for case in data["cases"]] == CONFIG["expected_nodes"]
    assert data["product_module_origins"], "No selected production module origin recorded"
    for case in data["cases"]:
        assert case["function"] == functions[case["function"]["name"]], case["nodeid"]
    for name, origin in data["product_module_origins"].items():
        relative = "src/" + origin["path"]
        assert relative in run.before["files"], (name, relative)
        assert origin["sha256"] == run.before["files"][relative]["sha256"], name
    record = {
        "snapshot": path.name, "actual_cases": data["cases"],
        "product_module_origins": data["product_module_origins"],
        "all_functions_match_unchanged_prepared_source": True,
        "all_loaded_product_modules_match_immutable_source": True,
        "qualification_complete": False,
    }
    write_json(REPORT / (path.stem + "-source-binding.json"), record)
    return data


def main() -> int:
    run = Run("rsp100-four-serial-dependency-witnesses")
    errors, results = [], {}
    env, primary = None, None
    try:
        run.before = source_witness("before")
        functions = prepared_source()
        env, primary, _create_venv = prepare_environment(run)
        collection, _ = run_pytest(run, env, primary, "witness-collection")
        assert len(collected(collection)["cases"]) == 4
        bind_origins(run, collection, functions)
        snapshot, junit = run_pytest(run, env, primary, "witness-execution", prior=collection)
        bind_origins(run, snapshot, functions)
        results["four_witnesses"] = execution(snapshot, collection, junit, no_skips=True)
    except BaseException as error:
        errors.append(repr(error))
    finally:
        if env is not None and primary is not None:
            try:
                finish_environment(run, env, primary)
            except BaseException as error:
                errors.append("Environment finalizer: " + repr(error))
        write_json(REPORT / "witness-results.json", {
            "results": results, "errors": errors, "expected_cases": 4,
            "all_four_original_assertion_bodies_unchanged": True,
            "serial_test_process": True, "selected_B_changed": False,
            "negative_control_is_intentionally_unsound": True,
            "negative_control_divergence_assertions_preserved": True,
            "optimization_selected": False, "performance_run": False,
            "historical_E_F_campaigns_imported": False, "qualification_complete": False,
        })
    run.error = "; ".join(errors) if errors else None
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
