"""Bind reviewed repairs and historical cases before fresh affected-case execution."""

from __future__ import annotations

import ast
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import sys
import textwrap
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HERE, REPORT, SOURCE, sha256, write_json

FIELDS = ("git_blob", "sha256", "bytes", "mode")


def dump(node: ast.AST) -> str:
    return ast.dump(node, include_attributes=False)


def pinned_json(field: str) -> dict:
    expected = CONFIG[field]
    raw = (HERE / expected["path"]).read_bytes()
    assert len(raw) == expected["bytes"] and sha256(raw) == expected["sha256"], field
    assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == expected["git_blob"]
    return json.loads(raw)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def git_tree(files: dict) -> str:
    root = {}
    for path, record in files.items():
        parts = path.split("/")
        directory = root
        for part in parts[:-1]:
            directory = directory.setdefault(part, {})
        assert parts[-1] not in directory
        directory[parts[-1]] = (record["mode"], record["git_blob"])

    def encode(directory):
        body = bytearray()
        entries = sorted(directory.items(), key=lambda item: (
            item[0] + ("/" if isinstance(item[1], dict) else "")).encode("utf-8"))
        for name, value in entries:
            mode, identity = ("40000", encode(value)) if isinstance(value, dict) else value
            body.extend(mode.encode() + b" " + name.encode("utf-8") + b"\0" + bytes.fromhex(identity))
        return hashlib.sha1(b"tree " + str(len(body)).encode() + b"\0" + body).hexdigest()

    return encode(root)


def definition(parsed: ast.Module, record: dict, *, original: bool = False) -> ast.FunctionDef:
    # Every function/fixture in this source-bound original collection is module-level.
    assert "." not in record["qualname"], record["qualname"]
    matches = [node for node in parsed.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name == record["qualname"]]
    assert len(matches) == 1, (record["path"], record["qualname"])
    node = matches[0]
    if original:
        assert min([node.lineno, *(item.lineno for item in node.decorator_list)]) == record["first_line"]
        assert node.end_lineno == record["definition_end_line"]
        assert sha256(dump(node).encode()) == record["complete_definition_ast_sha256"]
    return node


def current_record(record: dict, modules: dict) -> dict:
    result = copy.deepcopy(record)
    if record["origin"] == "candidate":
        raw, parsed = modules[record["path"]]
        node = definition(parsed, record)
        result.update(
            sha256=sha256(raw), first_line=min([node.lineno, *(item.lineno for item in node.decorator_list)]),
            definition_end_line=node.end_lineno, complete_definition_ast_sha256=sha256(dump(node).encode()))
    else:
        assert record["origin"] == "owned_dependency"
    return result


def original_rows(prior: dict) -> dict:
    for collection in ("functions", "fixture_definitions"):
        assert all(sha256(canonical(record)) == key for key, record in prior[collection].items())
    assert len(prior["complete_definition_asts"]) == 126
    assert all(sha256(value.encode()) == key for key, value in prior["complete_definition_asts"].items())
    rows = {}
    for cohort in prior["cohorts"]:
        assert cohort["collection_admitted"] is True
        assert len(cohort["rows"]) == cohort["expected_cases"]
        for entry in cohort["rows"]:
            row = copy.deepcopy(entry)
            row["function"] = prior["functions"][row.pop("function_ref")]
            row["fixtures"] = {name: [prior["fixture_definitions"][key] for key in keys]
                               for name, keys in row.pop("fixture_refs").items()}
            assert row["nodeid"] not in rows
            rows[row["nodeid"]] = row
    assert len(rows) == 169
    return rows


def product_bridges(repair: dict, modules: dict, originals: dict) -> dict:
    writer = "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py"
    witness = "scripts/native_slo_mixed_witness.py"
    gate = "scripts/ci/native_receipt_persistence_gate.py"
    assert dump(originals[writer][1]) == dump(modules[writer][1])
    expected = copy.deepcopy(originals[witness][1])
    assert isinstance(expected.body[0], ast.Expr) and isinstance(expected.body[0].value, ast.Constant)
    assert isinstance(expected.body[0].value.value, str)
    expected.body[0].value.value = modules[witness][1].body[0].value.value
    assert dump(expected) == dump(modules[witness][1])
    edits = [entry for entry in repair["exact_edits"] if entry["path"] == gate]
    assert len(edits) == 1
    old_if = ast.parse(textwrap.dedent(edits[0]["before"])).body[0]
    new_if = ast.parse(textwrap.dedent(edits[0]["after"])).body[0]
    assert isinstance(old_if, ast.If) and not old_if.orelse and len(old_if.body) == 1
    inner = old_if.body[0]
    assert isinstance(inner, ast.If) and not inner.orelse
    assert isinstance(old_if.test, ast.BoolOp) and isinstance(old_if.test.op, ast.And)
    assert isinstance(new_if.test, ast.BoolOp) and isinstance(new_if.test.op, ast.And)
    assert [dump(value) for value in new_if.test.values] == [
        *(dump(value) for value in old_if.test.values), dump(inner.test)]
    assert [dump(value) for value in new_if.body] == [dump(value) for value in inner.body]
    assert not new_if.orelse

    class ExactIf(ast.NodeTransformer):
        replaced = 0

        def visit_If(self, node):
            if dump(node) == dump(old_if):
                self.replaced += 1
                return copy.deepcopy(new_if)
            return self.generic_visit(node)

    transformer = ExactIf()
    transformed = transformer.visit(copy.deepcopy(originals[gate][1]))
    assert transformer.replaced == 1 and dump(transformed) == dump(modules[gate][1])
    return {"writer_complete_ast_equal": True, "witness_only_module_docstring_changed": True,
            "gate_exact_short_circuit_order_and_body_preserved": True,
            "other_production_files_byte_unchanged": True,
            "scope": "These exact admitted edits only; no general semantic-equivalence claim."}


def test_module_bridges(modules: dict, originals: dict, selected: dict) -> dict:
    output = {}
    queue = "tests/test_guard_runtime_hook_evidence_queue_observation.py"
    vfs = "tests/test_native_slo_sqlite_vfs.py"
    extra = "_assert_test_owns_last_record_reference"
    for path in sorted(name for name in modules if name.startswith("tests/")):
        old, new = originals[path][1], modules[path][1]
        allowed = {row["function"]["qualname"] for row in selected.values()
                   if row["function"]["path"] == path}
        if path == queue:
            allowed |= {"_command", extra}
        is_function = lambda node: isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        before = {node.name: node for node in old.body if is_function(node)}
        after = {node.name: node for node in new.body if is_function(node)}
        assert len(before) == sum(is_function(node) for node in old.body)
        assert len(after) == sum(is_function(node) for node in new.body)
        assert set(after) == set(before) | ({extra} if path == queue else set())
        changed = []
        for name, node in before.items():
            if dump(node) != dump(after[name]):
                assert name in allowed, (path, name)
                changed.append(name)
                left, right = copy.deepcopy(node), copy.deepcopy(after[name])
                left.body = right.body = []
                assert dump(left) == dump(right), (path, name, "signature/decorator drift")
        is_import = lambda node: isinstance(node, (ast.Import, ast.ImportFrom))
        old_imports = [dump(node) for node in old.body if is_import(node)]
        new_imports = [dump(node) for node in new.body if is_import(node)]
        if path == queue:
            weak = dump(ast.parse("import weakref").body[0])
            system = dump(ast.parse("import sys").body[0])
            assert old_imports.count(weak) == 1 and new_imports.count(system) == 1
            assert system not in old_imports and weak not in new_imports
            assert [item for item in old_imports if item != weak] == [
                item for item in new_imports if item != system]
        elif path == vfs:
            shlex = dump(ast.parse("import shlex").body[0])
            shutil = dump(ast.parse("import shutil").body[0])
            expected = list(old_imports)
            first, second = expected.index(shutil), expected.index(shlex)
            assert second == first + 1
            expected[first], expected[second] = expected[second], expected[first]
            assert expected == new_imports
        else:
            assert old_imports == new_imports
        rest = lambda tree: [dump(node) for node in tree.body if not is_function(node) and not is_import(node)]
        assert rest(old) == rest(new), path
        output[path] = {"changed_definitions": changed, "all_other_definitions_equal": True,
                        "signatures_and_decorators_equal": True, "module_binding_changes_admitted": True}
    return output


def prove() -> dict:
    assert sys.flags.isolated and sys.dont_write_bytecode and __debug__
    assert sys.argv[1:] == [] and sys.version.split()[0] == CONFIG["python_version"]
    observed = json.loads((REPORT / "source-before.json").read_bytes())
    original = pinned_json("original_source_before")
    prior, repair = pinned_json("original_case_contract"), pinned_json("repair_proposal")
    assert observed["source_sha"] == CONFIG["source_sha"] and observed["source_tree"] == CONFIG["source_tree"]
    assert original["source_sha"] == prior["source_sha"] == repair["source_parent"] == CONFIG["source_parent"]
    assert original["source_tree"] == prior["source_tree"] == repair["parent_tree"] == CONFIG["source_parent_tree"]
    assert prior["harness_sha"] == CONFIG["original_run"]["harness_sha"]
    assert (prior["run"], prior["attempt"], prior["job"]) == (35451397989, 1, 105919067104)
    assert prior["original_counts"] == CONFIG["original_run"]["counts"]
    assert prior["source_map_original_frame"]["original_sha256"] == CONFIG["original_source_before"]["sha256"]
    before, current = original["files"], observed["files"]
    assert len(before) == len(current) == CONFIG["tracked_files"] == 4560 and set(before) == set(current)
    assert git_tree(before) == CONFIG["source_parent_tree"] and git_tree(current) == CONFIG["source_tree"]
    changes = {row["path"]: row for row in repair["files"]}
    assert len(changes) == 7 and len(repair["exact_edits"]) == 29
    assert {path for path in before if before[path] != current[path]} == set(changes)
    original_raw = {}
    for path, row in changes.items():
        old, new = row["before"], row["after"]
        assert before[path] == {key: old[key] for key in FIELDS}
        assert current[path] == dict(git_blob=new["git_blob"], sha256=new["sha256"],
                                     bytes=new["bytes"], mode=row["mode"])
        raw = (SOURCE / path).read_bytes()
        assert raw == new["content"].encode() and sha256(raw) == new["sha256"]
        inverted = raw.decode()
        for edit in reversed([entry for entry in repair["exact_edits"] if entry["path"] == path]):
            offset = edit["offset"]
            assert inverted[offset:offset + len(edit["after"])] == edit["after"], path
            inverted = inverted[:offset] + edit["before"] + inverted[offset + len(edit["after"]):]
        assert inverted == old["content"] and sha256(inverted.encode()) == old["sha256"]
        original_raw[path] = inverted.encode()
    rows = original_rows(prior)
    outcomes = {row["nodeid"]: row for row in prior["original_cases"]}
    assert len(outcomes) == len(prior["original_cases"]) == 169 and set(outcomes) == set(rows)
    assert Counter(row["outcome"] for row in outcomes.values()) == {"passed": 157, "failed": 12}
    target = {row["nodeid"]: row for row in CONFIG["selected_original_cases"]}
    assert len(target) == 17 and set(target) <= set(rows)
    assert Counter(outcomes[node]["outcome"] for node in target) == {"failed": 12, "passed": 5}
    assert all(outcomes[node]["outcome"] == row["original_outcome"] for node, row in target.items())
    assert {node for node in rows if outcomes[node]["outcome"] == "failed"} <= set(target)
    retained = set(rows) - set(target)
    assert len(retained) == 152
    for node in retained:
        entry = outcomes[node]
        assert entry["outcome"] == entry["junit"]["outcome"] == "passed"
        assert [phase["when"] for phase in entry["phases"]] == ["setup", "call", "teardown"]
        assert all(phase["outcome"] == "passed" for phase in entry["phases"])
    functions = [row["function"] for row in rows.values()]
    functions += [value["source"] for value in prior["fixture_definitions"].values()]
    paths = {record["path"] for record in functions if record["origin"] == "candidate"}
    paths |= set(CONFIG["format_paths"])
    modules, originals = {}, {}
    for path in sorted(paths):
        raw = (SOURCE / path).read_bytes()
        assert sha256(raw) == current[path]["sha256"]
        old = original_raw.get(path, raw)
        assert sha256(old) == before[path]["sha256"]
        modules[path] = (raw, ast.parse(raw.decode(), filename=str(SOURCE / path), type_comments=True))
        originals[path] = (old, ast.parse(old.decode(), filename=path, type_comments=True))
        if path in CONFIG["format_paths"]:
            assert len(raw.decode().splitlines()) <= 500
    for record in functions:
        assert record["complete_definition_ast_sha256"] in prior["complete_definition_asts"]
        if record["origin"] == "candidate":
            assert record["sha256"] == before[record["path"]]["sha256"]
            definition(originals[record["path"]][1], record, original=True)
    command_users, weakref_users = [], []
    for node, row in rows.items():
        record = row["function"]
        old = definition(originals[record["path"]][1], record, original=True)
        new = definition(modules[record["path"]][1], record)
        if node in retained:
            assert dump(old) == dump(new), node
        if any(isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
               and item.id == "_command" for item in ast.walk(old)):
            command_users.append(node)
        if any(isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
               and item.id == "weakref" for item in ast.walk(old)):
            weakref_users.append(node)
        assert not any(isinstance(item, ast.Attribute) and item.attr == "_command" for item in ast.walk(old))
    assert len(command_users) == 11 and len(weakref_users) == 4
    assert set(command_users) | set(weakref_users) <= set(target)
    assert all(outcomes[node]["outcome"] == "failed" for node in command_users + weakref_users)
    for fixture in prior["fixture_definitions"].values():
        record = fixture["source"]
        if record["origin"] == "candidate":
            assert dump(definition(originals[record["path"]][1], record, original=True)) == dump(
                definition(modules[record["path"]][1], record))
    selected = {node: rows[node] for node in target}
    # The changed private helper has no unselected helper/global forwarding path.
    for path, (_, parsed) in originals.items():
        allowed_names = {row["function"]["qualname"] for row in selected.values()
                         if row["function"]["path"] == path}
        for statement in parsed.body:
            loads = [item for item in ast.walk(statement) if isinstance(item, ast.Name)
                     and isinstance(item.ctx, ast.Load) and item.id == "_command"]
            if loads:
                assert isinstance(statement, ast.FunctionDef) and statement.name in allowed_names, path
    bindings = test_module_bridges(modules, originals, selected)
    products = product_bridges(repair, modules, originals)
    origin_count = 0
    for cohort in prior["cohorts"]:
        for record in cohort["original_source_origins"].values():
            assert before[record["path"]]["sha256"] == record["sha256"]
            assert before[record["path"]] == current[record["path"]] or record["path"] in changes
            origin_count += 1
    expected = {}
    for cohort in CONFIG["cohorts"]:
        cohort_rows = []
        for node in cohort["selectors"]:
            assert target[node]["cohort"] == cohort["name"]
            row = copy.deepcopy(rows[node])
            row["function"] = current_record(row["function"], modules)
            for chain in row["fixtures"].values():
                for fixture in chain:
                    fixture["source"] = current_record(fixture["source"], modules)
            cohort_rows.append(row)
        assert len(cohort_rows) == cohort["expected_cases"]
        expected[cohort["name"]] = cohort_rows
    assert sum(map(len, expected.values())) == CONFIG["expected_total_cases"] == 17
    assert CONFIG["compile_controls"] == []
    assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                   for name in sys.modules)
    return {"passed": True, "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "whole_source_seven_file_inverse": True, "unchanged_other_files": 4553,
            "original_run": CONFIG["original_run"], "original_case_outcomes": [
                {"nodeid": node, "outcome": outcomes[node]["outcome"]} for node in rows],
            "retained_prior_passing_cases": sorted(retained), "retained_prior_case_ast_equal": True,
            "candidate_fixture_definition_asts_equal": True, "current_test_module_bridges": bindings,
            "current_product_bridges": products, "original_source_origin_records_rebound": origin_count,
            "actual_original_command_helper_users": command_users, "actual_original_weakref_users": weakref_users,
            "expected_followup_collections": expected, "expected_fresh_cases": 17,
            "expected_prior_failures_selected": 12, "expected_changed_prior_passes_selected": 5,
            "current_python_files_parsed": sorted(paths), "project_imports": [],
            "qualification_complete": False, "fresh_169_case_execution": False,
            "retained_evidence_scope": "152 original passes with exact current source/provider/fixture bridges; "
                "not a new execution. Current owned dependency fixture bytes are a separate mandatory gate."}


def dependencies() -> dict:
    assert sys.flags.isolated and sys.dont_write_bytecode and __debug__
    assert sys.version.split()[0] == CONFIG["python_version"]
    assert sys.argv[1:] in (["--dependencies", "before"], ["--dependencies", "after"])
    admitted = json.loads((REPORT / "source-contract.json").read_bytes())
    assert admitted["passed"] is True and admitted["source_sha"] == CONFIG["source_sha"]
    prior = pinned_json("original_case_contract")
    root = Path(sys.prefix).resolve(strict=True)
    records = []
    for fixture in prior["fixture_definitions"].values():
        record = fixture["source"]
        if record["origin"] != "owned_dependency":
            continue
        path = root / record["path"]
        assert path.resolve(strict=True).is_relative_to(root) and not path.is_symlink()
        raw = path.read_bytes()
        assert sha256(raw) == record["sha256"]
        parsed = ast.parse(raw.decode(), filename=str(path), type_comments=True)
        definition(parsed, record, original=True)
        records.append(record)
    assert len(records) == 4 and len({record["path"] for record in records}) == 3
    assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                   for name in sys.modules)
    return {"passed": True, "source_sha": CONFIG["source_sha"], "fixture_records": records,
            "fixture_complete_file_and_ast_hashes_equal_to_original": True,
            "owned_interpreter": str(Path(sys.executable)), "python_version": sys.version.split()[0],
            "scope": "These four original fixture definitions in three owned pytest source files only.",
            "qualification_complete": False}


def main() -> int:
    result = {"passed": False, "source_sha": CONFIG["source_sha"], "qualification_complete": False}
    name = "source-contract.json"
    try:
        if sys.argv[1:]:
            assert sys.argv[1:] in (["--dependencies", "before"], ["--dependencies", "after"])
            name = "dependency-contract-" + sys.argv[2] + ".json"
            result = dependencies()
        else:
            result = prove()
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
    write_json(REPORT / name, result)
    print(json.dumps({"passed": result["passed"], "error": result.get("error")}, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
