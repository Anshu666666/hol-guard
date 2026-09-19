"""Retain exact AST/tokens and verify the original Mac admission remains intact."""

from __future__ import annotations

import ast
import copy
import io
import json
import sys
import tokenize
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, REPORT, SOURCE, digest, git, write_json


class ImportGroups(ast.NodeTransformer):
    """Normalize only adjacent import statements and aliases; preserve every other AST node."""

    def generic_visit(self, node):
        node = super().generic_visit(node)
        for field, value in ast.iter_fields(node):
            if not isinstance(value, list) or not value or not all(isinstance(item, ast.stmt) for item in value):
                continue
            result, group = [], []

            def flush():
                result.extend(sorted(group, key=lambda item: ast.dump(item, include_attributes=False)))
                group.clear()

            for item in value:
                if isinstance(item, (ast.Import, ast.ImportFrom)):
                    for alias in item.names:
                        single = copy.deepcopy(item)
                        single.names = [copy.deepcopy(alias)]
                        group.append(single)
                else:
                    flush()
                    result.append(item)
            flush()
            setattr(node, field, result)
        return node


def snapshot(label: str) -> dict[str, object]:
    summary = {}
    for relative in CONFIG["python_files"]:
        data = (SOURCE / relative).read_bytes()
        tree = ast.parse(data, filename=relative)
        normalized = ImportGroups().visit(copy.deepcopy(tree))
        raw_ast = ast.dump(tree, include_attributes=False, indent=2) + "\n"
        normalized_ast = ast.dump(normalized, include_attributes=False, indent=2) + "\n"
        constants = [ast.dump(node, include_attributes=False) for node in ast.walk(tree)
                     if isinstance(node, ast.Constant)]
        tokens = [{"type": token.type, "name": tokenize.tok_name[token.type], "string": token.string,
                   "start": list(token.start), "end": list(token.end), "line": token.line}
                  for token in tokenize.tokenize(io.BytesIO(data).readline)]
        target = REPORT / "syntax" / label / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.with_suffix(".ast.txt").write_text(raw_ast)
        target.with_suffix(".normalized-ast.txt").write_text(normalized_ast)
        write_json(target.with_suffix(".tokens.json"), tokens)
        write_json(target.with_suffix(".literals.json"), constants)
        summary[relative] = {
            "source_sha256": digest(data), "ast_sha256": digest(raw_ast.encode()),
            "import_normalized_ast_sha256": digest(normalized_ast.encode()),
            "tokens_sha256": digest(target.with_suffix(".tokens.json").read_bytes()),
            "literals_sha256": digest(target.with_suffix(".literals.json").read_bytes()),
        }
    write_json(REPORT / ("syntax-" + label + ".json"), summary)
    return summary


def equivalence() -> None:
    before = json.loads((REPORT / "syntax-before.json").read_text())
    after = snapshot("after")
    comparisons = {}
    for path in CONFIG["python_files"]:
        comparisons[path] = {
            "raw_ast_identical": before[path]["ast_sha256"] == after[path]["ast_sha256"],
            "import_normalized_ast_identical": (
                before[path]["import_normalized_ast_sha256"] == after[path]["import_normalized_ast_sha256"]),
            "literal_values_identical": before[path]["literals_sha256"] == after[path]["literals_sha256"],
            "token_records_identical": before[path]["tokens_sha256"] == after[path]["tokens_sha256"],
            "source_bytes_identical": before[path]["source_sha256"] == after[path]["source_sha256"],
        }
    result = {"files": comparisons, "normalization": "adjacent import groups and import aliases only",
              "all_normalized_asts_equal": all(row["import_normalized_ast_identical"] for row in comparisons.values()),
              "all_literal_values_equal": all(row["literal_values_identical"] for row in comparisons.values()),
              "exact_token_records_retained": True, "semantic_equivalence_claim": False}
    write_json(REPORT / "format-equivalence.json", result)
    assert result["all_normalized_asts_equal"] and result["all_literal_values_equal"], result


def driver_ast(data: bytes):
    tree = ast.parse(data)
    values = []
    body = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "SOURCES"
                                               for target in node.targets):
            values.append(ast.literal_eval(node.value))
        else:
            body.append(node)
    assert len(values) == 1
    tree.body = body
    return ast.dump(tree, include_attributes=False), values[0]


def embedded(step):
    lines = step["run"].splitlines()
    assert lines[0] == "python3 -I - <<'PY'" and lines[-1] == "PY"
    return ast.parse("\n".join(lines[1:-1]))


def preservation() -> None:
    import yaml

    driver = "scripts/ci/native_macos_resolver_path.py"
    prior = git("show", CONFIG["source_parent"] + ":" + driver)
    current = (SOURCE / driver).read_bytes()
    assert digest(current) == CONFIG["changed_files"][driver]
    old_ast, old_sources = driver_ast(prior)
    new_ast, new_sources = driver_ast(current)
    additions = [path for path in new_sources if path not in old_sources]
    assert len(additions) == 9 and tuple(path for path in new_sources if path not in additions) == old_sources
    assert old_ast == new_ast
    reconstructed = current
    for path in additions:
        line = ('    "' + path + '",\n').encode()
        assert reconstructed.count(line) == 1, path
        reconstructed = reconstructed.replace(line, b"")
    assert reconstructed == prior
    for path, expected in CONFIG["preserved_files"].items():
        data = (SOURCE / path).read_bytes()
        assert digest(data) == expected and data == git("show", CONFIG["source_parent"] + ":" + path), path
    for path in new_sources:
        if path.endswith(".py"):
            ast.parse((SOURCE / path).read_bytes(), filename=path)
    workflow = ".github/workflows/native-macos-resolver-path.yml"
    workflow_bytes = (SOURCE / workflow).read_bytes()
    assert digest(workflow_bytes) == CONFIG["changed_files"][workflow]
    previous = yaml.safe_load(git("show", CONFIG["source_parent"] + ":" + workflow))
    current_workflow = yaml.safe_load(workflow_bytes)
    old_steps = previous["jobs"]["resolver-path"]["steps"]
    new_steps = current_workflow["jobs"]["resolver-path"]["steps"]
    key = lambda step: step.get("name", step.get("uses"))
    old_keys, new_keys = list(map(key, old_steps)), list(map(key, new_steps))
    assert [name for name in new_keys if name in old_keys] == old_keys
    added = [name for name in new_keys if name not in old_keys]
    assert len(old_steps) == 17 and len(added) == 4
    finite = [path for path in additions if path.startswith("tests/") and "forwarding" not in path]
    environment = {"PHASE_ADMISSION_OUTCOME", "PHASE_FORWARDING_OUTCOME", "PHASE_BUILD_OUTCOME", "PHASE_LOOKUP_OUTCOME"}
    keywords = {"phase_admission_outcome", "phase_forwarding_outcome", "phase_build_outcome",
                "phase_lookup_outcome", "phase_build_boundary"}
    for before in old_steps:
        after = copy.deepcopy(next(step for step in new_steps if key(step) == key(before)))
        if before.get("name") == "Validate finite parser and direct-child controls":
            normalized = after["run"]
            for path in finite:
                assert normalized.count(path) == 1
                normalized = normalized.replace(path, "")
            assert normalized.split() == before["run"].split()
            after["run"] = before["run"]
        if before.get("name") == "Retain normalized job outcome after failure":
            assert environment <= set(after["env"])
            for name in environment:
                after["env"].pop(name)
            tree = embedded(after)
            removed = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    removed.extend(item.arg for item in node.keywords if item.arg in keywords)
                    node.keywords = [item for item in node.keywords if item.arg not in keywords]
            assert len(removed) == 5 and set(removed) == keywords
            loops = [node for node in tree.body if isinstance(node, ast.For)
                     and isinstance(node.target, ast.Name) and node.target.id == "prefix"]
            assert len(loops) == 1 and ast.literal_eval(loops[0].iter) == ("phase-probe", "phase-bridge")
            tree.body.remove(loops[0])
            assert ast.dump(tree, include_attributes=False) == ast.dump(embedded(before), include_attributes=False)
            after["run"] = before["run"]
        assert after == before, key(before)
    normalized = copy.deepcopy(current_workflow)
    normalized["jobs"]["resolver-path"]["steps"] = copy.deepcopy(old_steps)
    trigger = "on" if "on" in normalized else True
    for pattern in ("scripts/ci/native_macos_dnssd_phase_*", "tests/test_native_macos_dnssd_phase*"):
        assert normalized[trigger]["push"]["paths"].count(pattern) == 1
        normalized[trigger]["push"]["paths"].remove(pattern)
    assert normalized == previous
    parsed = [step["name"] for step in new_steps if step.get("run", "").startswith("python3 -I - <<'PY'")
              and isinstance(embedded(step), ast.Module)]
    assert len(parsed) == 2
    write_json(REPORT / "original-admission-preserved.json", {
        "public_parent": CONFIG["source_parent"], "driver_sha256": digest(current),
        "original_driver_sha256": digest(prior), "driver_reconstructed_byte_for_byte": True,
        "driver_ast_except_sources_unchanged": True, "source_closure": list(new_sources),
        "preserved_files": CONFIG["preserved_files"], "original_steps": old_keys, "added_steps": added,
        "workflow_sha256": digest(workflow_bytes), "original_steps_preserved_except_explicit_additions": True,
        "parsed_embedded_python_steps": parsed, "native_qualification_credit": False,
    })


if __name__ == "__main__":
    if sys.argv[1] == "before":
        snapshot("before")
    elif sys.argv[1] == "after":
        equivalence()
    elif sys.argv[1] == "preservation":
        preservation()
    else:
        raise SystemExit(64)
