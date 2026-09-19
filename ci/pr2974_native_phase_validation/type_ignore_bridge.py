"""Prove the sole pinned TypeIgnore line relocation without widening AST equality."""

from __future__ import annotations

import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tokenize

RELATIVE = "tests/test_native_slo_rust_phase_run.py"
BEFORE_SHA256 = "bd2ad3e73a17ea44acf39de95dde66ae520af27421655fcd403dd39650809734"
AFTER_SHA256 = "cf9de5bfa3a72c505e0a1608caa9935a4436dfbc4e940f314af211f46b1f6d3b"
BEFORE_LINE, AFTER_LINE = 160, 174
COMMENT = "# type: ignore[arg-type]"
TAG = "[arg-type]"
CALL = 'launch.measure_native_phases(tmp_path / "runtime", count, tmp_path / "journal")'
LAYOUT = {tokenize.ENCODING, tokenize.ENDMARKER, tokenize.NL, tokenize.NEWLINE,
          tokenize.INDENT, tokenize.DEDENT}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def field_differences(before, after, path: str = "$") -> list[dict]:
    if type(before) is not type(after):
        return [{"path": path, "before_type": type(before).__name__, "after_type": type(after).__name__}]
    if isinstance(before, ast.AST):
        old_fields, new_fields = list(ast.iter_fields(before)), list(ast.iter_fields(after))
        if [name for name, _ in old_fields] != [name for name, _ in new_fields]:
            return [{"path": path, "before_fields": [name for name, _ in old_fields],
                     "after_fields": [name for name, _ in new_fields]}]
        return [difference for (name, old), (_, new) in zip(old_fields, new_fields, strict=True)
                for difference in field_differences(old, new, path + "." + name)]
    if isinstance(before, list):
        if len(before) != len(after):
            return [{"path": path, "before_length": len(before), "after_length": len(after)}]
        return [difference for index, (old, new) in enumerate(zip(before, after, strict=True))
                for difference in field_differences(old, new, path + "[" + str(index) + "]")]
    return [] if before == after else [{"path": path, "before": repr(before), "after": repr(after)}]


def statement_paths(node: ast.AST, path: str = "$"):
    if isinstance(node, ast.stmt):
        yield path, node
    for field, value in ast.iter_fields(node):
        if isinstance(value, ast.AST):
            yield from statement_paths(value, path + "." + field)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                if isinstance(child, ast.AST):
                    yield from statement_paths(child, path + "." + field + "[" + str(index) + "]")


def attachment(raw: bytes, module: ast.Module, line: int) -> dict:
    source = raw.decode("utf-8")
    comments = [token for token in tokenize.tokenize(io.BytesIO(raw).readline)
                if token.type == tokenize.COMMENT and "type:" in token.string]
    assert len(comments) == 1 and comments[0].string == COMMENT, "Exact sole type-ignore comment"
    token = comments[0]
    assert token.start[0] == token.end[0] == line, "Pinned type-ignore line"
    owners = [(path, node) for path, node in statement_paths(module)
              if isinstance(node, ast.Expr) and node.lineno == node.end_lineno == line]
    assert len(owners) == 1, "Type-ignore must remain on its single-line expression statement"
    path, owner = owners[0]
    assert ast.get_source_segment(source, owner) == CALL, "Exact annotated call"
    assert source.splitlines()[line - 1] == "        " + CALL + "  " + COMMENT, "Exact inline attachment"
    assert token.start[1] == 8 + len(CALL) + 2
    return {"statement_path": path, "statement_kind": type(owner).__name__,
            "statement_ast": ast.dump(owner, include_attributes=False), "call_source": CALL,
            "comment": COMMENT, "tag": TAG, "line": line, "column": token.start[1]}


def structural_contract(before: bytes, after: bytes, *, evidence: dict | None = None) -> dict:
    retained = {} if evidence is None else evidence
    old = ast.parse(before.decode("utf-8"), filename=RELATIVE, type_comments=True)
    new = ast.parse(after.decode("utf-8"), filename=RELATIVE, type_comments=True)
    old_dump, new_dump = ast.dump(old, include_attributes=False), ast.dump(new, include_attributes=False)
    differences = field_differences(old, new)
    retained.update(complete_before_ast=old_dump, complete_after_ast=new_dump,
                    raw_ast_differences=differences,
                    raw_ast_hashes={"before": digest(old_dump.encode()), "after": digest(new_dump.encode())})
    expected = [{"path": "$.type_ignores[0].lineno", "before": "160", "after": "174"}]
    assert differences == expected, ("Only the pinned TypeIgnore field may differ", differences)
    assert len(old.type_ignores) == len(new.type_ignores) == 1
    assert (old.type_ignores[0].lineno, old.type_ignores[0].tag) == (BEFORE_LINE, TAG)
    assert (new.type_ignores[0].lineno, new.type_ignores[0].tag) == (AFTER_LINE, TAG)
    before_owner, after_owner = attachment(before, old, BEFORE_LINE), attachment(after, new, AFTER_LINE)
    assert {key: value for key, value in before_owner.items() if key != "line"} == {
        key: value for key, value in after_owner.items() if key != "line"
    }, "Original semantic statement attachment changed"
    normalized = copy.deepcopy(new)
    normalized.type_ignores[0].lineno = BEFORE_LINE
    normalized_dump = ast.dump(normalized, include_attributes=False)
    assert normalized_dump == old_dump, "Every remaining complete AST field must stay exact"
    def tokens(raw):
        return [(token.type, token.string) for token in tokenize.tokenize(io.BytesIO(raw).readline)
                if token.type not in LAYOUT]
    assert tokens(before) == tokens(after), "All non-layout raw tokens including comments must match"
    retained.update(complete_after_exact_field_relocation_ast=normalized_dump,
                    before_attachment=before_owner, after_attachment=after_owner,
                    all_other_ast_fields_exact=True, all_non_layout_raw_tokens_equal=True,
                    exact_type_ignore_tag_and_statement_attachment_equal=True)
    return retained


def prove_relocation(before: bytes, after: bytes, relative: str, strict: dict,
                     evidence_root: Path, here: Path, config: dict) -> dict:
    assert relative == RELATIVE and sys.version.split()[0] == "3.12.13"
    assert digest(before) == BEFORE_SHA256 and digest(after) == AFTER_SHA256
    target = evidence_root / (relative + ".type-ignore.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    evidence = {"path": relative, "before_sha256": digest(before), "after_sha256": digest(after),
                "python_version": sys.version, "passed": False, "qualification_complete": False,
                "original_strict_bridge_passed": False, "strict_failure_retained": True}
    try:
        original_raw = (here / "prior-type-ignore-failure.json").read_bytes()
        assert digest(original_raw) == config["prior_type_ignore_failure_sha256"]
        current_raw = (evidence_root / (relative + ".json")).read_bytes()
        assert current_raw == original_raw, "Retain the exact observed strict failure without rewriting it"
        original = json.loads(original_raw)
        assert original["passed"] is strict["passed"] is False
        assert original["full_ast_equal_including_type_comments_and_type_ignore_line_fields"] is False
        assert original["canonical_tokens_equal"] and original["comments_and_statement_token_anchors_equal"]
        assert original["ordered_literal_values"]["before"] == original["ordered_literal_values"]["after"]
        structural_contract(before, after, evidence=evidence)
        assert evidence["raw_ast_hashes"] == original["full_ast_sha256"]
        from type_ignore_bridge_controls import run_controls
        evidence["finite_bridge_controls"] = run_controls(before, after)
        assert evidence["finite_bridge_controls"]["passed"]
        evidence["passed"] = True
    except BaseException as error:
        evidence["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        target.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"path": relative, "before_sha256": digest(before), "after_sha256": digest(after),
            "passed": evidence["passed"], "proof_kind": "exact_pinned_type_ignore_statement_relocation",
            "strict_original_bridge": strict,
            "audited_type_ignore_relocation": {
                key: value for key, value in evidence.items()
                if key not in {"complete_before_ast", "complete_after_ast",
                               "complete_after_exact_field_relocation_ast"}
            }}
