"""Five inert controls for the one source-bound TypeIgnore relocation."""

from __future__ import annotations

import ast
import hashlib

import type_ignore_bridge as bridge

BEFORE_SHA256 = "bd2ad3e73a17ea44acf39de95dde66ae520af27421655fcd403dd39650809734"
AFTER_SHA256 = "cf9de5bfa3a72c505e0a1608caa9935a4436dfbc4e940f314af211f46b1f6d3b"
COMMENT = b"# type: ignore[arg-type]"
CALL = b'launch.measure_native_phases(tmp_path / "runtime", count, tmp_path / "journal")'
ASSERTION = b'    assert not control.events and not (tmp_path / "journal").exists()'
FIELD_REFUSAL = "Only the pinned TypeIgnore field may differ"
OWNER_REFUSAL = "Type-ignore must remain on its single-line expression statement"
EXPECTED_CASES = (
    "actual_pair_accepts",
    "changed_ignore_tag_refused",
    "changed_call_body_refused",
    "extra_ignore_refused",
    "same_line_assert_owner_refused",
)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def replace_once(raw: bytes, old: bytes, new: bytes) -> bytes:
    assert raw.count(old) == 1, "The control must change one exact source occurrence"
    return raw.replace(old, new, 1)


def tree(raw: bytes) -> ast.Module:
    return ast.parse(raw.decode("utf-8"), filename=bridge.RELATIVE, type_comments=True)


def mutations(after: bytes) -> list[tuple[str, bytes, str, dict]]:
    tag = replace_once(after, COMMENT, b"# type: ignore[assignment]")
    body = replace_once(after, CALL, CALL.replace(b", count,", b", count + 0,"))
    extra = replace_once(after, ASSERTION + b"\n", ASSERTION + b"  " + COMMENT + b"\n")

    # Removing this earlier blank line puts the old Expr on 173 and Assert on
    # 174. Moving only the ignore to that Assert then preserves the valid
    # after tree, including TypeIgnore.lineno/tag, but changes its attachment.
    lines = after.splitlines(keepends=True)
    assert lines[1] == b"\n" and len(lines) == 175
    assert lines[173] == b"        " + CALL + b"  " + COMMENT + b"\n"
    assert lines[174] == ASSERTION + b"\n"
    del lines[1]
    assert lines[172] == b"        " + CALL + b"  " + COMMENT + b"\n"
    assert lines[173] == ASSERTION + b"\n"
    lines[172] = b"        " + CALL + b"\n"
    lines[173] = ASSERTION + b"  " + COMMENT + b"\n"
    wrong_owner = b"".join(lines)
    valid_tree, wrong_tree = tree(after), tree(wrong_owner)
    assert ast.dump(valid_tree, include_attributes=False) == ast.dump(
        wrong_tree, include_attributes=False
    ), "Wrong-owner control must preserve every location-free AST field"
    assert len(wrong_tree.type_ignores) == 1
    assert (wrong_tree.type_ignores[0].lineno, wrong_tree.type_ignores[0].tag) == (
        174,
        "[arg-type]",
    )
    owners = [
        node for node in ast.walk(wrong_tree)
        if isinstance(node, ast.stmt) and node.lineno == node.end_lineno == 174
    ]
    assert len(owners) == 1 and isinstance(owners[0], ast.Assert)
    assert wrong_owner.count(COMMENT) == 1
    assert digest(wrong_owner) != digest(after)
    assert len(tree(extra).type_ignores) == 2

    return [
        ("changed_ignore_tag_refused", tag, FIELD_REFUSAL, {"one_exact_tag_changed": True}),
        ("changed_call_body_refused", body, FIELD_REFUSAL, {"one_exact_call_changed": True}),
        ("extra_ignore_refused", extra, FIELD_REFUSAL, {"two_type_ignores": True}),
        (
            "same_line_assert_owner_refused",
            wrong_owner,
            OWNER_REFUSAL,
            {
                "complete_location_free_ast_equals_valid_after": True,
                "same_single_tag_and_line_174": True,
                "owner_is_following_assert": True,
                "original_expression_now_on_line_173": True,
            },
        ),
    ]


def evidence_summary(evidence: dict) -> dict:
    assert isinstance(evidence["complete_before_ast"], str)
    assert isinstance(evidence["complete_after_ast"], str)
    assert evidence["complete_before_ast"] and evidence["complete_after_ast"]
    assert evidence["raw_ast_hashes"] == {
        "before": digest(evidence["complete_before_ast"].encode("utf-8")),
        "after": digest(evidence["complete_after_ast"].encode("utf-8")),
    }
    return {
        "complete_raw_asts_populated_before_admission": True,
        "raw_ast_hashes": evidence["raw_ast_hashes"],
        "raw_ast_differences": evidence["raw_ast_differences"],
    }


def run_controls(before: bytes, after: bytes) -> dict:
    assert digest(before) == BEFORE_SHA256 and digest(after) == AFTER_SHA256
    prepared = mutations(after)
    cases = [("actual_pair_accepts", after, None, {"exact_pinned_pair": True}), *prepared]
    assert tuple(case[0] for case in cases) == EXPECTED_CASES
    rows = []
    for name, current, expected_refusal, preconditions in cases:
        evidence: dict = {}
        row = {
            "name": name,
            "passed": False,
            "before_sha256": digest(before),
            "after_sha256": digest(current),
            "after_bytes": len(current),
            "preconditions": preconditions,
        }
        try:
            if expected_refusal is None:
                result = bridge.structural_contract(before, current, evidence=evidence)
                assert result is evidence
                assert result["all_other_ast_fields_exact"] is True
                assert result["all_non_layout_raw_tokens_equal"] is True
                assert result["exact_type_ignore_tag_and_statement_attachment_equal"] is True
                row["observed"] = "accepted"
            else:
                try:
                    bridge.structural_contract(before, current, evidence=evidence)
                except AssertionError as error:
                    # An unrelated parse/runtime error is not a valid refusal.
                    message = str(error)
                    assert expected_refusal in message, ("Unexpected refusal", message)
                    row["observed"] = "refused"
                    row["refusal"] = {"type": type(error).__name__, "message": message}
                else:
                    raise AssertionError("The targeted invalid mutation was accepted")
            row["source_evidence"] = evidence_summary(evidence)
            row["passed"] = True
        except Exception as error:
            row["error"] = {"type": type(error).__name__, "message": str(error)}
            if "raw_ast_hashes" in evidence:
                row["raw_ast_hashes"] = evidence["raw_ast_hashes"]
                row["raw_ast_differences"] = evidence["raw_ast_differences"]
        rows.append(row)
    return {
        "passed": len(rows) == 5 and all(row["passed"] for row in rows),
        "case_count": len(rows),
        "expected_cases": list(EXPECTED_CASES),
        "before_sha256": digest(before),
        "after_sha256": digest(after),
        "scope": "Five inert AST/comment controls; no product imports or body execution.",
        "cases": rows,
    }
