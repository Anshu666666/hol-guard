"""Prove formatter changes preserve the complete parsed Python program and literals."""

from __future__ import annotations

import ast
import difflib
import hashlib
import io
import json
from pathlib import Path
import tokenize

LAYOUT = {
    tokenize.ENCODING, tokenize.ENDMARKER, tokenize.NL, tokenize.NEWLINE,
    tokenize.INDENT, tokenize.DEDENT,
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def syntax(raw: bytes, filename: str) -> ast.Module:
    return ast.parse(raw.decode("utf-8"), filename=filename, type_comments=True)


def dumped(node: ast.AST) -> str:
    return ast.dump(node, include_attributes=False)


def literal_values(tree: ast.AST) -> list[dict[str, str]]:
    return [
        {"type": type(node.value).__name__, "repr": repr(node.value), "kind": repr(node.kind)}
        for node in ast.walk(tree) if isinstance(node, ast.Constant)
    ]


def token_contract(raw: bytes, tree: ast.Module) -> dict[str, object]:
    tokens = list(tokenize.tokenize(io.BytesIO(raw).readline))
    meaningful = [token for token in tokens if token.type not in LAYOUT | {tokenize.COMMENT}]
    statements = [
        (index, node) for index, node in enumerate(ast.walk(tree)) if isinstance(node, ast.stmt)
    ]
    stable = []
    removed = []
    position_to_stable = {}
    for index, token in enumerate(meaningful):
        value = token.string
        if token.type == tokenize.OP and value in {"(", ")"}:
            removed.append({"kind": "parenthesis", "token": value, "start": token.start})
            continue
        if token.type == tokenize.OP and value == "," and index + 1 < len(meaningful):
            if meaningful[index + 1].type == tokenize.OP and meaningful[index + 1].string in {")", "]", "}"}:
                removed.append({"kind": "trailing_comma_before_close", "token": value, "start": token.start})
                continue
        if token.type == tokenize.STRING:
            # Parse the entire literal token, including any f-string expression structure.
            value = dumped(ast.parse(value, mode="eval"))
        position_to_stable[token.start] = len(stable)
        stable.append([token.type, value])
    comments = []
    for token in tokens:
        if token.type != tokenize.COMMENT:
            continue
        containing = [
            (node.end_lineno - node.lineno, index, node)
            for index, node in statements
            if node.lineno <= token.start[0] <= node.end_lineno
        ]
        owner = min(containing, key=lambda item: (item[0], -item[2].col_offset, item[1])) if containing else None
        previous = [
            (item.start, position_to_stable[item.start]) for item in meaningful
            if item.start in position_to_stable and item.end <= token.start
        ]
        following = [
            position_to_stable[item.start] for item in meaningful
            if item.start in position_to_stable and item.start >= token.end
        ]
        comments.append({
            "text": token.string,
            "previous_stable_token": previous[-1][1] if previous else None,
            "next_stable_token": following[0] if following else None,
            "statement_index": None if owner is None else owner[1],
            "statement_kind": None if owner is None else type(owner[2]).__name__,
            "inline": any(item.start[0] == token.start[0] and item.end <= token.start for item in meaningful),
        })
    return {
        "canonical_tokens": stable, "anchored_comments": comments, "removed_layout_punctuation": removed,
        "raw_tokens": [
            {"kind": tokenize.tok_name[token.type], "value": token.string,
             "start": token.start, "end": token.end}
            for token in tokens
        ],
    }


def prove(before: bytes, after: bytes, relative: str, evidence_root: Path) -> dict[str, object]:
    evidence = {"path": relative, "before_sha256": digest(before), "after_sha256": digest(after),
                "before_bytes": len(before), "after_bytes": len(after),
                "actual_imports_or_execution_performed": False, "passed": False}
    target = evidence_root / (relative + ".json")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        old, new = syntax(before, relative), syntax(after, relative)
        old_ast, new_ast = dumped(old), dumped(new)
        evidence["full_ast_sha256"] = {"before": digest(old_ast.encode()), "after": digest(new_ast.encode())}
        evidence["full_ast_equal_including_type_comments_and_type_ignore_line_fields"] = old_ast == new_ast
        evidence["ordered_literal_values"] = {"before": literal_values(old), "after": literal_values(new)}
        old_tokens, new_tokens = token_contract(before, old), token_contract(after, new)
        evidence["tokens"] = {"before": old_tokens, "after": new_tokens}
        evidence["canonical_tokens_equal"] = old_tokens["canonical_tokens"] == new_tokens["canonical_tokens"]
        evidence["comments_and_statement_token_anchors_equal"] = (
            old_tokens["anchored_comments"] == new_tokens["anchored_comments"]
        )
        evidence["text_diff"] = list(difflib.unified_diff(
            before.decode().splitlines(keepends=True), after.decode().splitlines(keepends=True),
            fromfile="before/" + relative, tofile="after/" + relative,
        ))
        assert evidence["full_ast_equal_including_type_comments_and_type_ignore_line_fields"], relative
        assert evidence["ordered_literal_values"]["before"] == evidence["ordered_literal_values"]["after"], relative
        assert evidence["canonical_tokens_equal"], relative
        assert evidence["comments_and_statement_token_anchors_equal"], relative
        # Parsing already proves balanced syntax; only parentheses and commas directly
        # before a closing delimiter were omitted from the otherwise exact token contract.
        evidence["passed"] = True
    except BaseException as error:
        evidence["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        target.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {key: value for key, value in evidence.items()
            if key not in {"tokens", "ordered_literal_values", "text_diff"}}
