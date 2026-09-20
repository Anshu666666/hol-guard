"""Produce reviewed formatter candidates without changing the immutable source."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tokenize
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, REPORT, SOURCE, write_json


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def vectors(text: str) -> dict:
    tree = ast.parse(text, type_comments=True)
    for node in ast.walk(tree):
        if isinstance(node, ast.TypeIgnore):
            node.lineno = 0
    tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    lexical = []
    comments = []
    literals = []
    ignored = {tokenize.ENCODING, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER}
    for token in tokens:
        if token.type == tokenize.COMMENT:
            comments.append(token.string)
        elif token.type == tokenize.STRING:
            try:
                value = repr(ast.literal_eval(token.string))
            except (ValueError, SyntaxError):
                value = token.string
            literals.append(value)
            lexical.append([token.type, value])
        elif token.type not in ignored and token.string not in {"(", ")", ","}:
            lexical.append([token.type, token.string])
    return {"ast": ast.dump(tree, include_attributes=False),
            "lexical_except_grouping_and_commas": lexical, "string_literals": literals, "comments": comments}


def vector_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def resolved_after_vectors(row: dict, index: int) -> dict:
    fields = {"ast", "lexical_except_grouping_and_commas", "string_literals", "comments"}
    before = row["before_vectors"]
    assert type(before) is dict and set(before) == fields
    reference = row.get("after_vectors_reference")
    if reference is None:
        assert "after_vectors_reference" not in row
        assert row["before"] != row["after"], "Identical source requires its exact vector reference"
        after = row["after_vectors"]
        assert type(after) is dict and set(after) == fields
        return after
    assert "after_vectors" not in row and type(reference) is dict
    assert set(reference) == {"file_index", "field", "bytes", "sha256"}
    assert type(reference["file_index"]) is int and reference["file_index"] == index
    assert reference["field"] == "before_vectors"
    assert row["before"].encode("utf-8") == row["after"].encode("utf-8")
    assert row["before_sha256"] == row["after_sha256"] == sha(row["before"].encode("utf-8"))
    raw = vector_bytes(before)
    assert type(reference["bytes"]) is int and reference["bytes"] == len(raw)
    assert reference["sha256"] == sha(raw)
    return before


def main() -> int:
    result = {"schema": "pr2974-immutable-formatter-proposals.v2",
              "source_sha": CONFIG["source_sha"], "files": [], "source_writes_requested": False,
              "source_format_check_result_unchanged": True, "qualification_complete": False,
              "vector_reference_schema": "same_file_index.before_vectors.exact_source_bytes.v1"}
    for index, relative in enumerate(CONFIG["python_source_paths"]):
        row = {"path": relative, "passed": False}
        result["files"].append(row)
        try:
            source = SOURCE / relative
            before = source.read_bytes()
            assert sha(before) == CONFIG["source_inputs"][relative]
            process = subprocess.run(
                [sys.executable, "-I", "-B", "-m", "ruff", "format", "--stdin-filename", relative, "-"],
                input=before, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=SOURCE, timeout=30, check=False,
            )
            row.update(returncode=process.returncode, stderr=process.stderr.decode("utf-8"),
                       before=before.decode("utf-8"), after=process.stdout.decode("utf-8"),
                       before_sha256=sha(before), after_sha256=sha(process.stdout))
            assert process.returncode == 0
            assert len(process.stdout) <= 2 * 1024 * 1024
            row["before_vectors"] = vectors(row["before"])
            if before == process.stdout:
                encoded_vectors = vector_bytes(row["before_vectors"])
                row["after_vectors_reference"] = {
                    "file_index": index, "field": "before_vectors",
                    "bytes": len(encoded_vectors), "sha256": sha(encoded_vectors),
                }
            else:
                row["after_vectors"] = vectors(row["after"])
            row["equivalent"] = row["before_vectors"] == resolved_after_vectors(row, index)
            assert row["equivalent"], "Formatter proposal changed retained source vectors"
            assert source.read_bytes() == before
            row["passed"] = True
        except Exception as error:
            row["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
        encoded = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8")
        assert len(encoded) <= 32 * 1024 * 1024
        write_json(REPORT / "formatter-proposals.json", result)
    retained = (REPORT / "formatter-proposals.json").read_bytes()
    assert len(retained) <= 32 * 1024 * 1024
    assert retained == encoded
    for index, row in enumerate(result["files"]):
        if row["passed"]:
            assert row["equivalent"] is True
            assert row["before_vectors"] == resolved_after_vectors(row, index)
    result["passed"] = all(row["passed"] for row in result["files"])
    final_encoded = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8")
    assert len(final_encoded) <= 32 * 1024 * 1024
    write_json(REPORT / "formatter-proposals.json", result)
    assert (REPORT / "formatter-proposals.json").read_bytes() == final_encoded
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
