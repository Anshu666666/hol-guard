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


def main() -> int:
    result = {"schema": "pr2974-immutable-formatter-proposals.v1",
              "source_sha": CONFIG["source_sha"], "files": [], "source_writes_requested": False,
              "source_format_check_result_unchanged": True, "qualification_complete": False}
    for relative in CONFIG["python_source_paths"]:
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
            row["after_vectors"] = vectors(row["after"])
            row["equivalent"] = row["before_vectors"] == row["after_vectors"]
            assert row["equivalent"], "Formatter proposal changed retained source vectors"
            assert source.read_bytes() == before
            row["passed"] = True
        except Exception as error:
            row["error"] = {"type": type(error).__name__, "traceback": traceback.format_exc()}
        encoded = json.dumps(result, sort_keys=True, indent=2).encode()
        assert len(encoded) <= 32 * 1024 * 1024
        write_json(REPORT / "formatter-proposals.json", result)
    result["passed"] = all(row["passed"] for row in result["files"])
    write_json(REPORT / "formatter-proposals.json", result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
