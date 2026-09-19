"""Bind only the exact eight repairs to the previously executed native source."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess

PRIOR = "717e16cde8b66a4d2bfcbf37163a898e4b3ed18d"
SUPPORT = "ci/native_runtime/native_phase_lifecycle_support.py"
LIFECYCLE = "ci/native_runtime/test_native_phase_lifecycle.py"
FAILED = "test_real_exporter_backpressure_is_reported_without_blocking_the_original_protocol"
FORMAT_PYTHON = {
    "scripts/native_slo_daemon_fixture.py",
    "tests/test_native_slo_rust_phase_sender.py",
}
RUST_PATTERN = re.compile(
    r'(?P<space>\s+)|(?P<comment>//[^\n]*)'
    r'|(?P<string>(?:b|c)?"(?:\\.|[^"\\])*")'
    r"|(?P<lifetime>'[A-Za-z_][A-Za-z_0-9]*)"
    r"|(?P<identifier>(?:r#)?[A-Za-z_][A-Za-z_0-9]*)"
    r"|(?P<number>(?:0[xob][0-9A-Fa-f_]+|[0-9][0-9_]*"
    r"(?:\.(?!\.|[A-Za-z_])[0-9_]*)?(?:[eE][+-]?[0-9_]+)?)(?:[A-Za-z][A-Za-z0-9_]*)?)"
    r"|(?P<punctuation><<=|>>=|\.\.=|::|->|=>|==|!=|>=|<=|&&|\|\||<<|>>|"
    r"\+=|-=|\*=|/=|%=|\^=|&=|\|=|\.\.|[{}()\[\];,:.!?+\-*/%&|^<>=#@$~])"
)
SINK_SIGNATURE = (
    "fn export_loop(\n    socket: UnixDatagram,\n    role: Role,\n"
    "    sender_start_ticks: u64,\n    run_state: Arc<AtomicU8>,\n) {"
)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(source: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", *arguments], cwd=source, stderr=subprocess.PIPE, timeout=60)


def committed(source: Path, revision: str, relative: str) -> bytes:
    assert relative and not relative.startswith("/") and not ({"", ".", ".."} & set(relative.split("/")))
    raw = git(source, "cat-file", "blob", revision + ":" + relative)
    assert len(raw) <= 2 * 1024 * 1024
    return raw


def pinned(here: Path, config: dict, key: str) -> bytes:
    pin = config[key]
    path = (here / pin["path"]).resolve(strict=True)
    assert path.is_relative_to(here)
    raw = path.read_bytes()
    assert len(raw) == pin["bytes"] <= 2 * 1024 * 1024 and digest(raw) == pin["sha256"]
    return raw


def rust_tokens(text: str) -> list[tuple[str, str]]:
    """Conservative lexer for these four pinned files; unsupported forms refuse."""
    result = []
    offset = 0
    while offset < len(text):
        assert not text.startswith("/*", offset), "Unadmitted block-comment shape"
        assert not re.match(r"(?:br|cr|r)#+?\"|(?:br|cr|r)\"", text[offset:]), "Unadmitted raw literal"
        match = RUST_PATTERN.match(text, offset)
        assert match is not None, ("Unsupported Rust lexical input", offset)
        assert match.end() > offset
        if match.lastgroup != "space":
            result.append((match.lastgroup, match.group()))
        offset = match.end()
    return result


def python_body_contract(relative: str, before: bytes, after: bytes) -> dict:
    original = ast.parse(before.decode(), filename=relative, type_comments=True)
    current = ast.parse(after.decode(), filename=relative, type_comments=True)
    original_full = ast.dump(original, include_attributes=False)
    current_full = ast.dump(current, include_attributes=False)
    if relative in FORMAT_PYTHON:
        assert original_full == current_full, relative
        return {"complete_ast_equal": True, "literal_values_and_type_ignores_equal": True}
    assert relative in {SUPPORT, LIFECYCLE}
    old, new = copy.deepcopy(original), copy.deepcopy(current)
    if relative == SUPPORT:
        old.body = [node for node in old.body if not (isinstance(node, ast.FunctionDef)
                    and node.name == "fill_owned_receiver")]
        removed = []
        kept = []
        for node in new.body:
            if isinstance(node, ast.FunctionDef) and node.name in {"fill_owned_receiver", "retain_native_stderr"}:
                removed.append(node.name)
            elif isinstance(node, ast.Import) and ast.dump(node, include_attributes=False) == (
                "Import(names=[alias(name='errno')])"
            ):
                continue
            elif isinstance(node, ast.ImportFrom) and node.module in {"collections.abc", "contextlib"}:
                expected = {"collections.abc": ["Iterator"], "contextlib": ["ExitStack", "contextmanager"]}
                assert [alias.name for alias in node.names] == expected[node.module]
                assert all(alias.asname is None for alias in node.names) and node.level == 0
            else:
                kept.append(node)
        assert removed == ["fill_owned_receiver", "retain_native_stderr"]
        new.body = kept
    else:
        old.body = [node for node in old.body if not (isinstance(node, ast.FunctionDef) and node.name == FAILED)]
        new.body = [node for node in new.body if not (isinstance(node, ast.FunctionDef) and node.name == FAILED)]
        provider = [node for node in new.body if isinstance(node, ast.ImportFrom)
                    and node.module == "ci.native_runtime.native_phase_lifecycle_support"]
        assert len(provider) == 1 and provider[0].level == 0
        added = [alias for alias in provider[0].names if alias.name == "retain_native_stderr"]
        assert len(added) == 1 and added[0].asname is None
        provider[0].names = [alias for alias in provider[0].names if alias.name != "retain_native_stderr"]
    assert ast.dump(old, include_attributes=False) == ast.dump(new, include_attributes=False), relative
    return {
        "all_other_ordered_statements_equal": True,
        "changed_function": "fill_owned_receiver" if relative == SUPPORT else FAILED,
        "new_stderr_helper_only_in_failed_case": True,
        "shared_OwnedNativeStream_response_deadline_and_cleanup_bodies_equal": True,
    }


def verify_preparation(config: dict, here: Path, source: Path) -> dict:
    raw = pinned(here, config, "source_repair_packet")
    prepared = json.loads(raw)
    assert prepared["source_sha"] == config["source_sha"]
    assert prepared["source_tree"] == config["source_tree"]
    assert prepared["source_parent"] == config["source_parent"] == PRIOR
    assert git(source, "rev-parse", config["source_sha"] + "^").decode().strip() == PRIOR
    changes = git(source, "diff-tree", "--no-commit-id", "--name-status", "-r",
                  PRIOR, config["source_sha"]).decode().splitlines()
    expected = set(prepared["changed_files"])
    assert len(expected) == 8 and len(changes) == 8
    assert {line[2:] for line in changes if line.startswith("M\t")} == expected
    assert len(prepared["source_files"]) == 23 and len(prepared["whole_file_inverse_edits"]) == 33
    rows = {}
    for relative, pin in prepared["source_files"].items():
        current = (source / relative).read_bytes()
        assert current == committed(source, config["source_sha"], relative)
        assert len(current) == pin["bytes"] and digest(current) == pin["sha256"]
        blob = hashlib.sha1(b"blob " + str(len(current)).encode() + b"\0" + current).hexdigest()
        assert blob == pin["git_blob"]
        assert len(current.decode().splitlines()) == pin["physical_lines"] <= 500
        old = committed(source, PRIOR, relative)
        assert digest(old) == pin["prior_sha256"]
        edits = [edit for edit in prepared["whole_file_inverse_edits"] if edit["path"] == relative]
        forward = old.decode()
        for edit in edits:
            assert forward.count(edit["before"]) == 1
            forward = forward.replace(edit["before"], edit["after"], 1)
        assert forward.encode() == current
        reverse = current.decode()
        for edit in reversed(edits):
            assert reverse.count(edit["after"]) == 1
            reverse = reverse.replace(edit["after"], edit["before"], 1)
        assert reverse.encode() == old
        row = {"current_sha256": digest(current), "prior_sha256": digest(old),
               "physical_lines": pin["physical_lines"], "within_500": True,
               "whole_file_forward_inverse_equal": True, "exact_edits": len(edits)}
        if relative.endswith(".py"):
            ast.parse(current.decode(), filename=relative, type_comments=True)
            row["current_python_ast_parsed"] = True
            if relative in expected:
                row["python_contract"] = python_body_contract(relative, old, current)
        elif relative in expected:
            assert relative.endswith(".rs")
            normalized = current.decode()
            optional_comma = relative.endswith("/native_phase_sink.rs")
            if optional_comma:
                assert normalized.count(SINK_SIGNATURE) == 1
                normalized = normalized.replace(
                    SINK_SIGNATURE, SINK_SIGNATURE.replace("Arc<AtomicU8>,\n", "Arc<AtomicU8>\n"), 1,
                )
            prior_tokens = rust_tokens(old.decode())
            current_tokens = rust_tokens(normalized)
            assert prior_tokens == current_tokens
            row["complete_rust_lexical_tokens_equal"] = True
            row["rust_optional_final_parameter_comma_only"] = optional_comma
            row["rust_token_count"] = len(prior_tokens)
            row["comments_and_literal_spellings_unchanged"] = True
        else:
            assert current == old
        rows[relative] = row
    prior_proof_raw = pinned(here, config, "prior_source_proof")
    proof = json.loads(prior_proof_raw)
    assert proof["source_sha"] == PRIOR and proof["passed"] is True
    assert set(proof["files"]) == set(rows)
    for relative, record in proof["files"].items():
        assert record["sha256"] == rows[relative]["prior_sha256"]
    return {
        "schema": "native-phase-corrected-source-proof.v1",
        "source_sha": config["source_sha"], "source_tree": config["source_tree"],
        "prior_executed_source": PRIOR, "files": rows, "passed": True,
        "prior_actual_source_proof_sha256": digest(prior_proof_raw),
        "prior_typeignore_and_other_control_bodies_reexecuted": False,
        "fresh_Rust_parser_or_compiler_credit_in_this_proof": False,
        "qualification_complete": False,
    }
