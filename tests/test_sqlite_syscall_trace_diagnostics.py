"""Failure metadata cannot change the frozen parser or retain private inputs."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json

import pytest

from scripts.probe_sqlite_syscall_observation import parse_calls
from scripts.sqlite_syscall_trace_diagnostics import (
    MAX_FAILURE_EVENTS,
    MAX_SIGNATURES,
    REASONS,
    SYSCALLS,
    SyntaxDiagnostics,
)


@pytest.mark.parametrize(
    ("trace", "reasons"),
    [
        (b"10 fsync(3) = 0\n", {}),
        (b"10 fsync(3 <unfinished ...>\n10 <... fsync resumed>) = 0\n", {}),
        (b"10 fsync(3 <unfinished ...>\n", {"dangling_unfinished": 1}),
        (b"10 <... fsync resumed>) = 0\n", {"unmatched_resumed": 1}),
        (b"10 <... malformed-resumed-line\n", {"malformed_resumed": 1}),
        (b"10 fsync(3 <unfinished ...>\n10 <... close resumed>) = 0\n", {"mismatched_resumed": 1}),
        (
            b"10 fsync(3 <unfinished ...>\n10 close(3 <unfinished ...>\n10 <... close resumed>) = 0\n",
            {"duplicate_unfinished": 1},
        ),
        (b"unknown malformed record\n", {"unrecognized_record": 1}),
    ],
)
def test_failure_classification_leaves_calls_and_acceptance_exactly_unchanged(trace, reasons):
    diagnostics = SyntaxDiagnostics()
    observed = parse_calls(trace, 10, diagnostics)
    assert observed == parse_calls(trace, 10)
    summary = diagnostics.summary()
    assert summary["reason_counts"] == reasons
    assert summary["metadata_complete"] and summary["affects_parser_acceptance"] is False
    assert observed[1] is (not reasons)


def test_normalized_signatures_never_include_or_depend_on_paths_pids_or_quoted_buffers():
    summaries = []
    for pid, path, contents in [
        ("191919", "/private/rsp131-private-alpha", "secret-one"),
        ("828282", "/different/rsp131-private-beta", "secret-two-longer"),
    ]:
        diagnostics = SyntaxDiagnostics()
        trace = f'{pid} unknown malformed "{path}" "{contents}"\n'.encode()
        assert parse_calls(trace, 10, diagnostics)[1] is False
        summary = diagnostics.summary()
        encoded = json.dumps(summary)
        assert all(value not in encoded for value in (pid, path, contents, "rsp131-private", "unknown malformed"))
        summaries.append(summary)
    assert summaries[0] == summaries[1]


def test_failure_event_retention_is_capped_and_explicitly_incomplete():
    diagnostics = SyntaxDiagnostics()
    parse_calls(b"unknown record\n" * (MAX_FAILURE_EVENTS + 2), 10, diagnostics)
    summary = diagnostics.summary()
    assert summary["failure_events_retained"] == MAX_FAILURE_EVENTS
    assert summary["reason_counts"] == {"unrecognized_record": MAX_FAILURE_EVENTS}
    assert summary["failure_events_truncated"] and not summary["metadata_complete"]


def test_signature_retention_is_capped_without_inventing_complete_metadata():
    diagnostics = SyntaxDiagnostics()
    for reason in sorted(REASONS):
        for syscall in sorted(SYSCALLS):
            diagnostics.record(reason, f'191919 {syscall}("/private/rsp131-private") malformed')
    summary = diagnostics.summary()
    assert len(summary["signatures"]) == MAX_SIGNATURES
    assert summary["signature_entries_truncated"] and not summary["metadata_complete"]
    assert "191919" not in json.dumps(summary) and "rsp131-private" not in json.dumps(summary)


def test_unknown_reason_is_rejected_without_retaining_its_text():
    diagnostics = SyntaxDiagnostics()
    with pytest.raises(ValueError, match=r"^unknown diagnostic reason$"):
        diagnostics.record("private-unknown-reason", "private-buffer")
    assert diagnostics.summary()["failure_events_retained"] == 0


def test_removing_only_observation_blocks_recovers_exact_original_parser_ast():
    class RemoveObservations(ast.NodeTransformer):
        def visit_If(self, node):
            if any(isinstance(value, ast.Name) and value.id == "diagnostics" for value in ast.walk(node.test)):
                return None
            return self.generic_visit(node)

    function = ast.parse(inspect.getsource(parse_calls)).body[0]
    assert isinstance(function, ast.FunctionDef)
    assert function.args.args[-1].arg == "diagnostics"
    function.args.args.pop()
    function.args.defaults.pop()
    stripped = RemoveObservations().visit(function)
    original_ast_sha256 = "c01d569fcfe2907c472f5724e89499f2e2e130669f9aa8da26383ef4c10db9b4"
    assert hashlib.sha256(ast.dump(stripped, include_attributes=False).encode()).hexdigest() == original_ast_sha256
