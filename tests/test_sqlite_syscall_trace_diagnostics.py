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


@pytest.mark.parametrize(
    ("trace", "record_class"),
    [
        (b"\n", "empty_line"),
        (b" \t\n", "whitespace_only"),
        (b"<unfinished ...>\n", "standalone_unfinished_marker"),
        (b"<unavailable>\n", "standalone_unavailable_marker"),
        (b'[pid 11] openat(AT_FDCWD, "/private", O_RDONLY\n', "syscall_entry_fragment"),
        (b") = 3\n", "closing_parenthesis_result"),
        (b", 0600) = 3\n", "comma_continuation_result"),
        (b"0x5) = 3\n", "numeric_continuation_result"),
        (b"72) = 3\n", "numeric_continuation_result"),
        (b"private-token) = 3\n", "unbound_result_fragment"),
        (b"unrelated-token\n", "other"),
        (b"<unfinished ...> extra\n", "other"),
        (b"<unavailable> extra\n", "other"),
        (b'private_syscall("/private") partial\n', "other"),
        (b"0xprivate) = 3\n", "unbound_result_fragment"),
    ],
)
def test_fixed_record_classes_distinguish_rejected_fragments_without_accepting_them(trace, record_class):
    diagnostics = SyntaxDiagnostics()
    calls, complete = parse_calls(trace, 10, diagnostics)
    assert (calls, complete) == parse_calls(trace, 10) == ([], False)
    summary = diagnostics.summary()
    assert summary["signatures"][0]["record_class"] == record_class
    assert summary["reason_counts"] == {"unrecognized_record": 1}
    assert not summary["affects_parser_acceptance"]


def test_previous_uninformative_hash_stays_exact_while_three_records_remain_distinct():
    diagnostics = SyntaxDiagnostics()
    for line in ("", "<unfinished ...>", "synthetic-other-token"):
        diagnostics.record("unrecognized_record", line)
    signatures = diagnostics.summary()["signatures"]
    assert len(signatures) == 3
    assert {entry["normalized_sha256"] for entry in signatures} == {
        "fcac451e4875e35a63382d8337490484dcfb685e93d8df61d7dbad7bae1295ec"
    }
    assert {entry["record_class"] for entry in signatures} == {
        "empty_line",
        "standalone_unfinished_marker",
        "other",
    }
    assert all(entry["count"] == 1 for entry in signatures)


def test_lexical_class_and_signature_ignore_actual_pid_path_sql_and_numeric_values():
    outputs = []
    for pid, path, number in [("111111", "/private-alpha", "0x5"), ("929292", "/private-beta", "0x9")]:
        diagnostics = SyntaxDiagnostics()
        for line in (f'{pid} openat(AT_FDCWD, "{path}", O_RDONLY', f"{number}) = 3"):
            diagnostics.record("unrecognized_record", line)
        summary = diagnostics.summary()
        encoded = json.dumps(summary)
        assert all(value not in encoded for value in (pid, path, number))
        outputs.append(summary)
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("/synthetic/bin/strace: Process 10 attached", "whole_attach_banner"),
        ("/synthetic/bin/strace: Process 10 attached with 2 threads", "whole_attach_banner"),
        ("/synthetic/bin/strace: Process 10 detached", "whole_detach_banner"),
        (
            '[pid 11] openat(AT_FDCWD, "/value", O_RDONLY/synthetic/bin/strace: Process 12 attached',
            "entry_then_attach_banner",
        ),
        (
            '[pid 11] openat(AT_FDCWD, "/value", O_RDONLY/synthetic/bin/strace: Process 12 detached',
            "entry_then_detach_banner",
        ),
    ],
)
def test_exact_invocation_status_framing_is_observation_only(line, expected):
    from scripts.sqlite_syscall_trace_diagnostics import _framing_class

    assert _framing_class(line, "/synthetic/bin/strace") == expected
    trace = (line + "\n").encode()
    diagnostics = SyntaxDiagnostics()
    before = parse_calls(trace, 10, diagnostics)
    diagnostics.observe_framing(trace, "/synthetic/bin/strace", complete_stream=True)
    assert before == parse_calls(trace, 10) == ([], False)
    assert diagnostics.summary()["framing_context"]["windows"][0]["current"] == expected


@pytest.mark.parametrize(
    "line",
    [
        "/synthetic/bin/strace: Process 10 attached extra",
        "/synthetic/bin/strace: Process 0 attached",
        "/synthetic/bin/strace: Process 10 attached with 0 threads",
        "/synthetic/bin/strace: Process x attached",
        "/synthetic/bin/strace: Process 10 attache",
        "/synthetic/bin/strace: Process 10  attached",
        "/different/bin/strace: Process 10 attached",
        "prefix /synthetic/bin/strace: Process 10 attached",
        "unknown_syscall(/synthetic/bin/strace: Process 10 attached",
        'openat(AT_FDCWD, "/synthetic/bin/strace: Process 10 attached',
        'openat(AT_FDCWD, "escaped\\"/synthetic/bin/strace: Process 10 attached',
        "openat(3</synthetic/bin/strace: Process 10 attached",
        "openat(3<escaped\\>/synthetic/bin/strace: Process 10 attached",
        "openat(3<</synthetic/bin/strace: Process 10 attached",
        "openat(3>/synthetic/bin/strace: Process 10 attached",
        'openat(AT_FDCWD, "/value", O_RDONLY) = 3/synthetic/bin/strace: Process 10 attached',
    ],
)
def test_status_near_matches_and_data_regions_never_become_framing_anchors(line):
    from scripts.sqlite_syscall_trace_diagnostics import _framing_class

    assert "banner" not in _framing_class(line, "/synthetic/bin/strace")
    diagnostics = SyntaxDiagnostics()
    diagnostics.observe_framing((line + "\n").encode(), "/synthetic/bin/strace", complete_stream=True)
    assert diagnostics.summary()["framing_context"]["windows"] == []


def test_framing_context_retains_physical_order_and_exact_adjacency_without_values():
    outputs = []
    for index in range(20):
        executable = f"/private-synthetic-{index}/strace"
        pid = 100000 + index
        trace = (
            f"{executable}: Process {pid} attached\n"
            f'[pid {pid}] openat(AT_FDCWD, "private-synthetic-{index}", O_RDONLY'
            f"{executable}: Process {pid + 1} attached\n"
            ") = 3\n"
            f"{executable}: Process {pid + 2} attached\n"
        ).encode()
        diagnostics = SyntaxDiagnostics()
        assert parse_calls(trace, 10, diagnostics) == ([], False)
        diagnostics.observe_framing(trace, executable, complete_stream=True)
        summary = diagnostics.summary()
        context = summary["framing_context"]
        assert context["metadata_complete"] and context["physical_records"] == 4
        assert context["windows"] == [
            {
                "physical_record": 1,
                "previous": None,
                "current": "whole_attach_banner",
                "following": "entry_then_attach_banner",
            },
            {
                "physical_record": 2,
                "previous": "whole_attach_banner",
                "current": "entry_then_attach_banner",
                "following": "closing_parenthesis_result",
            },
            {
                "physical_record": 4,
                "previous": "closing_parenthesis_result",
                "current": "whole_attach_banner",
                "following": None,
            },
        ]
        encoded = json.dumps(summary)
        assert "private-synthetic" not in encoded and str(pid) not in encoded and executable not in encoded
        outputs.append(summary)
    assert all(value == outputs[0] for value in outputs)


def test_framing_windows_are_capped_and_truncation_is_explicitly_incomplete():
    diagnostics = SyntaxDiagnostics()
    trace = b"/synthetic/bin/strace: Process 10 attached\n" * (MAX_SIGNATURES + 1)
    diagnostics.observe_framing(trace, "/synthetic/bin/strace", complete_stream=True)
    summary = diagnostics.summary()
    context = summary["framing_context"]
    assert len(context["windows"]) == MAX_SIGNATURES
    assert context["windows_truncated"] and not context["metadata_complete"]
    assert not summary["metadata_complete"] and not summary["affects_parser_acceptance"]


@pytest.mark.parametrize(
    ("trace", "complete_stream", "reason"),
    [
        (b"/synthetic/bin/strace: Process 10 attached", True, "unterminated_record"),
        (b"/synthetic/bin/strace: Process 10 attached\n", False, "capture_incomplete"),
        (b"\xff\n", True, "invalid_encoding"),
        (b"\r\n", True, "non_lf_line_separator"),
        (b"x" * (256 * 1024 + 1), True, "input_limit_exceeded"),
    ],
    ids=["unterminated", "capture-incomplete", "invalid-encoding", "non-lf", "byte-limit"],
)
def test_incomplete_or_ambiguous_physical_framing_never_claims_complete_metadata(trace, complete_stream, reason):
    diagnostics = SyntaxDiagnostics()
    diagnostics.observe_framing(trace, "/synthetic/bin/strace", complete_stream=complete_stream)
    summary = diagnostics.summary()
    assert summary["framing_context"][reason]
    assert not summary["framing_context"]["metadata_complete"] and not summary["metadata_complete"]
    assert not summary["affects_parser_acceptance"]
