"""Bounded structural failure metadata for the strict disposable trace parser.

No input text, numeric identifiers, paths, arguments or buffers are retained.
These observations never decide whether a trace is accepted.
"""

from __future__ import annotations

import hashlib
import io
import json
import re

MAX_FAILURE_EVENTS = 256
MAX_SIGNATURES = 16
MAX_FRAMING_TRACE_BYTES = 256 * 1024
REASONS = frozenset(
    {
        "invalid_prefix",
        "duplicate_unfinished",
        "malformed_resumed",
        "unmatched_resumed",
        "mismatched_resumed",
        "unrecognized_record",
        "dangling_unfinished",
    }
)
SYSCALLS = frozenset(
    {
        "open",
        "openat",
        "close",
        "dup",
        "dup2",
        "dup3",
        "fcntl",
        "write",
        "pwrite64",
        "writev",
        "pwritev",
        "pwritev2",
        "fsync",
        "fdatasync",
    }
)


def _shape(line: str) -> tuple[str, str, str]:
    match = re.match(r"^(?:\[pid\s+[0-9]+\]\s+|[0-9]+\s+)", line)
    prefix = "none"
    if match is not None:
        prefix = "bracket_pid" if line.startswith("[") else "numeric_pid"
        line = line[match.end() :]
    call = re.match(r"^(?:<\.\.\. )?([a-z][a-z0-9_]*)(?:\(| resumed>)", line)
    syscall = call[1] if call is not None and call[1] in SYSCALLS else "unknown"
    # Only these fixed booleans contribute to the hash. Even unknown words,
    # quoted values, PID digits and punctuation contents never enter it.
    normalized = {
        "prefix": prefix,
        "syscall": syscall,
        "starts_strace": line.startswith("strace:"),
        "starts_process_banner": line.startswith("strace: Process "),
        "starts_terminal": line.startswith("+++ "),
        "starts_signal": line.startswith("--- "),
        "starts_resumed": line.startswith("<... "),
        "ends_unfinished": line.endswith(" <unfinished ...>"),
        "has_open_parenthesis": "(" in line,
        "has_close_parenthesis": ")" in line,
        "has_result_separator": " = " in line,
        "has_quoted_region": '"' in line,
        "leading_whitespace": bool(line and line[0].isspace()),
        "trailing_whitespace": bool(line and line[-1].isspace()),
    }
    return prefix, syscall, hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()


def _record_class(line: str) -> str:
    """Fixed lexical classes only; fragments are never completed or accepted."""
    match = re.match(r"^(?:\[pid\s+[0-9]+\]\s+|[0-9]+\s+)", line)
    if match is not None:
        line = line[match.end() :]
    if line == "":
        return "empty_line"
    if line.isspace():
        return "whitespace_only"
    if line == "<unfinished ...>":
        return "standalone_unfinished_marker"
    if line == "<unavailable>":
        return "standalone_unavailable_marker"
    call = re.match(r"^([a-z][a-z0-9_]*)\(", line)
    if call is not None and call[1] in SYSCALLS and " = " not in line:
        return "syscall_entry_fragment"
    if " = " in line and ")" in line and "(" not in line:
        if line.startswith(")"):
            return "closing_parenthesis_result"
        if line.startswith(","):
            return "comma_continuation_result"
        if re.match(r"^-?(?:0x[0-9a-f]+|[0-9]+)(?:[,\s)]|$)", line) is not None:
            return "numeric_continuation_result"
        return "unbound_result_fragment"
    return "other"


def _outside_data_regions(prefix: str) -> bool:
    quoted = escaped = False
    angle = 0
    for character in prefix:
        if escaped:
            escaped = False
            continue
        if character == "\\" and (quoted or angle):
            escaped = True
        elif character == '"' and not angle:
            quoted = not quoted
        elif not quoted:
            if character == "<":
                angle += 1
            elif character == ">":
                if angle == 0:
                    return False
                angle -= 1
    return not quoted and angle == 0 and not escaped


def _framing_class(line: str, invocation_name: str) -> str:
    # v6.8 error_msg uses the actual invocation name, including its path.
    # Only whole banners or an exact suffix outside data regions are anchors.
    status = re.search(
        re.escape(invocation_name)
        + r": Process [1-9][0-9]{0,9} (attached(?: with [1-9][0-9]{0,9} threads)?|detached)\Z",
        line,
    )
    if status is not None and status.start() == 0:
        return "whole_attach_banner" if status[1].startswith("attached") else "whole_detach_banner"
    ordinary = _record_class(line)
    if status is not None and ordinary == "syscall_entry_fragment" and _outside_data_regions(line[: status.start()]):
        return "entry_then_attach_banner" if status[1].startswith("attached") else "entry_then_detach_banner"
    return ordinary


class SyntaxDiagnostics:
    def __init__(self) -> None:
        self.events_retained = 0
        self.events_truncated = False
        self.signatures_truncated = False
        self.reasons: dict[str, int] = {}
        self.signatures: dict[tuple[str, str, str, str, str], int] = {}
        self.framing: dict[str, object] | None = None

    def observe_framing(self, trace: bytes, invocation_name: str, *, complete_stream: bool) -> None:
        """Retain bounded adjacent LF-record classes; never join or accept them."""
        windows: list[dict[str, object]] = []
        previous: str | None = None
        following: dict[str, object] | None = None
        physical_records = 0
        windows_truncated = unterminated = invalid_encoding = non_lf = False
        oversized = len(trace) > MAX_FRAMING_TRACE_BYTES
        if not oversized:
            for physical_records, raw in enumerate(io.BytesIO(trace), start=1):
                terminated = raw.endswith(b"\n")
                unterminated |= not terminated
                try:
                    line = (raw[:-1] if terminated else raw).decode("utf-8")
                    non_lf |= any(value in line for value in "\r\v\f\x1c\x1d\x1e\x85\u2028\u2029")
                    current = _framing_class(line, invocation_name)
                except UnicodeDecodeError:
                    invalid_encoding = True
                    current = "other"
                if following is not None:
                    following["following"] = current
                    following = None
                if current in {
                    "whole_attach_banner",
                    "whole_detach_banner",
                    "entry_then_attach_banner",
                    "entry_then_detach_banner",
                }:
                    if len(windows) < MAX_SIGNATURES:
                        following = {
                            "physical_record": physical_records,
                            "previous": previous,
                            "current": current,
                            "following": None,
                        }
                        windows.append(following)
                    else:
                        windows_truncated = True
                previous = current
        self.framing = {
            "schema": "guard.sqlite-trace-framing.v1",
            "metadata_complete": not (
                oversized or windows_truncated or unterminated or invalid_encoding or non_lf or not complete_stream
            ),
            "physical_records": None if oversized else physical_records,
            "input_limit_exceeded": oversized,
            "capture_incomplete": not complete_stream,
            "windows_truncated": windows_truncated,
            "unterminated_record": unterminated,
            "invalid_encoding": invalid_encoding,
            "non_lf_line_separator": non_lf,
            "windows": windows,
            "raw_text_retained": False,
            "affects_parser_acceptance": False,
        }

    def record(self, reason: str, line: str) -> None:
        if reason not in REASONS:
            raise ValueError("unknown diagnostic reason")
        if self.events_retained == MAX_FAILURE_EVENTS:
            self.events_truncated = True
            return
        self.events_retained += 1
        self.reasons[reason] = self.reasons.get(reason, 0) + 1
        prefix, syscall, signature = _shape(line)
        key = (reason, prefix, syscall, signature, _record_class(line))
        if key in self.signatures:
            self.signatures[key] += 1
        elif len(self.signatures) < MAX_SIGNATURES:
            self.signatures[key] = 1
        else:
            self.signatures_truncated = True

    def summary(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema": "guard.sqlite-trace-syntax-failures.v1",
            "failure_events_retained": self.events_retained,
            "failure_events_truncated": self.events_truncated,
            "signature_entries_truncated": self.signatures_truncated,
            "metadata_complete": not self.events_truncated
            and not self.signatures_truncated
            and (self.framing is None or self.framing["metadata_complete"] is True),
            "reason_counts": dict(sorted(self.reasons.items())),
            "signatures": [
                {
                    "reason": reason,
                    "prefix": prefix,
                    "syscall": syscall,
                    "normalized_sha256": signature,
                    "record_class": record_class,
                    "count": count,
                }
                for (reason, prefix, syscall, signature, record_class), count in sorted(self.signatures.items())
            ],
            "raw_text_retained": False,
            "affects_parser_acceptance": False,
        }
        if self.framing is not None:
            result["framing_context"] = self.framing
        return result
