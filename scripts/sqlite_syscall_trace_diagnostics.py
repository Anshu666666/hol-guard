"""Bounded structural failure metadata for the strict disposable trace parser.

No input text, numeric identifiers, paths, arguments or buffers are retained.
These observations never decide whether a trace is accepted.
"""

from __future__ import annotations

import hashlib
import json
import re

MAX_FAILURE_EVENTS = 256
MAX_SIGNATURES = 16
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


class SyntaxDiagnostics:
    def __init__(self) -> None:
        self.events_retained = 0
        self.events_truncated = False
        self.signatures_truncated = False
        self.reasons: dict[str, int] = {}
        self.signatures: dict[tuple[str, str, str, str], int] = {}

    def record(self, reason: str, line: str) -> None:
        if reason not in REASONS:
            raise ValueError("unknown diagnostic reason")
        if self.events_retained == MAX_FAILURE_EVENTS:
            self.events_truncated = True
            return
        self.events_retained += 1
        self.reasons[reason] = self.reasons.get(reason, 0) + 1
        prefix, syscall, signature = _shape(line)
        key = (reason, prefix, syscall, signature)
        if key in self.signatures:
            self.signatures[key] += 1
        elif len(self.signatures) < MAX_SIGNATURES:
            self.signatures[key] = 1
        else:
            self.signatures_truncated = True

    def summary(self) -> dict[str, object]:
        return {
            "schema": "guard.sqlite-trace-syntax-failures.v1",
            "failure_events_retained": self.events_retained,
            "failure_events_truncated": self.events_truncated,
            "signature_entries_truncated": self.signatures_truncated,
            "metadata_complete": not self.events_truncated and not self.signatures_truncated,
            "reason_counts": dict(sorted(self.reasons.items())),
            "signatures": [
                {"reason": reason, "prefix": prefix, "syscall": syscall, "normalized_sha256": signature, "count": count}
                for (reason, prefix, syscall, signature), count in sorted(self.signatures.items())
            ],
            "raw_text_retained": False,
            "affects_parser_acceptance": False,
        }
