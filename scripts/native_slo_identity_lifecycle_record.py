"""Finite incremental cold-identity records, including interrupted preparation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from scripts.native_slo_evidence_files import _file, _stat, atomic_exclusive, directory, fingerprint, read_file
from scripts.native_slo_identity_phases import _COUNTERS

SCHEMA = "hol-guard.cold-identity-record.v1"
MAX_BYTES = 256 * 1024
MAX_RECORD_BYTES = 4096
MAX_CALLS = 96
MAX_RECORDS = 2 * MAX_CALLS + 32
OWNERS = {"preparation", "publication", "hook", "cleanup", "unassigned"}
PHASES = {"preparation", "ready", "hook", "between_hooks", "cleanup", "closed"}


def binding(value: object) -> dict[str, str]:
    fields = {"build_sha": 40, "runtime_sha256": 64, "installed_package_sha256": 64}
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("qualification cold identity binding invalid")
    if any(
        not isinstance(value[k], str) or re.fullmatch(r"[0-9a-f]{" + str(n) + "}", value[k]) is None
        for k, n in fields.items()
    ):
        raise ValueError("qualification cold identity binding invalid")
    return dict(value)


class LifecycleJournal:
    """A single child owns writes; diagnostic failure never replaces a call."""

    def __init__(self, path: Path, expected: dict[str, str]) -> None:
        self.path = path
        self.expected = binding(expected)
        self._stack = ExitStack()
        try:
            # Reuse the numeric journal's protected DACL/0600 creation and
            # retained-parent, same-domain descriptor identity admission.
            atomic_exclusive(path, b"")
            parent, directory_fd = self._stack.enter_context(directory(path.parent))
            before = _stat(parent, directory_fd, path.name)
            _file(before, 0, private=True)
            descriptor = os.open(
                parent / path.name if directory_fd is None else path.name,
                os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0),
                dir_fd=directory_fd,
            )
            try:
                if fingerprint(os.fstat(descriptor)) != fingerprint(before):
                    raise ValueError("qualification cold journal identity changed")
                self._stream = self._stack.enter_context(os.fdopen(descriptor, "wb"))
            except BaseException:
                os.close(descriptor)
                raise
        except BaseException:
            self._stack.close()
            raise
        self._lock = threading.Lock()
        self._started = time.perf_counter_ns()
        self.records = self.size = 0
        self.failed = False
        self.closed = False
        self.close_failed = False
        self.append("started", binding=self.expected)

    def append(self, kind: str, **fields: Any) -> None:
        with self._lock:
            if self.closed or self.failed:
                self.failed = True
                return
            record = {
                "schema": SCHEMA,
                "kind": kind,
                "sequence": self.records,
                "elapsed_ns": time.perf_counter_ns() - self._started,
                **fields,
            }
            try:
                data = json.dumps(record, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"
                if len(data) > MAX_RECORD_BYTES or self.size + len(data) > MAX_BYTES or self.records >= MAX_RECORDS:
                    self.failed = True
                    return
                if self._stream.write(data) != len(data):
                    self.failed = True
                    return
                self._stream.flush()
                self.records += 1
                self.size += len(data)
            except (OSError, ValueError, TypeError, UnicodeError):
                self.failed = True

    def close(self) -> None:
        with self._lock:
            if not self.closed:
                try:
                    self._stack.close()
                except (OSError, ValueError):
                    self.failed = self.close_failed = True
                self.closed = True


def _integer(value: object, maximum: int = 2**63 - 1) -> bool:
    return type(value) is int and 0 <= value <= maximum


def read_lifecycle(path: Path, expected: dict[str, str]) -> dict[str, Any]:
    """Read fixed scalar fields only; an incomplete final line is not success."""
    expected = binding(expected)
    try:
        encoded = read_file(path, MAX_BYTES, private=True)
    except (OSError, ValueError):
        return {"complete": False, "available": False, "reason": "cold_identity_journal_unavailable"}
    if len(encoded) > MAX_BYTES:
        return {"complete": False, "available": False, "reason": "cold_identity_journal_bounds"}
    proof = {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}
    records: list[dict[str, Any]] = []
    damaged = False
    for line in encoded.splitlines(keepends=True):
        try:
            if not line.endswith(b"\n") or len(line) > MAX_RECORD_BYTES:
                raise ValueError
            row = json.loads(line)
            if (
                not isinstance(row, dict)
                or row.get("schema") != SCHEMA
                or not _integer(row.get("sequence"), MAX_RECORDS - 1)
                or row["sequence"] != len(records)
                or not _integer(row.get("elapsed_ns"))
            ):
                raise ValueError
            if records and row["elapsed_ns"] < records[-1]["elapsed_ns"]:
                raise ValueError
            records.append(row)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            damaged = True
            break
    try:
        result = _project(records, expected)
    except (ValueError, KeyError, TypeError):
        return {"complete": False, "available": False, "reason": "cold_identity_journal_invalid", **proof}
    result.update(proof, available=True, damaged_tail=damaged)
    result["complete"] = result["complete"] and not damaged
    return result


def _project(records: list[dict[str, Any]], expected: dict[str, str]) -> dict[str, Any]:
    common = {"schema", "kind", "sequence", "elapsed_ns"}
    shapes = {
        "started": {"binding"},
        "phase": {"phase", "phase_epoch"},
        "call_started": {"call", "operation", "owner", "phase", "phase_epoch", "hook", "parent_call"},
        "call_finished": {"call", "phase", "phase_epoch", "outcome", "metrics", "identity_matches"},
        "hook_started": {"hook", "expected"},
        "hook_finished": {"hook", "outcome"},
        "observer_finished": {"drained", "unexpected", "overflow", "recording_failed", "initial_cache_entries"},
    }
    if not records or records[0].get("kind") != "started" or records[0].get("binding") != expected:
        raise ValueError
    calls: dict[int, dict[str, Any]] = {}
    hooks: dict[int, dict[str, Any]] = {}
    terminal = None
    totals = {owner: dict.fromkeys(_COUNTERS, 0) for owner in OWNERS}
    cross_boundary = ambiguous = unassigned = identity_mismatches = identity_unknown = 0
    for row in records:
        kind = row["kind"]
        if kind not in shapes or set(row) != common | shapes[kind] or terminal is not None:
            raise ValueError
        if kind == "started" and row["sequence"] != 0:
            raise ValueError
        if "phase" in row and (row["phase"] not in PHASES or not _integer(row["phase_epoch"], MAX_RECORDS)):
            raise ValueError
        if kind == "call_started":
            key = row["call"]
            if (
                not _integer(key, MAX_CALLS - 1)
                or key in calls
                or row["operation"] not in {"status", "validation", "capabilities", "live_proof", "capability_process"}
                or row["owner"] not in OWNERS
                or not (row["hook"] is None or _integer(row["hook"], 2))
            ):
                raise ValueError
            if (row["owner"] == "hook") != (row["hook"] is not None) or (
                row["hook"] is not None and row["hook"] not in hooks
            ):
                raise ValueError
            parent_call = row["parent_call"]
            if parent_call is not None and (
                not _integer(parent_call, MAX_CALLS - 1) or parent_call not in calls or "outcome" in calls[parent_call]
            ):
                raise ValueError
            calls[key] = {
                k: row[k] for k in ("operation", "owner", "phase", "phase_epoch", "hook", "parent_call", "elapsed_ns")
            }
        elif kind == "call_finished":
            if not _integer(row["call"], MAX_CALLS - 1):
                raise ValueError
            call = calls[row["call"]]
            metrics = row["metrics"]
            if (
                "outcome" in call
                or row["outcome"] not in {"returned", "raised"}
                or not isinstance(metrics, dict)
                or set(metrics) != set(_COUNTERS)
                or any(not _integer(v) for v in metrics.values())
                or not (row["identity_matches"] is None or type(row["identity_matches"]) is bool)
            ):
                raise ValueError
            if (
                metrics["capability_calls"]
                != metrics["capability_cache_hits"]
                + metrics["capability_cache_misses"]
                + metrics["capability_cache_ambiguous"]
            ):
                raise ValueError
            call.update(
                outcome=row["outcome"],
                finished_ns=row["elapsed_ns"],
                end_phase=row["phase"],
                metrics=metrics,
                identity_matches=row["identity_matches"],
            )
            cross_boundary += call["phase_epoch"] != row["phase_epoch"]
            ambiguous += metrics["capability_cache_ambiguous"]
            unassigned += call["owner"] == "unassigned"
            identity_mismatches += row["identity_matches"] is False
            identity_unknown += call["operation"] == "status" and row["identity_matches"] is None
            for key, value in metrics.items():
                totals[call["owner"]][key] += value
                if not _integer(totals[call["owner"]][key]):
                    raise ValueError
        elif kind == "hook_started":
            key = row["hook"]
            if not _integer(key, 2) or key in hooks or type(row["expected"]) is not bool:
                raise ValueError
            hooks[key] = {"started_ns": row["elapsed_ns"], "expected": row["expected"]}
        elif kind == "hook_finished":
            if not _integer(row["hook"], 2):
                raise ValueError
            hook = hooks[row["hook"]]
            if "outcome" in hook or row["outcome"] not in {"returned", "raised"}:
                raise ValueError
            hook.update(outcome=row["outcome"], finished_ns=row["elapsed_ns"])
        elif kind == "observer_finished":
            if (
                any(type(row[k]) is not bool for k in ("drained", "overflow", "recording_failed"))
                or not _integer(row["unexpected"])
                or not _integer(row["initial_cache_entries"])
            ):
                raise ValueError
            terminal = {k: row[k] for k in shapes[kind]}
    unfinished = sum("outcome" not in c for c in calls.values())
    returned = sum(h.get("outcome") == "returned" and h["expected"] for h in hooks.values())
    hook_status = {
        index: sum(
            c.get("metrics", {}).get("status_calls", 0)
            for c in calls.values()
            if c["owner"] == "hook" and c["hook"] == index
        )
        for index in range(3)
    }
    prepared_status = sum(
        c.get("metrics", {}).get("status_calls", 0)
        for c in calls.values()
        if c["owner"] in {"preparation", "publication"} and c["phase"] == "preparation"
    )
    nested = sum(c["parent_call"] is not None for c in calls.values())
    complete = bool(
        not nested
        and terminal
        and terminal["drained"]
        and not terminal["overflow"]
        and not terminal["recording_failed"]
        and not terminal["unexpected"]
        and not unfinished
        and returned == 3
        and prepared_status > 0
        and all(hook_status.values())
        and not cross_boundary
        and not ambiguous
        and not unassigned
        and not identity_mismatches
        and not identity_unknown
        and not any(c.get("outcome") == "raised" for c in calls.values())
    )
    return {
        "schema": "hol-guard.cold-identity-observation.v1",
        "binding": expected,
        "complete": complete,
        "nested_calls": nested,
        "calls_started": len(calls),
        "calls_unfinished": unfinished,
        "cross_boundary_calls": cross_boundary,
        "unassigned_calls": unassigned,
        "capability_cache_ambiguous": ambiguous,
        "identity_mismatches": identity_mismatches,
        "identity_unknown": identity_unknown,
        "preparation_status_calls": prepared_status,
        "hook_status_calls": [hook_status[i] for i in range(3)],
        "hooks_started": len(hooks),
        "hooks_returned": returned,
        "cold_preparation_to_first_handler_return_ns": hooks.get(0, {}).get("finished_ns"),
        "totals_by_owner": totals,
        "calls": [{"call": key, **v} for key, v in calls.items()],
        "hooks": [{"hook": key, **v} for key, v in hooks.items()],
        "terminal": terminal,
    }
