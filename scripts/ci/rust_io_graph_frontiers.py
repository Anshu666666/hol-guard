#!/usr/bin/env python3
"""Report known I/O graph frontiers without replacing the authoritative gate."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from scripts.ci import rust_io_ownership_gate as gate


def diagnose(
    root: Path, *, max_records: int = 10000, max_calls: int = 50000, max_seconds: float = 120.0
) -> dict[str, object]:
    """Follow every resolvable edge; an unresolved edge has an unknown tail."""
    if max_records < 1 or max_calls < 1 or not 0 < max_seconds <= 300:
        raise ValueError("invalid graph diagnostic bounds")
    started = time.monotonic()
    records = gate._function_map(root)
    pending: list[gate.FunctionRecord] = []
    unresolved: list[dict[str, object]] = []
    for spec in gate.ROOTS:
        try:
            pending.append(gate._root_record(root, spec, records))
        except RuntimeError:
            unresolved.append(
                {
                    "path": spec.path,
                    "caller": spec.name,
                    "call": None,
                    "line": None,
                    "reason": "root_binding_unresolved",
                }
            )
    seen: set[tuple[str, str]] = set()
    reachable: list[gate.FunctionRecord] = []
    stopped_reason: str | None = None
    inspected_calls = 0
    while pending:
        record = pending.pop()
        identity = (record.path, record.qualname)
        if identity in seen:
            continue
        if time.monotonic() - started >= max_seconds:
            stopped_reason = "elapsed_time_cap"
            break
        if len(reachable) >= max_records:
            stopped_reason = "reachable_record_cap"
            break
        seen.add(identity)
        reachable.append(record)
        for name in sorted(set(gate._calls(record))):
            if inspected_calls >= max_calls or time.monotonic() - started >= max_seconds:
                stopped_reason = "call_site_cap" if inspected_calls >= max_calls else "elapsed_time_cap"
                break
            inspected_calls += 1
            try:
                pending.extend(gate.resolve_calls(root, record, name, records))
            except RuntimeError:
                unresolved.append(
                    {
                        "path": record.path,
                        "caller": record.qualname,
                        "call": name,
                        "line": record.node.lineno,
                        "reason": "callable_binding_unresolved",
                    }
                )
        if stopped_reason is not None:
            break
    unclassified = {
        (item.path, item.line, item.operation, item.category)
        for record in reachable
        for item in gate._observations(record)
        if item.category.startswith("unclassified_python")
    }
    return {
        "schema": "hol-guard.io-graph-frontiers.v1",
        "acceptance": False,
        "authoritative_gate_required": True,
        "scope": "Known resolvable closure only; tails behind unresolved edges remain unknown.",
        "indexed_record_count": sum(len(values) for values in records.values()),
        "known_reachable_count": len(reachable),
        "all_root_bindings_resolved": not unresolved and stopped_reason is None,
        "status": "incomplete" if unresolved or stopped_reason is not None else "diagnostic_complete",
        "stopped_reason": stopped_reason,
        "elapsed_seconds": time.monotonic() - started,
        "inspected_call_sites": inspected_calls,
        "limits": {
            "max_records": max_records,
            "max_calls": max_calls,
            "cooperative_traversal_seconds": max_seconds,
            "time_limit_scope": (
                "Between-call checks only; use a process timeout for indexing, resolution and observations."
            ),
            "hosted_process_timeout_required": True,
        },
        "unresolved": sorted(unresolved, key=lambda item: (str(item["path"]), str(item["caller"]), str(item["call"]))),
        "reachable_unclassified_io": [
            {"path": path, "line": line, "operation": operation, "category": category}
            for path, line, operation, category in sorted(unclassified)
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = diagnose(args.root.resolve())
    except (RuntimeError, OSError, SyntaxError, MemoryError) as exc:
        report = {
            "schema": "hol-guard.io-graph-frontiers.v1",
            "acceptance": False,
            "authoritative_gate_required": True,
            "scope": "Diagnostic construction failed; no closure claim.",
            "diagnostic_error": (
                "MemoryError"
                if isinstance(exc, MemoryError)
                else "SyntaxError"
                if isinstance(exc, SyntaxError)
                else "OSError"
                if isinstance(exc, OSError)
                else "RuntimeError"
            ),
            "reason": "diagnostic_construction_failed",
        }
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "acceptance",
                    "authoritative_gate_required",
                    "scope",
                )
            },
            sort_keys=True,
        )
    )
    return int(
        bool(
            report.get("diagnostic_error")
            or report.get("stopped_reason")
            or report.get("unresolved")
            or report.get("reachable_unclassified_io")
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
