"""Closed scalar schema for the private executed-guard diagnostic export."""

from __future__ import annotations

from typing import Any, cast

from scripts.ci.codex_continuation_observer import MAX_CALLS, MAX_EVENTS, RETURN_GROUPS, SOURCE_SHA256, projected_locals

_PROJECTION = frozenset(projected_locals({}))


def require(value: bool) -> None:
    if not value:
        raise ValueError("codex_observer_export_schema")


def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in rows:
        require(key not in result)
        result[key] = value
    return result


def _mapping(value: object) -> dict[str, Any]:
    require(type(value) is dict)
    return cast(dict[str, Any], value)


def _projection(raw: object) -> None:
    value = _mapping(raw)
    require(set(value) == _PROJECTION)
    for key, item in value.items():
        if item is None:
            continue
        if key.endswith("_digest") or key.endswith("_identity"):
            require(type(item) is str and len(item) == 64 and all(c in "0123456789abcdef" for c in item))
        elif key.endswith("_generation"):
            require(type(item) is int and 0 <= item <= 2**63 - 1)
        elif key.startswith("native_"):
            require(type(item) is str and item in {"allow", "review", "block", "deny"})
        else:
            require(type(item) is bool)


def validated_export(value: object) -> dict[str, Any]:
    """Validate complete and incomplete original records without repairing them."""
    value = _mapping(value)
    require(set(value) == {"guards", "native_returns"})
    guards, native = _mapping(value["guards"]), _mapping(value["native_returns"])
    require(
        set(guards)
        == {
            "schema",
            "source_bound",
            "source_sha256",
            "calls",
            "active_calls",
            "overflow",
            "complete",
            "instrumented_deadline_unchanged",
            "latency_qualified",
        }
    )
    require(guards["schema"] == "hol-guard.codex-executed-guards.v1" and guards["source_sha256"] == SOURCE_SHA256)
    require(guards["instrumented_deadline_unchanged"] is True and guards["latency_qualified"] is False)
    require(set(native) == {"rows", "active_calls", "overflow", "complete"})
    for record, field in ((guards, "calls"), (native, "rows")):
        require(type(record[field]) is list and len(record[field]) <= MAX_CALLS)
        require(type(record["active_calls"]) is int and 0 <= record["active_calls"] <= MAX_CALLS)
        require(type(record["overflow"]) is bool and type(record["complete"]) is bool)
    require(type(guards["source_bound"]) is bool)
    for raw in guards["calls"]:
        row = _mapping(raw)
        require({"events", "complete", "returned", "projection"} <= set(row))
        require(
            set(row)
            <= {
                "events",
                "complete",
                "returned",
                "projection",
                "refused",
                "trace_restored",
                "return_statement_line",
                "return_event_line",
                "return_group",
            }
        )
        for key in ("complete", "returned", "trace_restored"):
            if key in row:
                require(type(row[key]) is bool)
        if "refused" in row:
            require(row["refused"] == "existing_trace_or_source_changed")
        for key in ("return_statement_line", "return_event_line"):
            if key in row:
                require(type(row[key]) is int and 90 <= row[key] <= 233)
        if "return_group" in row:
            require(row["return_group"] == RETURN_GROUPS.get(row.get("return_statement_line", -1), "unmapped_return"))
        if row["projection"]:
            _projection(row["projection"])
        else:
            require(row["projection"] == {} and row["complete"] is False)
        events = row["events"]
        require(type(events) is list and len(events) <= MAX_EVENTS)
        for raw_event in events:
            event = _mapping(raw_event)
            if event.get("event") == "helper_return":
                require(set(event) == {"event", "helper", "value"})
                require(event["helper"] in {"_original_hook_is_live", "native_review_binding_matches"})
                require(event["value"] is None or type(event["value"]) is bool)
            else:
                require(set(event) == {"event", "line"} and event["event"] in {"line", "return", "exception"})
                require(type(event["line"]) is int and 90 <= event["line"] <= 233)
    for raw in native["rows"]:
        row = _mapping(raw)
        require({"entered", "returned", "captured"} <= set(row))
        require(
            set(row)
            <= {
                "entered",
                "returned",
                "captured",
                "entry_snapshot",
                "receipt_identity",
                "edge_present",
                "entry_capture_failed",
                "capture_failed",
            }
        )
        for key, item in row.items():
            if key in {"entry_snapshot", "receipt_identity"}:
                _projection(item)
            else:
                require(type(item) is bool)
    if guards["complete"]:
        require(
            bool(guards["calls"]) and guards["active_calls"] == 0 and not guards["overflow"] and guards["source_bound"]
        )
        require(all(row["complete"] and row.get("trace_restored") for row in guards["calls"]))
    if native["complete"]:
        require(bool(native["rows"]) and native["active_calls"] == 0 and not native["overflow"])
        require(all(row["captured"] and row["returned"] for row in native["rows"]))
    return value
