"""Strict child sidecar admission and separately declared 24-coordinate join."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, cast

from .installation import canonical, owned
from .profile_runtime import MAX_BYTES, MAX_CALLBACKS, MAX_RECORDS, MAX_THREADS, pairs


def require(value: bool, label: str) -> None:
    if not value:
        raise ValueError("child_reader_" + label)


def coordinates() -> list[dict[str, Any]]:
    return [
        {"harness": harness, "event": event, "sample": -1, "case": case}
        for harness in ("claude-code", "codex")
        for event in ("PreToolUse", "PostToolUse")
        for case in ("benign", "block")
    ] + [
        {"harness": "claude-code", "event": "PostToolUse", "sample": sample, "case": "benign"}
        for sample in range(1_000_000, 1_000_016)
    ]


def coordinate(value: dict[str, Any]) -> tuple[object, ...]:
    return tuple(value[key] for key in ("harness", "event", "sample", "case"))


def join_subset(parent: dict[str, Any], daemon: dict[str, Any]) -> dict[str, Any]:
    # Keep the existing 88-reader's schema/individual native and mutation joins.
    # Its population result stays false; only this distinct reader admits 24.
    join_reports = importlib.import_module("priority_launcher_phase.joins").join_reports

    original = join_reports(parent, daemon)
    wanted = Counter(coordinate(item) for item in coordinates())
    parents = Counter(coordinate(item["coordinate"]) for item in parent["rows"])
    daemons = Counter(coordinate(item["coordinate"]) for item in daemon["rows"])
    valid = parents == daemons == wanted
    return {
        "schema": "hol-guard.priority-child-subset-joins.v1",
        "rows": original["rows"],
        "declared_coordinates": coordinates(),
        "original_88_population_complete": original["observation_complete"],
        "exact_24_population": valid,
        "observation_complete": valid
        and parent["observation_complete"] is True
        and daemon["observation_complete"] is True
        and all(row["complete"] is True for row in original["rows"]),
        "qualification_eligible": False,
    }


KEYS = {
    "schema",
    "pid",
    "parent_pid",
    "argv_sha256",
    "registered_argv_sha256",
    "isolated_flag",
    "configuration_sha256",
    "records",
    "callback_count",
    "callback_ns",
    "setup_ns",
    "module_roster_before",
    "module_roster_after_setup",
    "faults",
    "open_spans",
    "profile_restored",
    "observation_complete",
    "qualification_eligible",
    "return_events_prove_success",
    "finish_prewrite_ns",
    "callbacks_in_flight_at_snapshot",
    "callback_threads_seen",
    "worker_hooks_not_retired",
    "current_worker_threads_at_snapshot",
    "thread_census_complete",
}
ROW_KEYS = {"index", "stage", "thread", "thread_kind", "parent", "start_ns", "end_ns", "termination"}
FAULTS = {
    "preexisting_profile",
    "activation_failed",
    "restoration_failed",
    "callback_limit",
    "thread_limit",
    "thread_census_limit",
    "thread_census_failed",
    "record_or_depth_limit",
    "frame_identity_changed",
    "stack_mismatch",
    "capture_failed",
    "clock_order",
    "clock_failed",
    "report_byte_limit",
    "export_failed",
    "setup_failed",
}


def integer(value: object, minimum: int = 0, maximum: int = 2**63 - 1) -> bool:
    return type(value) is int and minimum <= value <= maximum


def validate(
    document: object,
    *,
    pid: int,
    parent_pid: int,
    argv: list[str],
    configuration_sha: str,
    allowed_stages: set[str],
    observed_argv0: str | None = None,
) -> dict[str, Any]:
    require(type(document) is dict, "document")
    value = cast(dict[str, Any], document)
    require(set(value) in (KEYS, KEYS | {"records_withheld"}), "keys")
    require(value["schema"] == "hol-guard.priority-child-profile.v2", "schema")
    require(value["pid"] == pid and integer(pid, 1, 2**31 - 1) and value["parent_pid"] == parent_pid, "pid")
    require(value["registered_argv_sha256"] == hashlib.sha256(canonical(argv)).hexdigest(), "registered_argv")
    observed = [observed_argv0 or argv[0], *argv[1:]]
    require(value["argv_sha256"] == hashlib.sha256(canonical(observed)).hexdigest(), "argv")
    require(value["configuration_sha256"] == configuration_sha, "configuration")
    require(value["isolated_flag"] is ("-I" in argv[1:2]), "isolation")
    require(value["qualification_eligible"] is False and value["return_events_prove_success"] is False, "scope")
    for key in (
        "callback_count",
        "callback_ns",
        "setup_ns",
        "open_spans",
        "finish_prewrite_ns",
        "callbacks_in_flight_at_snapshot",
        "worker_hooks_not_retired",
        "current_worker_threads_at_snapshot",
    ):
        require(integer(value[key]), "counter")
    require(value["callback_count"] <= MAX_CALLBACKS + 1, "callback_count")
    require(integer(value["callback_threads_seen"], 0, MAX_THREADS), "callback_threads")
    require(integer(value["current_worker_threads_at_snapshot"], 0, MAX_THREADS), "current_threads")
    for key in ("profile_restored", "observation_complete", "thread_census_complete"):
        require(type(value[key]) is bool, "boolean")
    require(
        type(value["faults"]) is list
        and len(value["faults"]) <= 16
        and all(type(item) is str and item in FAULTS for item in value["faults"])
        and len(set(value["faults"])) == len(value["faults"]),
        "faults",
    )
    for key in ("module_roster_before", "module_roster_after_setup"):
        roster = value[key]
        require(
            type(roster) is list
            and len(roster) <= 2048
            and roster == sorted(set(roster))
            and all(type(item) is str and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9.]{0,199}", item) for item in roster),
            "module_roster",
        )
    rows = value["records"]
    require(type(rows) is list and len(rows) <= MAX_RECORDS, "rows")
    if "records_withheld" in value:
        require(
            value["records_withheld"] is True
            and not rows
            and "report_byte_limit" in value["faults"]
            and value["observation_complete"] is False,
            "withheld_scope",
        )
    threads: set[int] = set()
    thread_kinds: dict[int, str] = {}
    open_rows = 0
    last_by_parent: dict[tuple[int, int | None], dict[str, Any]] = {}
    for index, original_row in enumerate(rows):
        require(type(original_row) is dict, "row_type")
        row = cast(dict[str, Any], original_row)
        require(type(row) is dict and set(row) == ROW_KEYS, "row_fields")
        require(row["index"] == index and type(row["index"]) is int, "index")
        require(type(row["stage"]) is str and row["stage"] in allowed_stages, "stage")
        require(integer(row["thread"], 0, MAX_THREADS - 1) and row["thread_kind"] in {"main", "worker"}, "thread")
        require(thread_kinds.setdefault(row["thread"], row["thread_kind"]) == row["thread_kind"], "thread_kind_changed")
        threads.add(row["thread"])
        require(integer(row["start_ns"], 1), "start")
        if row["end_ns"] is None:
            open_rows += 1
            require(row["termination"] == "missing", "missing_termination")
        else:
            require(integer(row["end_ns"], row["start_ns"]) and row["termination"] == "profile_return_or_unwind", "end")
        parent = row["parent"]
        if parent is not None:
            require(integer(parent, 0, index - 1), "parent")
            above = rows[parent]
            require(above["thread"] == row["thread"] and above["start_ns"] <= row["start_ns"], "parent_thread")
            if row["end_ns"] is not None and above["end_ns"] is not None:
                require(row["end_ns"] <= above["end_ns"], "parent_end")
        sibling_key = (row["thread"], parent)
        previous = last_by_parent.get(sibling_key)
        if previous is not None:
            require(previous["end_ns"] is not None and previous["end_ns"] <= row["start_ns"], "sibling_overlap")
        last_by_parent[sibling_key] = row
    require(threads == set(range(len(threads))), "thread_indices")
    require(list(thread_kinds.values()).count("main") <= 1, "main_thread_unique")
    require(value["open_spans"] == open_rows or value.get("records_withheld") is True, "open_spans")
    complete = not value["faults"] and open_rows == 0 and value["profile_restored"] is True
    complete = complete and value["callbacks_in_flight_at_snapshot"] == value["worker_hooks_not_retired"] == 0
    complete = complete and value["current_worker_threads_at_snapshot"] == 0 and value["thread_census_complete"] is True
    require(value["observation_complete"] == complete, "complete_claim")
    return value


# Only exact, source-declared labels are exported. Never stringify an exception:
# parser/OS/custom exception messages can contain private report bytes or paths.
REFUSALS = {
    "argv",
    "boolean",
    "bytes",
    "callback_count",
    "callback_threads",
    "child",
    "complete_claim",
    "configuration",
    "coordinate",
    "counter",
    "current_threads",
    "document",
    "end",
    "faults",
    "footer",
    "footer_binding",
    "footer_bytes",
    "index",
    "isolation",
    "keys",
    "main_thread_unique",
    "missing_termination",
    "module_roster",
    "open_spans",
    "parent",
    "parent_end",
    "parent_thread",
    "pid",
    "registered_argv",
    "row_fields",
    "row_type",
    "rows",
    "schema",
    "scope",
    "sibling_overlap",
    "stage",
    "start",
    "thread",
    "thread_indices",
    "thread_kind_changed",
    "unique_pid",
    "withheld_scope",
}


def failure_projection(error: BaseException, stage: str, body: bytes | None, footer: bytes | None) -> dict[str, Any]:
    label = "unclassified"
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str:
        declared = {"child_reader_" + value for value in REFUSALS}
        declared |= {"child_duplicate_key", "child_observer_path_admission"}
        if error.args[0] in declared:
            label = error.args[0]
    elif type(error) is FileNotFoundError:
        label = "file_missing"
    elif type(error) is json.JSONDecodeError:
        label = "invalid_json"
    elif type(error) is UnicodeDecodeError:
        label = "invalid_encoding"
    elif isinstance(error, OSError):
        label = "file_io_error"

    def capture(value: bytes | None, limit: int) -> dict[str, Any]:
        # A limit+1 capture is a bounded prefix, not the full file's identity.
        return {
            "read_returned": value is not None,
            "captured_bytes": len(value) if value is not None else None,
            "captured_sha256": hashlib.sha256(value).hexdigest() if value is not None else None,
            "within_read_limit": len(value) <= limit if value is not None else None,
        }

    return {
        "refusal": label,
        "stage": stage,
        "report_capture": capture(body, MAX_BYTES),
        "footer_capture": capture(footer, 4096),
    }


def read_profiles(
    directory: Path,
    parent: dict[str, Any],
    registrations: list[Any],
    configuration_sha: str,
    registry: dict[str, Any],
    parent_pid: int,
    observed_argv0: str | None = None,
) -> dict[str, Any]:
    wanted = {coordinate(item) for item in coordinates()}
    argv_by_route = {(item.harness, item.event): list(item.argv) for item in registrations}
    allowed = {item["id"] for item in registry["frames"]}
    allowed |= {"module:" + item for item in registry["modules"].values()}
    allowed |= {"import:" + item for item in registry["modules"].values()}
    reports: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    seen: set[int] = set()
    offered: set[tuple[object, ...]] = set()
    for row in parent["rows"]:
        key = coordinate(row["coordinate"])
        pid: int | None = None
        body: bytes | None = None
        footer_body: bytes | None = None
        stage = "parent_binding"
        try:
            require(key in wanted and key not in offered, "coordinate")
            offered.add(key)
            children = row["facts"]["children"]
            require(type(children) is list and len(children) == 1 and set(children[0]) == {"pid"}, "child")
            pid = children[0]["pid"]
            require(integer(pid, 1, 2**31 - 1) and pid not in seen, "unique_pid")
            pid = cast(int, pid)
            seen.add(pid)
            path = directory / (str(pid) + ".json")
            stage = "report_read"
            owned(path, directory=False)
            with path.open("rb") as stream:
                body = stream.read(MAX_BYTES + 1)
            stage = "report_validation"
            require(len(body) <= MAX_BYTES, "bytes")
            value = validate(
                json.loads(body, object_pairs_hook=pairs),
                pid=pid,
                parent_pid=parent_pid,
                argv=argv_by_route[(key[0], key[1])],
                configuration_sha=configuration_sha,
                allowed_stages=allowed,
                observed_argv0=observed_argv0,
            )
            done = path.with_suffix(".json.done")
            stage = "footer_read"
            owned(done, directory=False)
            with done.open("rb") as stream:
                footer_body = stream.read(4097)
            stage = "footer_validation"
            require(len(footer_body) <= 4096, "footer_bytes")
            footer = json.loads(footer_body, object_pairs_hook=pairs)
            require(
                type(footer) is dict
                and set(footer) == {"schema", "pid", "report_sha256", "finish_through_report_export_ns"},
                "footer",
            )
            require(
                footer["schema"] == "hol-guard.priority-child-export.v1"
                and footer["pid"] == pid
                and footer["report_sha256"] == hashlib.sha256(body).hexdigest()
                and integer(footer["finish_through_report_export_ns"], value["finish_prewrite_ns"]),
                "footer_binding",
            )
            stage = "source_coverage"
            stages = Counter(item["stage"] for item in value["records"])
            harness = key[0]
            bridge = "claude" if harness == "claude-code" else "codex"
            main_stage = f"codex_plugin_scanner.guard.adapters.{bridge}_daemon_hook_bridge:main"
            transport_stage = (
                "codex_plugin_scanner.guard.adapters.claude_daemon_hook_transport:authenticated_claude_hook_response"
                if harness == "claude-code"
                else "codex_plugin_scanner.guard.adapters.codex_daemon_hook_transport:_daemon_response_once"
            )
            source_coverage = (
                stages[main_stage] == 1
                and stages[transport_stage] >= 1
                and stages["codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth:_verify_challenge_response"] >= 1
                and stages["stdlib_http:HTTPConnection.request"] >= 2
                and stages["stdlib_http:HTTPConnection.getresponse"] >= 2
            )
            if harness == "claude-code":
                source_coverage = source_coverage and any(
                    item["stage"] == transport_stage and item["thread_kind"] == "worker" for item in value["records"]
                )
            reports.append(
                {
                    "coordinate": row["coordinate"],
                    "report": value,
                    "footer": footer,
                    "report_bytes": len(body),
                    "report_sha256": hashlib.sha256(body).hexdigest(),
                    "source_stage_coverage": source_coverage,
                }
            )
        except BaseException as error:
            failures.append(
                {
                    "coordinate": row["coordinate"],
                    "pid": pid,
                    "category": "child_evidence_rejected",
                    "evidence": failure_projection(error, stage, body, footer_body),
                }
            )
    names = {path.name for path in directory.iterdir()}
    expected_names = {str(pid) + suffix for pid in seen for suffix in (".json", ".json.done")}
    return {
        "schema": "hol-guard.priority-child-reports.v1",
        "rows": reports,
        "failures": failures,
        "unexpected_sidecars": len(names - expected_names),
        "offered_children": len(seen),
        "observation_complete": not failures
        and len(reports) == 24
        and offered == wanted
        and names == expected_names
        and all(row["report"]["observation_complete"] is True and row["source_stage_coverage"] for row in reports),
        "qualification_eligible": False,
    }
