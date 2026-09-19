"""Print bounded allowlisted facts from a completed workspace witness.

This reader imports no Guard code, starts no processes, and changes no witness
acceptance condition. Original receipt bytes remain untouched. Missing or
malformed evidence is printed as a fixed diagnostic state, never as a traceback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

PHASES = ("initial", "unchanged", "stricter_overlay", "coalesced_burst", "public_policy", "resident_restart")
OWNER_FLAGS = (
    "verified",
    "initial_children_empty",
    "enabled_before_spawn",
    "worker_exit_observed",
    "descendants_exhausted",
    "timed_out",
    "limit_exceeded",
    "containment_failed",
)
KNOWN_FAILURES = frozenset(
    {
        "observational_ownership_not_verified",
        "worker_receipt_missing",
        "collector_attempt_failed",
        "installed_members_changed",
        "witness_sources_changed",
        "collector_installed_identity",
        "installed_members_changed_during_worker",
        "copied_helper_changed",
        "production_import_escaped_installed_package",
    }
)
EXCEPTIONS = frozenset(
    {
        "AssertionError",
        "ChildProcessError",
        "FileNotFoundError",
        "KeyError",
        "OSError",
        "PermissionError",
        "ProcessLookupError",
        "RuntimeError",
        "TimeoutError",
        "TypeError",
        "ValueError",
    }
)
ERROR_CATEGORIES = EXCEPTIONS | {
    "AttributeError",
    "BlockingIOError",
    "BrokenPipeError",
    "ConnectionError",
    "ConnectionAbortedError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "FileExistsError",
    "ImportError",
    "InterruptedError",
    "IsADirectoryError",
    "ModuleNotFoundError",
    "NotADirectoryError",
    "NotImplementedError",
    "JSONDecodeError",
    "GuardConfigSourceError",
    "CodexHookIntegrityError",
    "Failure",
    "AccessDenied",
    "NoSuchProcess",
    "ZombieProcess",
}
# These are identifiers in the pinned source, never arbitrary receipt strings.
ERROR_ORIGINS = frozenset(
    f"{module}.{routine}"
    for module, routines in {
        "native_slo_workspace": ("_cell", "_control"),
        "native_slo_daemon_fixture": (
            "__init__",
            "__enter__",
            "_receive",
            "control",
            "_serve",
            "_serve_session",
            "close",
        ),
        "native_slo_resources": ("_psutil", "__init__", "__enter__", "_sample", "_inventory"),
        "native_slo_session": ("__init__", "__enter__", "start", "close", "_request"),
        "native_slo_workspace_server": (
            "__init__",
            "dispatch",
            "startup_failure",
            "phase",
            "_ack",
            "_chain",
            "_probe",
            "_overlay",
        ),
        "native_slo_mixed_witness": ("__init__", "__enter__"),
        "native_slo_mixed_receipt_reader": ("__init__",),
        "native_slo_qualification_scenarios": ("validate_receipt_profile",),
        "native_slo_workspace_trace": ("startup_rows", "validate_trace"),
        "config_source_io": (
            "capture_guard_config",
            "_posix_parent_chain",
            "_capture_in_parent",
            "_validate_file",
            "_directory_identity",
            "_read_descriptor",
            "_verify_missing_parent",
        ),
        "server": ("__init__", "start", "_begin_owned_service", "_complete_owned_service_after_listen"),
        "socket": ("getfqdn",),
        "http.server": ("HTTPServer.server_bind",),
        "socketserver": ("TCPServer.server_bind", "TCPServer.server_activate"),
    }.items()
    for routine in routines
)
STARTUP_STAGES = (
    "spawn",
    "construct",
    "construct_workspace",
    "construct_store",
    "construct_daemon",
    "register_workspace",
    "start",
    "fault",
    "serve",
    "cleanup",
)
ERROR_MESSAGES = {
    ("RuntimeError", "workspace installed witness setup failed"): "workspace_start_failed",
    (
        "RuntimeError",
        "workspace qualification requires exact installed native authority",
    ): "workspace_native_authority_rejected",
    ("RuntimeError", "workspace observer must precede publisher startup"): "workspace_publisher_already_started",
    ("RuntimeError", "workspace initial compilation cache must be empty"): "workspace_initial_cache_not_empty",
    ("RuntimeError", "workspace registration was not accepted"): "workspace_registration_rejected",
    ("RuntimeError", "workspace registration count mismatch"): "workspace_registration_mismatch",
    (
        "RuntimeError",
        "qualification resources require the pinned psutil development dependency",
    ): "psutil_dependency_unavailable",
    ("RuntimeError", "candidate binding-aware receipt getter unavailable"): "receipt_getter_unavailable",
    ("RuntimeError", "native_installed_slo_failed: native policy was not ready"): "native_policy_not_ready",
    (
        "RuntimeError",
        "native_installed_slo_failed: native readiness exceeded budget",
    ): "native_readiness_budget_exceeded",
    **{
        ("RuntimeError", message): message.replace(" ", "_")
        for message in (
            "workspace phase starting authority unavailable",
            "workspace resident containment failed",
            "workspace unnotified reconciliation deadline",
            "workspace authenticated acknowledgment deadline",
            "workspace observed publication chain deadline",
            "workspace observed compilation count invalid",
            "adapter request failed",
            "adapter response exceeded bound",
            "adapter response was not JSON",
        )
    },
    (
        "RuntimeError",
        "native_installed_slo_failed: adapter response was not an object",
    ): "adapter_response_not_object",
    **{
        ("RuntimeError", message): message.replace(" ", "_")
        for message in (
            "daemon fixture did not acknowledge readiness",
            "daemon fixture process containment failed",
            "daemon fixture cleanup was not acknowledged",
            "daemon fixture operation failed",
            "daemon fixture invalid progress stage",
            "daemon fixture invalid startup evidence",
            "daemon fixture invalid failure evidence",
            "daemon fixture unavailable",
        )
    },
    **{
        ("RuntimeError", f"daemon fixture {condition} at {stage}"): f"daemon_{condition.replace(' ', '_')}_{stage}"
        for condition in ("deadline", "stream unavailable")
        for stage in STARTUP_STAGES
    },
    **{
        ("Failure", code): code
        for code in (
            "unexpected_disposable_home",
            "private_directory_identity",
            "registration_after_publisher_start",
            "preexisting_compact_socket_directory",
            "private_registry_write",
        )
    },
    **{
        ("GuardConfigSourceError", code): code
        for code in (
            "guard_config_parent_not_directory",
            "guard_config_not_regular",
            "guard_config_link_count",
            "guard_config_too_large",
            "guard_config_descriptor_io_unavailable",
            "guard_config_parent_changed",
            "guard_config_changed",
            "guard_config_name_invalid",
            "guard_config_scope_changed",
            "guard_config_scope_rejected",
            "guard_config_source_unavailable",
        )
    },
}
ERROR_DIGEST_CODES = {
    (category, hashlib.sha256(message.encode()).hexdigest()): code
    for (category, message), code in ERROR_MESSAGES.items()
}
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 32768
EVENT_KINDS = ("compile", "push", "transport_ack", "barrier")
CACHE_CHECKS = (
    "acknowledged_compilation_observed",
    "registered_scopes_complete",
    "compiled_cache_complete",
    "load_records_valid",
    "compile_load_counts_reconcile",
    "all_scopes_loaded_once",
    "unchanged_scopes_reused",
    "only_stricter_scope_recompiled",
    "all_changed_scopes_captured",
)
PHASE_TIMES = (
    "mutation_ms",
    "registration_ms",
    "elapsed_ms",
    "accepted_ms",
    "acknowledgment_observed_ms",
    "accept_to_ack_ms",
    "accept_to_first_native_ms",
    "accept_to_delivered_response_ms",
    "readiness_deadline_ms",
)
ACK_PREDICATES = (
    "prepared_mapping",
    "snapshot_mapping",
    "snapshot_binding_present",
    "prepared_binding_matches",
    "authenticated_readback_matches",
    "generation_at_least_floor",
    "enforce_mode",
    "effective_mapping",
    "default_action_matches",
    "subprocess_action_matches",
    "strict_not_required",
    "sandbox_strict",
    "within_deadline",
    "retry_deadline_reached",
)
ACK_STAGES = (
    "prepare",
    "snapshot",
    "mapping_predicates",
    "authenticated_readback",
    "snapshot_fields",
    "authority_predicates",
    "accepted",
    "retry_clock",
    "deadline",
    "sleep",
)


class ProjectionError(ValueError):
    """An invalid selected field, with no receipt content in the exception."""


def require(condition: bool) -> None:
    if not condition:
        raise ProjectionError()


def mapping(value: Any) -> dict[str, Any]:
    require(type(value) is dict)
    return value


def flag(value: Any) -> bool | None:
    require(value is None or type(value) is bool)
    return value


def integer(value: Any, low: int = 0, high: int = 1048576) -> int | None:
    require(value is None or (type(value) is int and low <= value <= high))
    return value


def status(value: Any) -> str | None:
    require(value is None or value in ("passed", "failed"))
    return value


def sha(value: Any) -> str | None:
    require(value is None or (type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None))
    return value


def failure_counts(value: Any) -> dict[str, Any]:
    require(type(value) is list and len(value) <= 64)
    require(all(type(item) is str for item in value))
    return {
        "count": len(value),
        "known_codes": [item for item in value if item in KNOWN_FAILURES],
        "other_count": sum(item not in KNOWN_FAILURES for item in value),
    }


def exception_kind(value: Any) -> str | None:
    if value is None:
        return None
    return value if type(value) is str and value in EXCEPTIONS else "other_exception"


def error_location(value: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    origin = value.get(prefix + "origin")
    return {
        "origin": origin if type(origin) is str and origin in ERROR_ORIGINS else None,
        "line": integer(value.get(prefix + "line"), 1, 1048576),
        "errno": integer(value.get(prefix + "errno"), 0, 4095),
    }


def error_detail(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    detail = mapping(value)
    if detail.get("schema") != "hol-guard.native-qualification-failure.v1":
        return {"state": "unavailable"}
    category = detail.get("category")
    category = category if type(category) is str and category in ERROR_CATEGORIES else None
    digest = sha(detail.get("diagnostic_digest"))
    stack = detail.get("startup_stack", [])
    require(type(stack) is list and len(stack) <= 8)
    causes = []
    count = integer(detail.get("config_cause_count"), 0, 3)
    for index in range(1, (count or 0) + 1):
        prefix = f"config_cause_{index}_"
        cause = detail.get(prefix + "category")
        causes.append(
            {
                "category": cause if type(cause) is str and cause in ERROR_CATEGORIES else None,
                **error_location(detail, prefix),
                "winerror": integer(detail.get(prefix + "winerror"), 0, 0xFFFFFFFF),
            }
        )
    return {
        "state": "projected",
        "category": category,
        "known_message_code": ERROR_DIGEST_CODES.get((category, digest)),
        **error_location(detail),
        "startup_stack": [error_location(mapping(row)) for row in stack],
        "config_diagnostic_available": flag(detail.get("config_diagnostic_available")),
        "config_causes": causes,
        **{
            name: flag(detail.get(name))
            for name in ("config_cause_cycle", "config_cause_truncated", "config_cause_unavailable")
        },
        "workspace_observation_present": detail.get("workspace_observation") is not None,
    }


def cell_failure(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    detail = mapping(value)
    return {
        "primary": error_detail(detail.get("primary", detail)),
        "trace_failure": error_detail(detail.get("trace_failure")),
        "startup_trace_retained": flag(detail.get("startup_trace_retained")),
    }


def timing_recorded(cell: dict[str, Any], name: str) -> bool:
    if name not in cell:
        return False
    value = cell[name]
    require(type(value) in (int, float) and 0 <= value <= 86400000)
    return True


def main_receipt(value: dict[str, Any]) -> dict[str, Any]:
    require(value.get("schema") == "installed-workspace-publication-witness.v1")
    worker_failures = value.get("worker_failures")
    owner = mapping(value.get("owned_descendant_boundary", {}))
    streams = mapping(value.get("bounded_streams", {}))
    cleanup = mapping(value.get("cleanup", {}))
    projected_owner: dict[str, Any] = {name: flag(owner.get(name)) for name in OWNER_FLAGS}
    for name in ("termination_signals_sent", "adopted_signalled_exits", "reaped_process_count"):
        projected_owner[name] = integer(owner.get(name))
    projected_owner["worker_return_code"] = integer(owner.get("worker_return_code"), -64, 255)
    projected_owner["exit_statuses_sha256"] = sha(owner.get("exit_statuses_sha256"))
    for name in ("observation_failure", "cleanup_failure"):
        projected_owner[name] = exception_kind(owner.get(name))
    return {
        "result": status(value.get("result")),
        "failures": failure_counts(value.get("failures", [])),
        "worker_returncode": integer(value.get("worker_returncode"), -64, 255),
        "worker_result": status(value.get("worker_result")),
        "worker_failures": None if worker_failures is None else failure_counts(worker_failures),
        "ownership": projected_owner,
        "streams": {name: integer(streams.get(name), 0, 256 * 1024) for name in ("stdout_bytes", "stderr_bytes")},
        "stream_hashes": {name: sha(streams.get(name)) for name in ("stdout_sha256", "stderr_sha256")},
        "installed_members_unchanged": flag(value.get("installed_members_unchanged")),
        "harness_sources_unchanged": flag(value.get("harness_sources_unchanged")),
        "complete_receipt_bindings_passed": flag(value.get("complete_receipt_bindings_passed")),
        "implemented_checks_passed": flag(value.get("implemented_checks_passed")),
        "cleanup": {
            name: flag(cleanup.get(name))
            for name in ("owned_descendants_exhausted", "private_material_removed", "failure_material_retained")
        },
    }


def worker_receipt(value: dict[str, Any]) -> dict[str, Any]:
    require(value.get("schema") == "installed-workspace-worker.v1")
    return {
        "result": status(value.get("result")),
        "failures": failure_counts(value.get("failures", [])),
        "complete_receipt_bindings_passed": flag(value.get("complete_receipt_bindings_passed")),
        "implemented_checks_passed": flag(value.get("implemented_checks_passed")),
        "installed_members_unchanged": flag(value.get("installed_members_unchanged")),
    }


def milliseconds(value: Any, *, offset: bool = False) -> int | float | None:
    low = -86400000 if offset else 0
    require(value is None or (type(value) in (int, float) and low <= value <= 86400000))
    return value


def event_counts(value: Any, *, report: bool = False) -> dict[str, int | None] | None:
    if value is None:
        return None
    counts = mapping(value)
    names = (*EVENT_KINDS, "overflow", "scope_overflow") if report else EVENT_KINDS
    return {name: integer(counts.get(name, 0), 0, 1048576 if report else 256) for name in names}


def observer_report(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    report = mapping(value)
    active = report.get("active_stages_at_freeze")
    if active is not None:
        active = mapping(active)
        require(set(active) == set(EVENT_KINDS))
        active = {kind: integer(active[kind]) for kind in EVENT_KINDS}
        require(all(count is not None for count in active.values()))
        require(sum(active.values()) == integer(report.get("calls_in_flight_at_freeze")))
    return {
        "events": integer(report.get("events"), 0, 256),
        "event_bound": integer(report.get("event_bound"), 256, 256),
        "counts": event_counts(report.get("counts"), report=True),
        "complete": flag(report.get("complete")),
        "calls_in_flight_at_freeze": integer(report.get("calls_in_flight_at_freeze"), 0, 1048576),
        "active_stages_at_freeze": active,
        "headline_timing_eligible": flag(report.get("headline_timing_eligible")),
    }


def ack_observation(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    detail = mapping(value)
    require(detail.get("schema") == "workspace_ack_observation.v1")
    require(detail.get("stage") in ACK_STAGES)
    require(set(detail) >= {*ACK_PREDICATES, "schema", "stage", "iteration"})
    iteration = integer(detail.get("iteration"), 1)
    require(iteration is not None)
    return {
        "iteration": iteration,
        "stage": detail["stage"],
        "predicates": {name: flag(detail[name]) for name in ACK_PREDICATES},
        "null_means_unexecuted_or_non_boolean": True,
    }


def phase_observation(phase: dict[str, Any], index: int) -> dict[str, Any]:
    checks = mapping(phase.get("cache_feature_checks", {}))
    return {
        "offered_phase": PHASES[index],
        "observer_counts_at_phase_return": event_counts(phase.get("observer_counts")),
        "config_loads": integer(phase.get("config_loads")),
        "offered_writes": integer(phase.get("offered_writes"), 0, 32),
        "last_ack_observation": ack_observation(phase.get("ack_observation")),
        "cache_feature_checks": {name: flag(checks[name]) for name in CACHE_CHECKS if name in checks},
        "recorded_times": {
            name: milliseconds(phase[name], offset=name == "accepted_ms") for name in PHASE_TIMES if name in phase
        },
    }


def private_binding(value: Any) -> dict[str, Any] | None:
    """Validate authority identifiers for equality only; never export their bytes."""
    if value is None:
        return None
    binding = mapping(value)
    require(set(binding) == {"generation", "policy_digest", "runtime_identity"})
    require(integer(binding["generation"], 1, 2**64 - 1) is not None)
    require(sha(binding["policy_digest"]) is not None and sha(binding["runtime_identity"]) is not None)
    return binding


def validate_event(value: Any, count: int) -> dict[str, Any]:
    event = mapping(value)
    kind = event.get("kind")
    require(kind in EVENT_KINDS)
    require(integer(event.get("phase"), 0, 5) is not None)
    integer(event.get("publication"), 1, 1048576)
    started, finished = milliseconds(event.get("started_ms")), milliseconds(event.get("finished_ms"))
    require(started is not None and finished is not None and started <= finished)
    require(milliseconds(event.get("thread_cpu_ms")) is not None)
    state = {"compile": "succeeded", "push": "returned", "transport_ack": "validated", "barrier": "ready"}[kind]
    require(flag(event.get(state)) is not None)
    if kind == "compile":
        scopes = event.get("scope_loads")
        require(type(scopes) is list and len(scopes) == count + 1)
        require(all(integer(load, 0, 255) is not None for load in scopes))
        for name in ("config_loads", "unregistered_loads", "config_load_failures", "registered_workspaces"):
            require(integer(event.get(name)) is not None)
        integer(event.get("cache_entries"))
        require(flag(event.get("scope_counts_overflow")) is not None)
        for name in ("config_load_wall_ms", "config_load_thread_cpu_ms"):
            require(milliseconds(event.get(name)) is not None)
    else:
        private_binding(event.get("binding"))
    return event


def completed_span(event: dict[str, Any], expected: Any, accepted: Any) -> dict[str, Any]:
    """A completed observer span is not an accepted phase or a live-process check."""
    kind = event["kind"]
    state = {"compile": "succeeded", "push": "returned", "transport_ack": "validated", "barrier": "ready"}[kind]
    result = {
        "outcome": event[state],
        "wall_ms": event["finished_ms"] - event["started_ms"],
        "thread_cpu_ms": event["thread_cpu_ms"],
        "started_after_accept_ms": None if accepted is None else event["started_ms"] - accepted,
        "finished_after_accept_ms": None if accepted is None else event["finished_ms"] - accepted,
        "has_publication_identity": event.get("publication") is not None,
    }
    if kind == "compile":
        result.update(
            {
                name: event.get(name)
                for name in (
                    "config_loads",
                    "config_load_failures",
                    "unregistered_loads",
                    "cache_entries",
                    "registered_workspaces",
                    "scope_counts_overflow",
                    "config_load_wall_ms",
                    "config_load_thread_cpu_ms",
                )
            }
        )
        result["scopes_with_loads"] = sum(load > 0 for load in event["scope_loads"])
        result["scope_load_total"] = sum(event["scope_loads"])
    else:
        result["binding_present"] = event.get("binding") is not None
        result["matches_phase_binding"] = None if expected is None else event.get("binding") == expected
    return result


def observed_chain(rows: list[dict[str, Any]], expected: Any, accepted: Any, final_compile: bool) -> dict[str, Any]:
    """Replay only the recorded chain predicate, without its live deadline loop."""
    if expected is None or accepted is None:
        return {"state": "phase_binding_or_acceptance_unavailable"}
    for barrier in reversed(rows):
        attempt = barrier.get("publication")
        if (
            barrier["kind"] != "barrier"
            or barrier["ready"] is not True
            or attempt is None
            or barrier.get("binding") != expected
        ):
            continue
        current = [row for row in rows if row.get("publication") == attempt]
        compiled = [row for row in current if row["kind"] == "compile" and row["succeeded"] is True]
        pushed = [
            row
            for row in current
            if row["kind"] == "push" and row["returned"] is True and row.get("binding") == expected
        ]
        acks = [
            row
            for row in current
            if row["kind"] == "transport_ack" and row["validated"] is True and row.get("binding") == expected
        ]
        if not compiled or not pushed or not acks:
            continue
        compilation, push, ack = compiled[-1], pushed[-1], acks[-1]
        if not (
            compilation["started_ms"]
            <= compilation["finished_ms"]
            <= push["started_ms"]
            <= push["finished_ms"]
            <= ack["finished_ms"]
            <= barrier["finished_ms"]
        ) or (final_compile and compilation["started_ms"] < accepted):
            continue
        return {
            "state": "ordered_matching_chain_observed",
            "compile_started_after_accept_ms": compilation["started_ms"] - accepted,
            "ack_finished_after_accept_ms": ack["finished_ms"] - accepted,
            "barrier_finished_after_accept_ms": barrier["finished_ms"] - accepted,
        }
    return {"state": "no_ordered_matching_chain_in_retained_rows"}


def publication_observation(rows: list[dict[str, Any]], count: int) -> dict[str, Any]:
    """Inspect the final offered phase after collection; never alter its outcome.

    Events are tagged at publication entry and may finish after a phase returns.
    Missing spans establish only absence in retained rows, especially when the
    observer reports overflow or calls still in flight at freeze.
    """
    selected = [row for row in rows if row.get("registered_workspaces") == count]
    offers = [
        row.get("phase")
        for row in selected
        if row.get("kind") == "control_offer" and row.get("operation") == "workspace_phase"
    ]
    require(len(offers) <= 6 and offers == list(PHASES[: len(offers)]))
    if not offers:
        return {"state": "no_phase_offered"}
    terminals = [
        mapping(row.get("result"))
        for row in selected
        if row.get("kind") == "control_terminal" and row.get("operation") == "workspace_phase"
    ]
    identities = [row for row in selected if row.get("kind") == "phase_identity"]
    finishes = [
        mapping(row.get("result"))
        for row in selected
        if row.get("kind") == "control_terminal" and row.get("operation") == "workspace_finish"
    ]
    require(len(terminals) == len(identities) == len(offers) and len(finishes) == 1)
    for index, (terminal, identity) in enumerate(zip(terminals, identities, strict=True)):
        require(terminal.get("phase") in (None, PHASES[index]) and identity.get("phase") == PHASES[index])
        require(private_binding(terminal.get("binding")) == private_binding(identity.get("binding")))
    raw_events = [mapping(row.get("event")) for row in selected if row.get("kind") == "publisher_event"]
    require(len(raw_events) <= 256)
    raw_report = mapping(finishes[0].get("observer"))
    report = observer_report(raw_report)
    encoded = json.dumps(raw_events, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    require(report is not None and report["events"] == len(raw_events) and report["event_bound"] == 256)
    require(sha(raw_report.get("event_digest")) == hashlib.sha256(encoded).hexdigest())
    events = [validate_event(event, count) for event in raw_events]
    counts = report["counts"]
    require(counts is not None and all(value is not None for value in counts.values()))
    require(sum(counts[kind] for kind in EVENT_KINDS) == len(events) + counts["overflow"])
    require(all(sum(event["kind"] == kind for event in events) <= counts[kind] for kind in EVENT_KINDS))
    require(counts["scope_overflow"] <= counts["compile"])
    require(
        report["complete"]
        is (counts["overflow"] == counts["scope_overflow"] == 0 and report["calls_in_flight_at_freeze"] in (None, 0))
    )
    require(report["headline_timing_eligible"] is False)
    require(all(event["phase"] < len(offers) for event in events))
    index = len(offers) - 1
    phase = terminals[-1]
    current = [event for event in events if event["phase"] == index]
    expected = private_binding(phase.get("binding"))
    accepted = milliseconds(phase.get("accepted_ms"), offset=True)
    groups = {kind: [event for event in current if event["kind"] == kind] for kind in EVENT_KINDS}
    outcomes = {"compile": "succeeded", "push": "returned", "transport_ack": "validated", "barrier": "ready"}
    return {
        "state": "retained_trace_digest_verified",
        "scope": "post_attempt_final_offered_phase_not_live_acceptance",
        "offered_phase": PHASES[index],
        "observer": report,
        "retained_counts_by_phase": [
            {
                "phase": name,
                **{
                    kind: sum(event["phase"] == ordinal and event["kind"] == kind for event in events)
                    for kind in EVENT_KINDS
                },
            }
            for ordinal, name in enumerate(PHASES[: len(offers)])
        ],
        "phase_binding_recorded": expected is not None,
        "acceptance_time_recorded": accepted is not None,
        "retained_publication_identities": len(
            {event["publication"] for event in current if event.get("publication") is not None}
        ),
        "compiles_without_publication_identity": sum(event.get("publication") is None for event in groups["compile"]),
        "completed_outcomes": {
            kind: {
                "true": sum(event[outcomes[kind]] is True for event in values),
                "false": sum(event[outcomes[kind]] is False for event in values),
            }
            for kind, values in groups.items()
        },
        "last_completed_spans": {
            kind: completed_span(values[-1], expected, accepted) if values else None for kind, values in groups.items()
        },
        "recorded_chain": observed_chain(current, expected, accepted, PHASES[index] == "coalesced_burst"),
        "ack_predicate_bits_recorded": ack_observation(phase.get("ack_observation")) is not None,
    }


def bounded_publication_observation(rows: list[dict[str, Any]], count: int) -> dict[str, Any]:
    try:
        return publication_observation(rows, count)
    except (ValueError, TypeError, KeyError):
        return {"state": "unavailable_or_invalid"}


def collector_receipt(value: dict[str, Any]) -> dict[str, Any]:
    require(value.get("scope") == "installed_workspace_publication_diagnostic")
    cells = value.get("cells", [])
    require(type(cells) is list and len(cells) <= 3)
    projected = []
    seen = set()
    for cell_value in cells:
        cell = mapping(cell_value)
        count = cell.get("registered_workspaces")
        require(type(count) is int and count in (1, 10, 100) and count not in seen)
        seen.add(count)
        phases = cell.get("phases", [])
        require(type(phases) is list and len(phases) <= 6)
        phase_rows = []
        for index, phase_value in enumerate(phases):
            phase = mapping(phase_value)
            # Failed control replies may omit their phase label; the offered
            # ordinal still maps to the unchanged six-phase source contract.
            require(phase.get("phase") is None or phase["phase"] == PHASES[index])
            phase_rows.append(
                {
                    "offered_phase": PHASES[index],
                    "label_present": phase.get("phase") is not None,
                    "failure_present": phase.get("failure") is not None,
                    "failure": error_detail(phase.get("failure")),
                    **{
                        name: flag(phase.get(name))
                        for name in (
                            "passed",
                            "installed_runtime_matches",
                            "first_native_receipt_matches",
                            "authenticated_ack",
                            "cache_feature_checks_passed",
                        )
                    },
                }
            )
        unvisited = cell.get("unvisited_phases")
        require(type(unvisited) is list and len(unvisited) <= 6)
        offered = 6 - len(unvisited)
        require(unvisited == list(PHASES[offered:]) and len(phases) <= offered)
        final = mapping(cell.get("final", {}))
        observation = mapping(final.get("complete_receipt_identity_observation", {}))
        require("resources" not in cell or type(cell["resources"]) is dict)
        projected.append(
            {
                "registered_workspaces": count,
                "passed": flag(cell.get("passed")),
                "fixture_contained": flag(cell.get("fixture_contained")),
                "failure_present": cell.get("failure") is not None,
                "construction": {
                    "startup_time_recorded": timing_recorded(cell, "startup_ms"),
                    "readiness_time_recorded": timing_recorded(cell, "startup_readiness_ms"),
                    "resources_recorded": "resources" in cell,
                    "retained_startup_events": integer(cell.get("retained_startup_events"), 0, 256),
                    "failure": cell_failure(cell.get("failure")),
                },
                "phases": phase_rows,
                "last_phase_observation": phase_observation(mapping(phases[-1]), len(phases) - 1) if phases else None,
                "offered_phases": offered,
                "unvisited_phases": unvisited,
                "final": {
                    **{
                        name: flag(final.get(name))
                        for name in (
                            "passed",
                            "receipt_bindings_validated",
                            "cache_feature_checks_passed",
                            "writer_drained",
                        )
                    },
                    **{
                        name: integer(final.get(name), 0, 6)
                        for name in (
                            "completed_phases",
                            "receipt_count",
                            "committed_receipts",
                        )
                    },
                    "complete_receipt_observation_passed": flag(observation.get("passed")),
                    "complete_receipt_count": integer(observation.get("receipt_count"), 0, 6),
                },
            }
        )
    return {
        **{
            name: flag(value.get(name))
            for name in (
                "declared_matrix_visited",
                "implemented_checks_passed",
                "authority_checks_passed",
            )
        },
        "cells": projected,
        "ledger_binding": {
            "records": integer(mapping(value.get("ledger", {})).get("records"), 0, 350000),
            "bytes": integer(mapping(value.get("ledger", {})).get("bytes"), 0, 256 * 1024 * 1024),
            "sha256": sha(mapping(value.get("ledger", {})).get("sha256")),
        },
    }


def publisher_ledger(rows: list[dict[str, Any]]) -> dict[str, Any]:
    require(bool(rows) and rows[0].get("kind") == "matrix_offer")
    counts = rows[0].get("counts")
    require(type(counts) is list and all(type(count) is int for count in counts) and counts == [1, 10, 100])
    cells: dict[int, dict[str, Any]] = {}
    active = None
    for row in rows[1:]:
        count = row.get("registered_workspaces")
        require(type(count) is int and count in (1, 10, 100))
        kind = row.get("kind")
        if kind == "cell_offer":
            require(count not in cells and active is None)
            active = count
            cells[count] = {
                "registered_workspaces": count,
                "cell_offer_present": True,
                "cell_terminal_present": False,
                "workspace_start_offer_present": False,
                "workspace_start_terminal_present": False,
                "workspace_start": None,
            }
            continue
        require(active == count and count in cells)
        cell = cells[count]
        if kind == "cell_terminal":
            cell["cell_terminal_present"] = True
            active = None
        elif kind in ("control_offer", "control_terminal"):
            operation = row.get("operation")
            require(operation in ("workspace_start", "workspace_phase", "workspace_finish", "workspace_page"))
            if operation != "workspace_start":
                continue
            if kind == "control_offer":
                require(not cell["workspace_start_offer_present"])
                cell["workspace_start_offer_present"] = True
            else:
                require(cell["workspace_start_offer_present"] and not cell["workspace_start_terminal_present"])
                cell["workspace_start_terminal_present"] = True
                result = mapping(row.get("result"))
                require(result.get("status") in ("completed", "failed"))
                cell["workspace_start"] = {
                    "status": result["status"],
                    "passed": flag(result.get("passed")),
                    "failure": error_detail(result.get("failure")),
                }
        else:
            require(kind in ("publisher_event", "phase_identity"))
    for count, cell in cells.items():
        cell["publication_observation"] = bounded_publication_observation(rows, count)
    return {"records": len(rows), "cells": list(cells.values())}


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        require(name not in result)
        result[name] = value
    return result


def read_receipt(path: Path, projector: Any, *, json_lines: bool = False) -> dict[str, Any]:
    record: dict[str, Any] = {"state": "unavailable"}
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_FILE_BYTES)
            data = handle.read(MAX_FILE_BYTES + 1)
            after = os.fstat(handle.fileno())
        record.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            not stat.S_ISREG(after.st_mode)
            or any(getattr(info, field) != getattr(after, field) for field in identity_fields)
            or len(data) != info.st_size
        ):
            record["state"] = "changed_during_read"
            return record
        if json_lines:
            lines = data.splitlines(keepends=True)
            require(0 < len(lines) <= 4096 and data.endswith(b"\n") and all(len(line) <= 8192 for line in lines))
            value: Any = [mapping(json.loads(line, object_pairs_hook=strict_object)) for line in lines]
        else:
            value = mapping(json.loads(data, object_pairs_hook=strict_object))
        record.update(state="projected", facts=projector(value))
    except (OSError, ValueError, TypeError, RecursionError):
        record["state"] = "unavailable_or_invalid"
    return record


def summary(directory: Path) -> dict[str, Any]:
    collector = read_receipt(directory / "collector-report.json", collector_receipt)
    ledger = read_receipt(directory / "publisher-ledger.jsonl", publisher_ledger, json_lines=True)
    if ledger["state"] == "projected":
        binding = collector.get("facts", {}).get("ledger_binding", {})
        if binding != {"records": ledger["facts"]["records"], "bytes": ledger["bytes"], "sha256": ledger["sha256"]}:
            ledger.pop("facts")
            ledger["state"] = "collector_binding_unavailable_or_mismatched"
    return {
        "schema": "workspace-ownership-log-summary.v2",
        "qualification_claimed": False,
        "original_acceptance_unchanged": True,
        "witness": read_receipt(directory / "receipt.json", main_receipt),
        "worker": read_receipt(directory / "worker-receipt.json", worker_receipt),
        "collector": collector,
        "publisher_ledger": ledger,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempt-directory", type=Path, required=True)
    args = parser.parse_args()
    result = summary(args.attempt_directory)
    content = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if len(content.encode("ascii")) > MAX_LOG_BYTES:
        print('{"schema":"workspace-ownership-log-summary.v2","state":"summary_bound_exceeded"}')
        return 1
    print(content)
    return int(
        any(result[name]["state"] != "projected" for name in ("witness", "worker", "collector", "publisher_ledger"))
    )


if __name__ == "__main__":
    raise SystemExit(main())
