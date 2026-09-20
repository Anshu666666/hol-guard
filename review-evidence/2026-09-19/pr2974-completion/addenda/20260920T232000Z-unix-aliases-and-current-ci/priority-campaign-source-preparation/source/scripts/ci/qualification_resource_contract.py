"""Closed, stdlib-only admission for the finite Linux live-member witness."""

from __future__ import annotations

import json
from typing import Any

NAMES = ("child_and_grandchild", "reparented_member", "denied_private_memory")
METRICS = ("private_bytes", "rss_bytes", "processes", "threads", "descriptors")
_LIMIT = 128 * 1024


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("resource_duplicate_key")
        result[key] = value
    return result


def _integer(value: Any, minimum: int, maximum: int = 2**63 - 1) -> bool:
    return type(value) is int and minimum <= value <= maximum


def admit_facts(name: str, facts: Any) -> None:
    if type(facts) is not dict or set(facts) != {
        "member_count",
        "non_ancestry_members",
        "samples",
        "private_bytes",
        "rss_bytes",
        "metric_minimum_met",
        "only_worker_live_after",
        "orphan_reaped_by_worker",
        "denied_private_observed",
        "sampled_peak_only",
    }:
        raise ValueError("resource_facts_schema")
    if (
        type(facts["member_count"]) is not int
        or facts["member_count"] != (3 if name == "child_and_grandchild" else 2)
        or type(facts["non_ancestry_members"]) is not int
        or facts["non_ancestry_members"] != (1 if name == "reparented_member" else 0)
        or not _integer(facts["samples"], 30, 200)
        or not _integer(facts["rss_bytes"], 1)
        or facts["only_worker_live_after"] is not True
        or facts["orphan_reaped_by_worker"] is not False
        or facts["sampled_peak_only"] is not True
    ):
        raise ValueError("resource_facts_identity")
    minima = facts["metric_minimum_met"]
    if (
        type(minima) is not dict
        or set(minima) != set(METRICS)
        or any(type(value) is not bool for value in minima.values())
    ):
        raise ValueError("resource_metric_schema")
    denied = name == "denied_private_memory"
    if facts["denied_private_observed"] is not denied or (
        minima["private_bytes"] is not False if denied else not all(minima.values())
    ):
        raise ValueError("resource_metric_flags")
    if denied:
        if facts["private_bytes"] is not None:
            raise ValueError("resource_denial_not_null")
    elif (
        not _integer(facts["private_bytes"], (10 if name == "child_and_grandchild" else 8) * 1024 * 1024)
        or facts["rss_bytes"] < facts["private_bytes"]
    ):
        raise ValueError("resource_memory_witness")


def read_worker_report(body: bytes) -> dict[str, Any]:
    if len(body) > _LIMIT:
        raise ValueError("resource_report_size")
    report = json.loads(body, object_pairs_hook=_pairs)
    if (
        type(report) is not dict
        or set(report) != {"schema", "admitted", "admission_refusal", "controls", "passed"}
        or report["schema"] != "hol-guard.live-member-resource-controls.v1"
    ):
        raise ValueError("resource_report_schema")
    if type(report["admitted"]) is not bool or type(report["passed"]) is not bool:
        raise ValueError("resource_report_boolean")
    if report["admitted"] is False:
        if (
            report["admission_refusal"] not in {"accounting", "os", "other"}
            or report["controls"] != []
            or report["passed"] is not False
        ):
            raise ValueError("resource_refusal")
        return report
    rows = report["controls"]
    if report["admission_refusal"] is not None or type(rows) is not list or len(rows) != len(NAMES):
        raise ValueError("resource_roster")
    for name, row in zip(NAMES, rows, strict=True):
        if (
            type(row) is not dict
            or set(row) != {"name", "passed", "error", "facts"}
            or row["name"] != name
            or type(row["passed"]) is not bool
        ):
            raise ValueError("resource_control_schema")
        if row["error"] not in {None, "accounting", "assertion", "os", "other"} or row["passed"] != (
            row["error"] is None
        ):
            raise ValueError("resource_control_error")
        if row["passed"]:
            admit_facts(name, row["facts"])
        elif row["facts"] != {}:
            raise ValueError("resource_failed_facts")
    if report["passed"] != all(row["passed"] for row in rows):
        raise ValueError("resource_summary")
    return report
