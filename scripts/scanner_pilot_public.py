"""Finite scanner evidence projection and independent-run comparisons."""

from __future__ import annotations

import base64
import json
import random
import statistics
from typing import Any

from scripts.mcp_rebaseline_public_types import (
    SHA1,
    SHA256,
    array,
    boolean,
    choice,
    fields,
    integer,
    number,
    optional,
    require,
)
from scripts.native_slo_evidence_format import canonical, digest
from scripts.native_slo_qualification import paired_ratio_interval
from scripts.native_slo_statistics import percentile
from scripts.scanner_pilot_identity import EXECUTABLE_FAILURE_REASONS
from scripts.scanner_pilot_protocol import ARMS, ATTEMPTS, CASES, PAIRS, RUNS, SCHEMA, STATES, planned

FAILURES = (
    None,
    "command_deadline",
    "controller_deadline",
    "process_io_failed",
    "process_interrupted",
    "capture_byte_bound",
    "descendant_cleanup_required",
    "containment_unconfirmed",
    "unexpected_cli_exit",
    "cli_result_invalid",
    "detector_oracle_failed",
    "collector_operation_failed",
    "collector_failed",
    "source_identity_failed",
    "dependency_identity_failed",
    "python_executable_identity_failed",
    "native_executable_identity_failed",
)
SOURCE = fields(
    {
        **dict.fromkeys(("source_sha", "source_tree", "python_source_tree", "pilot_tree"), SHA1),
        **dict.fromkeys(
            (
                "scanner_sha256",
                "lock_sha256",
                "rust_lock_sha256",
                "harness_sha256",
                "dependency_sha256",
                "python_sha256",
                "binary_sha256",
            ),
            SHA256,
        ),
        "python_version": array(integer, 3),
        "host": fields(
            {
                "system": choice("linux"),
                "architecture": choice("x86_64"),
                "logical_cpus": integer,
                "image_identity_available": boolean,
                "runner_image_sha256": SHA256,
                "kernel_sha256": SHA256,
            }
        ),
    }
)
OBSERVATION = fields(
    {
        "id": choice(*(p["id"] for p in planned(CASES[0], 0))),
        "state": choice(*STATES),
        "pair": integer,
        "arm": choice(*ARMS),
        "status": choice("completed", "failed", "interrupted", "unoffered", "cache_unavailable"),
        "failure": choice(*FAILURES),
        "wall_ms": optional(number),
        "cpu_ms": optional(number),
        "stdout_sha256": optional(SHA256),
        "stderr_sha256": optional(SHA256),
        "stdout_bytes": optional(integer),
        "stderr_bytes": optional(integer),
        "result_sha256": optional(SHA256),
        "native_files": optional(integer),
        "fallback_files": optional(integer),
    }
)
REPORT = fields(
    {
        "schema": choice(SCHEMA),
        "selection": choice("smoke", "full"),
        "case": choice(*CASES),
        "run": integer,
        "source_sha": SHA1,
        "source": optional(SOURCE),
        "fixture_sha256": optional(SHA256),
        "planned": choice(ATTEMPTS),
        "observations": array(OBSERVATION, ATTEMPTS),
        "preflight_passed": boolean,
        "identity_verified_after": boolean,
        "worker_failure": choice(*FAILURES),
        "collection_complete": boolean,
        "installed_qualified": choice(False),
        "commitments_sha256": SHA256,
        "private_files": integer,
    },
    optional_fields={"identity_failure_reason": optional(choice(*EXECUTABLE_FAILURE_REASONS))},
)


def _identity_failure_reason(failure: Any, diagnostic: Any) -> str | None:
    if diagnostic is None:
        return None
    require(isinstance(diagnostic, dict))
    require(failure in ("python_executable_identity_failed", "native_executable_identity_failed"))
    return choice(*EXECUTABLE_FAILURE_REASONS)(diagnostic.get("reason"))


def _capture(value: Any) -> tuple[int, str]:
    require(isinstance(value, dict) and set(value) == {"bytes", "sha256", "base64"})
    length, identity = integer(value["bytes"]), SHA256(value["sha256"])
    require(length <= 8 * 1024 * 1024 and isinstance(value["base64"], str))
    raw = base64.b64decode(value["base64"], validate=True)
    require(len(raw) == length and digest(raw) == identity)
    return length, identity


def projection(
    snapshot: tuple[tuple[str, bytes], ...], *, source_sha: str, case: str, run: int, selection: str
) -> dict[str, Any]:
    values = {name: json.loads(data) for name, data in snapshot}
    plan = values["plan.json"]
    expected = planned(case, run)
    require(
        plan
        == {
            "schema": SCHEMA,
            "case": case,
            "run": run,
            "selection": selection,
            "source_sha": source_sha,
            "attempts": expected,
        }
    )
    require(selection == "full" or (selection == "smoke" and case == "working_provider_large" and run == 0))
    source = SOURCE(values["source.json"]) if "source.json" in values else None
    require(source is None or source["source_sha"] == source_sha)
    fixture = values.get("fixture.json")
    fixture_digest = None
    if fixture is not None:
        fixture_digest = SHA256(fixture["sha256"])
        require(digest(canonical({k: v for k, v in fixture.items() if k != "sha256"})) == fixture_digest)
    worker = values.get("worker.json", {})
    failure = choice(*FAILURES)(worker.get("failure"))
    identity_failure_reason = _identity_failure_reason(failure, worker.get("identity_failure"))
    preflight = values.get("preflight.json", {})
    preflight_passed = preflight.get("passed") is True
    if preflight_passed:
        SHA256(preflight["complete_result_sha256"])
        require(source is not None and fixture_digest is not None)
        variants = ["complete", "findings", "files", "bytes", "default", "missing"]
        if case != "working_many_unique":
            variants.append("finding-limit")
        require(preflight["variants"] == variants)
        for prefix in ["oracle", *("preflight-" + label for label in variants)]:
            left, right = [values[f"{prefix}-{arm}.terminal.json"] for arm in ARMS]
            require(
                left["status"] == right["status"] == "completed" and left["result_sha256"] == right["result_sha256"]
            )
    observations = []
    for attempt in expected:
        offered = values.get(attempt["id"] + ".offered.json")
        terminal = values.get(attempt["id"] + ".terminal.json")
        verified = values.get(attempt["id"] + ".verified.json")
        unavailable = any(
            values.get(f"cache-{attempt['state']}{suffix}.json", {}).get("status") == "unavailable"
            for suffix in ("", "-interrupted")
        )
        status = "cache_unavailable" if unavailable else "unoffered"
        observation: dict[str, Any] = {
            **attempt,
            "status": status,
            "failure": None,
            "wall_ms": None,
            "cpu_ms": None,
            "stdout_sha256": None,
            "stderr_sha256": None,
            "stdout_bytes": None,
            "stderr_bytes": None,
            "result_sha256": None,
            "native_files": None,
            "fallback_files": None,
        }
        if offered is not None:
            require(offered == attempt)
            observation["status"] = "interrupted"
        if terminal is not None:
            require(offered == attempt and terminal["identity"] == attempt)
            observation.update(status="failed", failure=choice(*FAILURES)(terminal["failure"]))
            process = terminal["process"]
            if process is not None:
                stdout, stderr = _capture(process["stdout"]), _capture(process["stderr"])
                observation.update(
                    wall_ms=number(process["full_cli_wall_ms"]),
                    cpu_ms=optional(number)(process["full_cli_process_tree_cpu_ms"]),
                    stdout_bytes=stdout[0],
                    stdout_sha256=stdout[1],
                    stderr_bytes=stderr[0],
                    stderr_sha256=stderr[1],
                )
            if verified is not None:
                require(
                    preflight_passed
                    and terminal["status"] == "completed"
                    and terminal["failure"] is None
                    and process is not None
                    and process["failure"] is None
                    and process["returncode"] == (0 if case == "working_many_unique" else 3)
                    and observation["cpu_ms"] is not None
                    and observation["cpu_ms"] > 0
                    and verified == {"verified": True, "result_sha256": preflight["complete_result_sha256"]}
                    and terminal["result_sha256"] == verified["result_sha256"]
                )
                assert isinstance(process, dict)
                observation.update(status="completed", result_sha256=verified["result_sha256"])
                if attempt["arm"] == "native_regex_pilot":
                    native, fallback = (
                        integer(process["native_pilot_native_files"]),
                        integer(process["native_pilot_python_fallback_files"]),
                    )
                    require(native > 0 and fallback == 0 and process["native_pilot_cleanup_failures"] == 0)
                    observation.update(native_files=native, fallback_files=fallback)
        observations.append(OBSERVATION(observation))
    complete = (
        len(observations) == ATTEMPTS
        and all(item["status"] == "completed" for item in observations)
        and failure is None
        and worker.get("finished") is True
        and worker.get("identity_verified_after") is True
    )
    commitments = [{"name": name, "bytes": len(data), "sha256": digest(data)} for name, data in snapshot]
    return REPORT(
        {
            "schema": SCHEMA,
            "selection": selection,
            "case": case,
            "run": run,
            "source_sha": source_sha,
            "source": source,
            "fixture_sha256": fixture_digest,
            "planned": ATTEMPTS,
            "observations": observations,
            "preflight_passed": preflight_passed,
            "identity_verified_after": worker.get("identity_verified_after") is True,
            "worker_failure": failure,
            "identity_failure_reason": identity_failure_reason,
            "collection_complete": complete,
            "installed_qualified": False,
            "commitments_sha256": digest(canonical(commitments)),
            "private_files": len(snapshot),
        }
    )


def validate_report(value: Any) -> dict[str, Any]:
    report = REPORT(value)
    reason = report.setdefault("identity_failure_reason", None)
    require(
        reason is None
        or report["worker_failure"] in ("python_executable_identity_failed", "native_executable_identity_failed")
    )
    require(0 <= report["run"] < RUNS and len(report["observations"]) == ATTEMPTS)
    require(
        [{k: row[k] for k in ("id", "state", "pair", "arm")} for row in report["observations"]]
        == planned(report["case"], report["run"])
    )
    require(report["selection"] == "full" or (report["case"] == "working_provider_large" and report["run"] == 0))
    for row in report["observations"]:
        if row["status"] == "completed":
            require(
                row["failure"] is None
                and row["cpu_ms"] is not None
                and row["cpu_ms"] > 0
                and row["wall_ms"] is not None
                and row["wall_ms"] > 0
                and row["result_sha256"] is not None
                and row["stdout_sha256"] is not None
                and row["stderr_sha256"] is not None
                and (
                    row["arm"] != "native_regex_pilot"
                    or (row["native_files"] is not None and row["native_files"] > 0 and row["fallback_files"] == 0)
                )
            )
    require(
        not report["collection_complete"]
        or (
            report["preflight_passed"]
            and report["identity_verified_after"]
            and report["worker_failure"] is None
            and report["source"] is not None
            and report["fixture_sha256"] is not None
            and all(
                row["status"] == "completed"
                and row["cpu_ms"] is not None
                and row["cpu_ms"] > 0
                and row["wall_ms"] is not None
                and row["wall_ms"] > 0
                and row["result_sha256"] is not None
                and (
                    row["arm"] != "native_regex_pilot"
                    or (row["native_files"] is not None and row["native_files"] > 0 and row["fallback_files"] == 0)
                )
                for row in report["observations"]
            )
        )
    )
    return report


def aggregate(reports: list[dict[str, Any]], *, selection: str, source_sha: str) -> dict[str, Any]:
    expected = (
        {(case, run) for case in CASES for run in range(RUNS)}
        if selection == "full"
        else {("working_provider_large", 0)}
    )
    observed = [validate_report(report) for report in reports]
    require(len({(r["case"], r["run"]) for r in observed}) == len(observed))
    require(
        all(
            (r["case"], r["run"]) in expected and r["source_sha"] == source_sha and r["selection"] == selection
            for r in observed
        )
    )
    cohorts = []
    for case in CASES if selection == "full" else ("working_provider_large",):
        shards = sorted((r for r in observed if r["case"] == case), key=lambda r: r["run"])
        for state in STATES:
            valid = [
                r
                for r in shards
                if r["identity_verified_after"]
                and r["preflight_passed"]
                and r["worker_failure"] is None
                and all(row["status"] == "completed" for row in r["observations"] if row["state"] == state)
            ]
            entry: dict[str, Any] = {
                "case": case,
                "cache_state": state,
                "independent_runs": len(valid),
                "required_runs": RUNS,
                "samples_per_arm": len(valid) * PAIRS,
                "comparison": None,
                "benefit_gate_passed": False,
                "run_hosts": [{"run": r["run"], **r["source"]["host"]} for r in valid],
            }
            if len(valid) == RUNS:
                require(
                    len({canonical({key: value for key, value in r["source"].items() if key != "host"}) for r in valid})
                    == 1
                )
                metrics = {}
                point = {}
                for field, label, summarize in (
                    ("wall_ms", "p95_wall", lambda values: percentile(values, 0.95)),
                    ("cpu_ms", "mean_cpu", statistics.mean),
                ):
                    left, right = [], []
                    all_values = [[], []]
                    for report in valid:
                        values = [
                            [
                                row[field]
                                for row in report["observations"]
                                if row["state"] == state and row["arm"] == arm
                            ]
                            for arm in ARMS
                        ]
                        left.append(summarize(values[0]))
                        right.append(summarize(values[1]))
                        for combined, per_run in zip(all_values, values, strict=True):
                            combined.extend(per_run)
                    metrics[label] = paired_ratio_interval(left, right)
                    # The shared presentation helper rounds to six decimals.
                    # Thresholds use the same paired bootstrap before rounding.
                    ratios = [right_value / left_value for left_value, right_value in zip(left, right, strict=True)]
                    generator = random.Random(0)
                    boot = [statistics.median(generator.choices(ratios, k=len(ratios))) for _ in range(2000)]
                    metrics[label]["ci95_high_unrounded"] = percentile(boot, 0.975)
                    point[label] = summarize(all_values[1]) / summarize(all_values[0])
                wall = max(point["p95_wall"], metrics["p95_wall"]["ci95_high_unrounded"])
                cpu = max(point["mean_cpu"], metrics["mean_cpu"]["ci95_high_unrounded"])
                entry.update(
                    comparison={"independent_runs": metrics, "pooled_point_ratios": point},
                    benefit_gate_passed=(wall <= 0.70 and cpu <= 1.05) or (cpu <= 0.70 and wall <= 1.05),
                )
            cohorts.append(entry)
    return {
        "schema": SCHEMA,
        "selection": selection,
        "source_sha": source_sha,
        "planned_shards": len(expected),
        "retained_shards": len(observed),
        "planned_attempts": len(expected) * ATTEMPTS,
        "complete_shards": sum(r["collection_complete"] for r in observed),
        "missing_shards": len(expected - {(r["case"], r["run"]) for r in observed}),
        "collection_complete": len(observed) == len(expected) and all(r["collection_complete"] for r in observed),
        "scope": "source_cli_experiment_no_installed_or_default_activation",
        "installed_qualified": False,
        "minimum_independent_runs_met": selection == "full" and all(c["independent_runs"] == RUNS for c in cohorts),
        "estimator": "paired_independent_run_ratio_median_and_bootstrap2000_of_six_sample_p95_or_mean_cpu",
        "cohorts": cohorts,
    }
