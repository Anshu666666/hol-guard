"""Run the unchanged native oracle on the original returned child edge."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def digest(value: object) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(body) > 1_048_576:
        raise ValueError("cline_value_bound")
    return hashlib.sha256(body).hexdigest()


def semantic_facts(oracle: Any, case: Any, native: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    """Record presence/equality only; invoke the full unchanged oracle once."""
    expected = case.native_expected
    keys = set(oracle._SEMANTIC_FIELDS) | set(expected.fields)
    facts = {}
    for key in sorted(keys):
        actual = oracle._at_path(native, key)
        wanted = expected.fields.get(key, oracle._MISSING)
        facts[key] = {
            "present": actual is not oracle._MISSING,
            "expected_present": wanted is not oracle._MISSING,
            "same_type_and_value": type(actual) is type(wanted) and actual == wanted,
        }
    passed = True
    try:
        oracle.validate_native_result(case, native)
    except AssertionError:
        passed = False
    return passed, facts


def validate(
    config: dict[str, Any], arguments: object, edge: object, worker: Any, worker_result: object
) -> dict[str, Any]:
    # This import occurs after the original CLI call, with profiling restored.
    # Only the exact source-checkout scripts namespace is additionally admitted.
    source = Path(config["source_root"])
    sys.path.insert(0, str(source))
    from codex_plugin_scanner.guard.native_decision_receipt import (
        receipt_matches_edge,
        validate_native_decision_receipt,
    )
    from scripts import native_slo_workloads as oracle
    from scripts.native_slo_adapter import route_counts
    from scripts.native_slo_daemon_fixture import witnessed_route

    if Path(str(oracle.__file__)).resolve() != source / "scripts/native_slo_workloads.py":
        raise ValueError("cline_original_oracle_origin")
    case_data = dict(config["case"])
    for key in ("expected", "native_expected"):
        if case_data[key] is not None:
            values = dict(case_data[key])
            values["nonempty_fields"] = tuple(values["nonempty_fields"])
            case_data[key] = oracle.ExpectedResponse(**values)
    case = oracle.QualificationCase(**case_data)
    result: dict[str, Any] = {
        "complete": False,
        "original_validator_called": False,
        "original_worker_result_sha256": digest(worker_result),
    }
    if worker is not None:
        routes = dict(route_counts(worker.metrics.snapshot()))
        if set(routes) - {
            "native_resident",
            "native_oneshot",
            "native_fail_safe",
            "native_degraded",
            "python_semantic",
        }:
            raise ValueError("cline_route_label")
        result["original_worker_routes"] = routes
        try:
            result["original_worker_route"] = witnessed_route({}, routes)
        except RuntimeError:
            result["original_worker_route"] = "ambiguous"
    if worker is None or type(arguments) is not dict or type(edge) is not dict or type(edge.get("result")) is not dict:
        result["edge_shape_valid"] = False
        return result
    native = edge["result"]
    passed, fields = semantic_facts(oracle, case, native)
    receipt = validate_native_decision_receipt(edge.get("receipt"))
    snapshot = arguments.get("policy_snapshot")
    result.update(
        original_validator_called=True,
        original_native_validation_passed=passed,
        semantic_fields=fields,
        edge_sha256=digest(edge),
        native_result_sha256=digest(native),
        original_payload_sha256=digest(arguments.get("payload")),
        declared_payload_sha256=digest(case.payload),
        payload_equal=arguments.get("payload") == case.payload,
        edge_shape_valid=True,
        receipt_matches_original_edge=receipt_matches_edge(edge, receipt),
        receipt_accepted_by_original_worker=receipt is not None and worker.last_native_decision_receipt == receipt,
        python_oracle_disabled=worker.test_oracle is None,
    )
    result["request_context_equal"] = (
        arguments.get("harness") == case.harness
        and arguments.get("event") == case.canonical_event
        and str(arguments.get("cwd")) == config["workspace"]
        and str(arguments.get("home_dir")) == config["home"]
        and str(arguments.get("guard_home")) == config["guard_home"]
        and arguments.get("source_ref_external_allowed") is False
        and arguments.get("observe_mode") is False
    )
    result["policy_binding_valid"] = (
        receipt is not None
        and type(snapshot) is dict
        and snapshot.get("mode") == "enforce"
        and all(
            receipt.get(key) == snapshot.get(other)
            for key, other in (
                ("policy_generation", "generation"),
                ("policy_digest", "policy_digest"),
                ("runtime_identity", "runtime_identity"),
            )
        )
        and receipt.get("runtime_identity") == config["runtime_identity"]
        and receipt.get("rule_digest") == config["rule_digest"]
    )
    result["complete"] = (
        passed
        and result["payload_equal"]
        and result["request_context_equal"]
        and result["policy_binding_valid"]
        and result["receipt_matches_original_edge"]
        and result["receipt_accepted_by_original_worker"]
        and result["python_oracle_disabled"]
        and result["original_worker_route"] == case.expected_route
    )
    return result
