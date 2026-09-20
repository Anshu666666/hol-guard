"""Four original Cline cases, actual registration and a child-local edge witness."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from scripts.ci.cline_witness.identity import admit_installed
from scripts.ci.cline_witness.installation import Installation, code_frames, current_site
from scripts.ci.cline_witness.invocation import preflight
from scripts.ci.cline_witness.nested_run import validate as validate_nested_run
from scripts.ci.cline_witness.process_observation import normal_delivery
from scripts.ci.cline_witness.process_observation import validate as validate_process_observation
from scripts.ci.cline_witness.profile_runtime import encoded, pairs, private_read, write_report
from scripts.native_slo_adapter import route_counts
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_registered_surfaces import install_registered_surface
from scripts.native_slo_registered_surfaces_evidence import SurfaceAttempt, SurfaceEvidence
from scripts.native_slo_registered_surfaces_run import (
    SurfaceSession,
    _context,
    observe_registered_surface,
    surface_cases,
)
from scripts.native_slo_workloads import build_cases, validate_setup

ROOT = Path(__file__).resolve().parents[3]
CASE_IDS = (
    "cline/PreToolUse/benign/small",
    "cline/PreToolUse/dangerous/small",
    "cline/PostToolUse/benign/1k",
    "cline/PostToolUse/block/1k",
)


def require(value: bool, label: str) -> None:
    if not value:
        raise ValueError("cline_witness_" + label)


def load(path: Path) -> dict[str, Any]:
    value = json.loads(private_read(path, 131072), object_pairs_hook=pairs)
    require(type(value) is dict, "report_object")
    return value


def configuration(
    session: SurfaceSession, surface: Any, case: Any, identity: dict[str, Any], package: Path, observed_argv0: str
) -> dict[str, Any]:
    state_path = session.guard_home / "managed/cline/native-hooks-state.json"
    state = json.loads(state_path.read_bytes(), object_pairs_hook=pairs)
    worker = Path(state["workers"][case.event])
    worker_bytes = worker.read_bytes()
    require(hashlib.sha256(worker_bytes).hexdigest() == state["worker_sha256"][case.event], "worker_source")
    tree = ast.parse(worker_bytes)
    guard_values = [
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "GUARD" for target in node.targets)
    ]
    require(len(guard_values) == 1, "guard_command")
    guard = guard_values[0]
    mains = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"]
    require(len(mains) == 1, "worker_main")
    nested_calls = [
        node
        for node in ast.walk(mains[0])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "run"
    ]
    require(len(nested_calls) == 1, "worker_nested_call")
    cli = [*state["guard_cli_identity"]["command"], "guard", "hook"]
    require(
        guard == cli and cli == [sys.executable, "-I", "-s", "-m", "codex_plugin_scanner.cli", "guard", "hook"],
        "attested_cli",
    )
    selected = package / "guard/daemon/hook_worker.py"
    frames = code_frames(selected, {"HookWorker._review_raw_hook_native", "HookWorker.review_http_payload"}, "cline")
    for frame in frames:
        frame["role"] = "edge" if frame["qualname"].endswith("._review_raw_hook_native") else "worker"
    sources = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (
            selected,
            package / "guard/native_hook_edge.py",
            package / "guard/native_decision_receipt.py",
            ROOT / "scripts/native_slo_workloads.py",
            ROOT / "scripts/native_slo_workload_cases.py",
            ROOT / "tests/fixtures/guard-native-qualification/corpus.v1.json",
        )
    }
    argv = [[sys.executable, "-I", "-s", str(worker)], [*cli, "--harness", "cline", "--json"]]
    validation = Path(__file__).with_name("validation.py")
    return {
        "parent_pid": os.getpid(),
        "worker_source_sha256": hashlib.sha256(worker_bytes).hexdigest(),
        "nested_callsite": {"file": str(worker), "first_line": mains[0].lineno, "call_line": nested_calls[0].lineno},
        "registered_slot_argv_sha256": hashlib.sha256(encoded(surface.argv)).hexdigest(),
        "executable": sys.executable,
        "argv": argv,
        "observed_argv": [[observed_argv0, *row[1:]] for row in argv],
        "frames": frames,
        "method_source": str(selected),
        "sources": sources,
        "case": asdict(case),
        "home": str(session.root),
        "workspace": str(session.workspace),
        "guard_home": str(session.guard_home),
        "source_root": str(ROOT),
        "validation_path": str(validation),
        "validation_sha256": hashlib.sha256(validation.read_bytes()).hexdigest(),
        "runtime_identity": identity["runtime_sha256"],
        "rule_digest": identity["rule_digest"],
    }


def admit_method_observation(child: dict[str, Any]) -> None:
    require(child.get("schema") == "hol-guard.cline-child-edge.v3", "child_schema")
    require(child.get("callback_count_scope") == "selected_methods_only", "callback_count_scope")
    require(
        type(child.get("maximum_counted_callbacks")) is int and child["maximum_counted_callbacks"] == 0,
        "callback_count_bound",
    )
    require(type(child.get("callbacks")) is int and child["callbacks"] == 0, "callback_count")
    require(child.get("callbacks_saturated") is False, "callback_count_saturation")
    methods = child.get("method_observation")
    expected_methods = {
        "schema": "hol-guard.cline-selected-method-observation.v1",
        "selected_imports": 1,
        "bound": True,
        "finder_restored": True,
        "methods_restored": True,
        "faults": [],
        "global_profile_installed": False,
        "complete": True,
    }
    require(
        type(methods) is dict
        and set(methods) == set(expected_methods)
        and all(type(methods[key]) is type(value) and methods[key] == value for key, value in expected_methods.items()),
        "method_observation",
    )


def reconcile(worker: dict[str, Any], child: dict[str, Any], config: dict[str, Any], manifest: dict[str, Any]) -> None:
    digest = manifest["configuration_sha256"]
    require(worker.get("schema") == "hol-guard.cline-worker-start.v1", "worker_schema")
    if "method_source" in config:
        admit_method_observation(child)
    else:
        require(child.get("schema") == "hol-guard.cline-child-edge.v2", "child_schema")
        require(child.get("callback_count_scope") == "all_profile_events_saturating", "callback_count_scope")
        require(
            type(child.get("maximum_counted_callbacks")) is int and child["maximum_counted_callbacks"] == 2_000_000,
            "callback_count_bound",
        )
        require(type(child.get("callbacks")) is int and 4 <= child["callbacks"] <= 2_000_000, "callback_count")
        require(type(child.get("callbacks_saturated")) is bool, "callback_count_saturation_type")
        require(not child["callbacks_saturated"] or child["callbacks"] == 2_000_000, "callback_count_saturation")
    require(worker.get("configuration_sha256") == child.get("configuration_sha256") == digest, "configuration_join")
    require(type(worker.get("pid")) is int and worker["pid"] > 0, "worker_pid")
    require(type(child.get("pid")) is int and child["pid"] > 0 and child["pid"] != worker["pid"], "child_pid")
    require(
        worker.get("parent_pid") == config["parent_pid"] and child.get("parent_pid") == worker["pid"], "parent_join"
    )
    for index, row in enumerate((worker, child)):
        require(
            row.get("registered_argv_sha256") == hashlib.sha256(encoded(config["argv"][index])).hexdigest(),
            "registered_argv_join",
        )
        require(
            row.get("observed_argv_sha256") == hashlib.sha256(encoded(config["observed_argv"][index])).hexdigest(),
            "observed_argv_join",
        )
        require(row.get("isolated") is True and row.get("no_user_site") is True, "original_flags")
    require(child.get("observation_complete") is True, "child_incomplete")
    require(child.get("original_values_stable") is True, "original_values_changed")
    require(child.get("faults") == [] and child.get("profile_restored") is True, "observer_loss")
    counts = child.get("counts")
    require(
        type(counts) is dict
        and set(counts) == {"edge_call", "edge_return_or_unwind", "worker_call", "worker_return_or_unwind"}
        and all(type(value) is int and value == 1 for value in counts.values()),
        "selected_call_population",
    )
    require(type(child.get("open_frames")) is int and child["open_frames"] == 0, "open_frames")
    edge = child.get("original_edge")
    if type(edge) is not dict:
        raise ValueError("cline_witness_edge_report")
    for name in (
        "complete",
        "original_validator_called",
        "original_native_validation_passed",
        "payload_equal",
        "edge_shape_valid",
        "receipt_matches_original_edge",
        "receipt_accepted_by_original_worker",
        "python_oracle_disabled",
        "request_context_equal",
        "receipt_workspace_binding_matches_source",
        "policy_binding_valid",
    ):
        require(edge.get(name) is True, "original_edge_" + name)
    context = edge.get("request_context_fields")
    require(
        type(context) is dict
        and set(context)
        == {"harness", "event", "cwd", "home_dir", "guard_home", "source_ref_external_allowed", "observe_mode"}
        and all(value is True for value in context.values()),
        "request_context_fields",
    )
    require(edge.get("receipt_workspace_bound") is False, "receipt_workspace_bound")
    require(edge.get("original_worker_route") == "native_resident", "original_route")
    require(edge.get("original_worker_routes") == {"native_resident": 1}, "route_population")


def observed_delivery(session: Any, surface: Any, case: Any, attempt: SurfaceAttempt, installed: Installation) -> Any:
    """Preserve the original call; never remove sidecars with unproved containment."""
    installed.__enter__()
    try:
        return observe_registered_surface(session, surface, case, attempt=attempt)
    finally:
        # Original helper sets process before offering the child and delivery
        # only after its actual containment/output/timeout checks succeeded.
        # A process-stage exception cannot certify descendant retirement.
        if attempt.stage == "process":
            installed.cleanup_faults.append("original_containment_unproved_cleanup_deferred")
        else:
            installed.close()


def verify(wheel: Path, source_sha: str, output: Path) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "hol-guard.installed-cline-child-witness.v1",
        "passed": False,
        "declared_cases": list(CASE_IDS),
        "attempts": [],
        "performance_qualified": False,
        "instrumented_functional_evidence": True,
        "external_host_application_executed": False,
        "historical_failed_run_reclassified": False,
    }
    try:
        identity, distribution, native = admit_installed(wheel, source_sha)
        report["identity"] = identity
        package = Path(str(distribution.locate_file("codex_plugin_scanner"))).resolve(strict=True)
        site = current_site()
        observed_argv0, report["invocation_preflight"] = preflight(sys.executable, sys.prefix)
        with DaemonFixture(native.path, setup="normal") as owned_session:
            session = cast(SurfaceSession, cast(object, owned_session))
            cases = build_cases(session.workspace)
            surfaces = install_registered_surface(_context(session), "cline")
            declared = [(surface, case) for surface in surfaces for case in surface_cases(cases, surface)]
            require(tuple(case.case_id for _, case in declared) == CASE_IDS, "original_four_cases")
            with SurfaceEvidence(output / "original-attempts.jsonl") as ledger:
                for index, (surface, case) in enumerate(declared):
                    row: dict[str, Any] = {
                        "index": index,
                        "case_id": case.case_id,
                        "passed": False,
                        "registration_sha256": surface.registration_sha256,
                        "registered_slot_argv_sha256": hashlib.sha256(encoded(surface.argv)).hexdigest(),
                    }
                    report["attempts"].append(row)
                    attempt = SurfaceAttempt()
                    ledger.offer("global/" + case.case_id, surface.registration_sha256)
                    case_output = output / f"case-{index}"
                    case_output.mkdir(mode=0o700)
                    config = configuration(session, surface, case, identity, package, observed_argv0)
                    installed = Installation(site, case_output, config)
                    try:
                        session.control("case_before")
                        row["fixture_daemon_routes_before"] = dict(
                            route_counts(session.daemon._server.hook_worker.metrics.snapshot())
                        )
                        process, _elapsed = observed_delivery(session, surface, case, attempt, installed)
                        row["observer_installation"] = installed.manifest
                        row["original_delivery"] = process
                        row["cleanup_faults"] = list(installed.cleanup_faults)
                        require(not installed.cleanup_faults and not installed.created, "sidecar_cleanup")
                        row["worker"] = load(case_output / "worker.json")
                        row["nested_run"] = load(case_output / "nested-run.json")
                        validate_nested_run(
                            row["nested_run"], row["worker"], installed.manifest["configuration_sha256"]
                        )
                        validate_process_observation(
                            row["nested_run"]["process_observation"],
                            row["nested_run"]["selected_calls"],
                            row["nested_run"]["outcome"],
                        )
                        row["child"] = load(case_output / "child.json")
                        require(
                            row["nested_run"]["process_observation"]["owned_process_pid"] == row["child"]["pid"],
                            "original_process_child_identity",
                        )
                        row["fixture_daemon_routes_after"] = dict(
                            route_counts(session.daemon._server.hook_worker.metrics.snapshot())
                        )
                        evidence = session.control("case_result")
                        validate_setup(case, cast(Any, evidence["setup"]))
                        row["original_setup_validated"] = True
                        attempt.stage = "witness"
                        reconcile(row["worker"], row["child"], config, installed.manifest)
                        row["strict_child_oracle_passed"] = True
                        require(row["nested_run"]["selected_calls"] == 1, "native_child_without_observed_offer")
                        row["normal_nested_delivery"] = normal_delivery(row["nested_run"])
                        require(row["normal_nested_delivery"], "normal_nested_delivery_failed")
                        attempt.route = case.expected_route
                        attempt.stage = "complete"
                        row["passed"] = True
                    except BaseException:
                        row["observer_installation"] = installed.manifest
                        row["cleanup_faults"] = list(installed.cleanup_faults)
                        row["owned_sidecars_retained"] = bool(installed.created)
                        # Preserve whichever original child records exist even
                        # when delivery or attribution failed first.
                        for name in ("worker", "child", "nested-run"):
                            try:
                                row[name.replace("-", "_")] = load(case_output / (name + ".json"))
                            except BaseException:
                                row[name.replace("-", "_") + "_unavailable"] = True
                        ledger.finish("failed", attempt)
                        raise
                    else:
                        ledger.finish("completed", attempt)
        from scripts.native_slo_artifact import assert_installed_import_origin, installed_package_digest

        assert_installed_import_origin(distribution)
        require(installed_package_digest(distribution) == identity["installed_package_sha256"], "package_changed")
        report["passed"] = len(report["attempts"]) == 4 and all(row["passed"] for row in report["attempts"])
    except Exception as error:
        report["failure"] = failure_evidence(error)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = verify(args.wheel.resolve(), args.source_sha, args.output)
    write_report(args.output / "result.json", result)
    print(json.dumps({"passed": result["passed"], "cases": len(result["attempts"])}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
