"""Prove causal observation preserves source operations using explicit doubles.

No Guard module, socket, subprocess or thread is started. Original helper bytes
are verified before selecting AST bodies; clocks and synchronization are finite
doubles, so these controls make no latency or native acceptance claim.
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import math
import re
import sys
import types
from collections import Counter
from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Any, TypedDict

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from witness_support import digest, error_name, require, verify_helpers, write_json  # noqa: E402

OBSERVER = "scripts/native_slo_workspace_observer.py"
SERVER = "scripts/native_slo_workspace_server.py"
STAGES = ("compile", "push", "transport_ack", "barrier")


def selected(raw: bytes, name: str) -> ast.FunctionDef | ast.ClassDef:
    matches = [
        node
        for node in ast.walk(ast.parse(raw))
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name
    ]
    require(len(matches) == 1, "causal_source_selection")
    return matches[0]


def compile_nodes(nodes: list[Any], namespace: dict[str, Any]) -> None:
    tree = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *nodes],
        type_ignores=[],
    )
    exec(compile(ast.fix_missing_locations(tree), "bound_causal_control_ast", "exec"), namespace)


class RemoveObservation(ast.NodeTransformer):
    """Remove only declared observation additions, exposing the original AST."""

    @staticmethod
    def diagnostic_target(node: Any) -> bool:
        if isinstance(node, ast.Name):
            return node.id in {"iteration", "observation", "active_stages"}
        if isinstance(node, ast.Attribute):
            return node.attr in {"_ack_observation", "_active_stages", "_active_stages_at_freeze"}
        return isinstance(node, ast.Subscript) and RemoveObservation.diagnostic_target(node.value)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if node.name == "observed" and node.args.args and node.args.args[0].arg == "name":
            return None
        if node.name == "_mark":
            require(node.args.args[1].arg == "kind", "mark_stage_argument")
            del node.args.args[1]
        return self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        return None if all(self.diagnostic_target(target) for target in node.targets) else self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        return None if self.diagnostic_target(node.target) else self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> Any:
        return None if self.diagnostic_target(node.target) else self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if isinstance(node.func, ast.Name) and node.func.id == "observed":
            require(
                len(node.args) == 2 and not node.keywords and isinstance(node.args[0], ast.Constant),
                "operand_wrapper_shape",
            )
            return self.visit(node.args[1])
        if isinstance(node.func, ast.Attribute) and node.func.attr == "_mark":
            require(isinstance(node.args[0], ast.Constant) and node.args[0].value in STAGES, "mark_stage_literal")
            del node.args[0]
        return self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> Any:
        for index in reversed(range(len(node.keys))):
            key = node.keys[index]
            if isinstance(key, ast.Constant) and key.value in {"active_stages_at_freeze", "ack_observation"}:
                del node.keys[index]
                del node.values[index]
        return self.generic_visit(node)


def source_transparency(original: dict[str, bytes], candidate: dict[str, bytes]) -> None:
    for path, name in ((SERVER, "_ack"), (OBSERVER, "PublicationObserver")):
        before = selected(original[path], name)
        after = RemoveObservation().visit(copy.deepcopy(selected(candidate[path], name)))
        require(ast.dump(before) == ast.dump(after), "original_operation_ast_changed")
    for path in (OBSERVER, SERVER):
        before = selected(original[path], "PublicationObserver" if path == OBSERVER else "_ack")
        after = selected(candidate[path], "PublicationObserver" if path == OBSERVER else "_ack")
        # Added accounting must reuse existing synchronization sites.
        require(
            sum(isinstance(node, (ast.With, ast.AsyncWith)) for node in ast.walk(before))
            == sum(isinstance(node, (ast.With, ast.AsyncWith)) for node in ast.walk(after)),
            "synchronization_site_added",
        )


class Clock:
    def __init__(self, events: list[Any]) -> None:
        self.events = events
        self.wall, self.cpu = 0, 0

    def monotonic(self) -> float:
        self.events.append("monotonic")
        self.wall += 1
        return self.wall / 1000

    def thread_time(self) -> float:
        self.events.append("thread_time")
        self.cpu += 1
        return self.cpu / 10000


class Lock:
    def __init__(self, events: list[Any], name: str) -> None:
        self.events, self.name = events, name

    def __enter__(self) -> None:
        self.events.append(("lock_enter", self.name))

    def __exit__(self, *_args: Any) -> None:
        self.events.append(("lock_exit", self.name))


def observer_namespace(raw: bytes, events: list[Any]) -> dict[str, Any]:
    namespace = {
        "Any": Any,
        "Mapping": Mapping,
        "TypedDict": TypedDict,
        "Counter": Counter,
        "ExitStack": ExitStack,
        "time": Clock(events),
        "hashlib": hashlib,
        "json": json,
        "re": re,
        "MAX_EVENTS": 256,
        "PAGE_SIZE": 32,
        "ACTIVE_STAGES": STAGES,
        "threading": types.SimpleNamespace(Lock=lambda: Lock(events, "observer"), local=types.SimpleNamespace),
        "_DIGEST": re.compile(r"[0-9a-f]{64}"),
    }
    compile_nodes(
        [selected(raw, name) for name in ("PolicyBinding", "public_binding", "PublicationObserver")], namespace
    )
    return namespace


def observer_case(raw: bytes, *, freeze_at: str | None = None, failure_at: str | None = None) -> dict[str, Any]:
    events: list[Any] = []
    namespace = observer_namespace(raw, events)
    binding = {"generation": 1, "policy_digest": "a" * 64, "runtime_identity": "b" * 64}
    publisher = types.SimpleNamespace(
        _condition=Lock(events, "publisher"),
        _snapshot=binding,
        _acked=True,
        _closed=False,
        _compiled_workspace_policies={"home": {}, "workspace": {}},
        _workspace_paths={Path("workspace")},
    )
    observer = namespace["PublicationObserver"](publisher, (Path("workspace"),))
    original_error = RuntimeError("fixed_original_observer_failure")
    result_object = object()
    marker = object()
    frozen = None

    def edge(stage: str) -> None:
        nonlocal frozen
        events.append(("original", stage))
        if freeze_at == stage:
            observer.freeze()
            frozen = observer.report()
        if failure_at == stage:
            raise original_error

    def compile_original(*args: Any, **kwargs: Any) -> Any:
        require(args == (marker,) and kwargs == {"sentinel": marker}, "compile_arguments_changed")
        edge("compile")
        return result_object

    def client_original(*args: Any, **kwargs: Any) -> Any:
        require(args == (marker,) and kwargs == {"payload": marker}, "client_arguments_changed")
        edge("push")
        return result_object

    def transport_original(*args: Any, **kwargs: Any) -> Any:
        require(args == (marker,) and kwargs["publisher"] is publisher, "transport_arguments_changed")
        require(
            set(kwargs) == {"publisher", "client", "sentinel"} and kwargs["sentinel"] is marker,
            "transport_keywords_changed",
        )
        edge("transport_ack")
        require(kwargs["client"](marker, payload=marker) is result_object, "client_return_replaced")
        return binding, 1

    compiled = observer._compilation(compile_original)
    transported = observer._transport(transport_original)

    def publication_original(*args: Any, **kwargs: Any) -> Any:
        require(args == (marker,) and kwargs == {"renew_after_generation": None}, "publication_arguments_changed")
        edge("barrier")
        require(compiled(marker, sentinel=marker) is result_object, "compile_return_replaced")
        options = {"publisher": publisher, "sentinel": marker}
        if failure_at != "missing_client_setup":
            options["client"] = client_original
        returned = transported(marker, **options)
        require(returned[0] is binding and returned[1] == 1, "transport_return_replaced")
        return result_object

    if freeze_at == "before_entry":
        observer.freeze()
        frozen = observer.report()
    caught = None
    returned_original = False
    try:
        if freeze_at == "standalone_compile":
            freeze_at = "compile"
            returned_original = compiled(marker, sentinel=marker) is result_object
        else:
            returned_original = (
                observer._publication(publication_original)(marker, renew_after_generation=None) is result_object
            )
    except Exception as error:
        caught = {"same_original": error is original_error, "category": type(error).__name__}
    if freeze_at == "after_call":
        observer.freeze()
        frozen = observer.report()
    if frozen is None:
        frozen = observer.report()
    final = observer.report()
    return {
        "events": events,
        "frozen": frozen,
        "final": final,
        "rows": observer.rows(),
        "caught": caught,
        "returned_original": returned_original,
    }


def observer_transparency(original: bytes, candidate: bytes) -> int:
    cases = [
        ("barrier", None, {"barrier": 1}),
        ("compile", None, {"barrier": 1, "compile": 1}),
        ("transport_ack", None, {"barrier": 1, "transport_ack": 1}),
        ("push", None, {"barrier": 1, "transport_ack": 1, "push": 1}),
        ("standalone_compile", None, {"compile": 1}),
        ("before_entry", None, {}),
        (None, None, None),
        *[("after_call", failure, {}) for failure in STAGES],
        ("after_call", "missing_client_setup", {"transport_ack": 1}),
    ]
    for freeze_at, failure_at, expected in cases:
        before = observer_case(original, freeze_at=freeze_at, failure_at=failure_at)
        after = observer_case(candidate, freeze_at=freeze_at, failure_at=failure_at)
        normalized = copy.deepcopy(after)
        for field in ("frozen", "final"):
            normalized[field].pop("active_stages_at_freeze")
        require(normalized == before, "observer_original_calls_or_events_changed")
        if expected is not None:
            expected = {stage: expected.get(stage, 0) for stage in STAGES}
            require(after["frozen"]["active_stages_at_freeze"] == expected, "active_stage_attribution")
            require(sum(expected.values()) == after["frozen"]["calls_in_flight_at_freeze"], "active_stage_total")
            require(after["final"]["active_stages_at_freeze"] == expected, "freeze_mutated_after_completion")
        else:
            require(after["frozen"]["active_stages_at_freeze"] is None, "prefreeze_detail_invented")
    return len(cases)


class TracedMapping(dict):
    def __init__(self, world: Any, label: str, values: dict[str, Any]) -> None:
        super().__init__(values)
        self.world, self.label = world, label

    def get(self, name: str, default: Any = None) -> Any:
        self.world.edge(self.label + ".get." + name)
        return super().get(name, default)


class TracedTruth:
    def __init__(self, world: Any, value: bool) -> None:
        self.world, self.value = world, value

    def __bool__(self) -> bool:
        self.world.edge("truth_test")
        return self.value


class AckWorld:
    def __init__(self, case: str, *, fault: str | None = None) -> None:
        self.case, self.fault = case, fault
        self.events: list[Any] = []
        self.original_error = RuntimeError("fixed_original_ack_failure")
        self.iteration = 0
        self.clock_calls = 0
        self.workspace, self.store = object(), object()
        effective: Any = TracedMapping(
            self, "effective", {"default_action": "allow", "subprocess_action": "allow", "sandbox_analysis": "strict"}
        )
        if case == "effective_mapping":
            effective = None
        elif case in ("default_action_matches", "subprocess_action_matches", "sandbox_strict"):
            field = {
                "default_action_matches": "default_action",
                "subprocess_action_matches": "subprocess_action",
                "sandbox_strict": "sandbox_analysis",
            }[case]
            effective[field] = "different"
        self.snapshot: Any = TracedMapping(
            self, "snapshot", {"effective_policy": effective, "mode": "other" if case == "enforce_mode" else "enforce"}
        )
        self.prepared: Any = TracedMapping(self, "prepared", {})
        if case == "snapshot_mapping":
            self.snapshot = None
        if case == "prepared_mapping":
            self.prepared = None
        self.fixture = types.SimpleNamespace(
            worker=types.SimpleNamespace(prepare_workspace_policy=self.prepare),
            publisher=types.SimpleNamespace(current_snapshot=self.current),
            session=types.SimpleNamespace(workspace=self.workspace, store=self.store),
        )

    def edge(self, name: str) -> None:
        self.events.append(name)
        if self.fault == name:
            raise self.original_error

    def prepare(self, workspace: Any, *, deadline: float) -> Any:
        require(workspace is self.workspace and deadline == 10.0, "prepare_arguments_changed")
        self.iteration += 1
        self.edge("prepare")
        return self.prepared

    def current(self) -> Any:
        self.edge("current_snapshot")
        return self.snapshot

    def readback(self, store: Any) -> tuple[Any, Any]:
        require(store is self.store, "readback_arguments_changed")
        self.edge("authenticated_readback")
        return self.workspace, self.store

    def binding(self, value: Any) -> Any:
        label = "snapshot" if value is self.snapshot else "prepared"
        require(value is self.snapshot or value is self.prepared, "public_binding_argument_changed")
        self.edge("public_binding." + label)
        if label == "snapshot" and self.case == "snapshot_binding_present":
            return None
        generation = 1 if self.case == "generation_at_least_floor" else 2
        if label == "prepared" and self.case == "prepared_binding_matches":
            generation += 1
        return {"generation": generation}

    def matches(self, binding: Any, accepted: Any, snapshot: Any) -> Any:
        require(
            binding is self.workspace and accepted is self.store and snapshot is self.snapshot,
            "matches_arguments_changed",
        )
        self.edge("readback_matches")
        if self.case in ("truthy_non_boolean", "false_non_boolean"):
            return TracedTruth(self, self.case == "truthy_non_boolean")
        return not (
            self.case == "authenticated_readback_matches" or (self.case == "second_iteration" and self.iteration == 1)
        )

    def monotonic(self) -> float:
        self.edge("monotonic")
        self.clock_calls += 1
        if self.case == "second_iteration":
            return 1.0 if self.iteration == 1 else 9.0
        if self.case in ("success", "strict_not_required", "truthy_non_boolean") or self.fault:
            return 9.0
        return 11.0

    def sleep(self, duration: float) -> None:
        require(duration == 0.005, "retry_sleep_changed")
        self.edge("sleep")
        require(self.case == "second_iteration", "unexpected_retry_added")


def ack_case(raw: bytes, predicates: tuple[str, ...], case: str, fault: str | None = None) -> dict[str, Any]:
    world = AckWorld(case, fault=fault)
    namespace = {
        "Any": Any,
        "Mapping": Mapping,
        "ACK_PREDICATES": predicates,
        "_authenticated_readback": world.readback,
        "_readback_matches": world.matches,
        "public_binding": world.binding,
        "time": types.SimpleNamespace(monotonic=world.monotonic, sleep=world.sleep),
    }
    compile_nodes([selected(raw, "_ack")], namespace)
    caught = None
    returned_original = False
    try:
        value = namespace["_ack"](
            world.fixture, previous=2, action="allow", strict=case != "strict_not_required", deadline=10.0
        )
        returned_original = value is world.snapshot
    except Exception as error:
        caught = {
            "category": type(error).__name__,
            "same_original": error is world.original_error,
            "message": str(error),
        }
    return {
        "events": world.events,
        "returned_original": returned_original,
        "caught": caught,
        "observation": getattr(world.fixture, "_ack_observation", None),
    }


def ack_transparency(original: bytes, candidate: bytes) -> int:
    tree = ast.parse(candidate)
    predicates = ast.literal_eval(
        next(
            node.value for node in tree.body if isinstance(node, ast.Assign) and node.targets[0].id == "ACK_PREDICATES"
        )
    )
    cases = [
        (name, None)
        for name in (
            "success",
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
            "sandbox_strict",
            "strict_not_required",
            "within_deadline",
            "truthy_non_boolean",
            "false_non_boolean",
            "second_iteration",
        )
    ]
    cases += [
        ("success", name)
        for name in (
            "prepare",
            "current_snapshot",
            "authenticated_readback",
            "snapshot.get.effective_policy",
            "public_binding.snapshot",
            "public_binding.prepared",
            "readback_matches",
            "snapshot.get.mode",
            "effective.get.default_action",
            "effective.get.subprocess_action",
            "effective.get.sandbox_analysis",
            "monotonic",
        )
    ]
    cases += [("truthy_non_boolean", "truth_test"), ("second_iteration", "sleep")]
    for case, fault in cases:
        before = ack_case(original, predicates, case, fault)
        after = ack_case(candidate, predicates, case, fault)
        observation = after.pop("observation")
        before.pop("observation")
        require(after == before, "ack_calls_operands_order_or_exception_changed")
        require(observation["iteration"] in (1, 2), "ack_iteration_count")
        bits = {name: observation[name] for name in predicates}
        require(
            set(bits) == set(predicates) and all(value is None or type(value) is bool for value in bits.values()),
            "ack_fixed_boolean_projection",
        )
        if case == "strict_not_required":
            require(
                bits["strict_not_required"] is True and bits["sandbox_strict"] is None,
                "skipped_strict_predicate_reevaluated",
            )
        if case in ("truthy_non_boolean", "false_non_boolean"):
            require(bits["authenticated_readback_matches"] is None, "non_boolean_coerced_for_observation")
        if not fault and case in predicates and case != "strict_not_required":
            require(bits[case] is False, "failed_predicate_not_retained")
            if case != "within_deadline":
                index = predicates.index(case)
                require(all(bits[name] is None for name in predicates[index + 1 : -1]), "skipped_predicate_invented")
        if fault:
            require(after["caught"]["same_original"] is True, "original_exception_replaced")
    return len(cases)


def aggregate_boundary(candidate: bytes) -> None:
    """Exercise the unchanged sanitizer at actual collector/ledger nesting."""
    contract = (ROOT / "helpers/scripts/native_slo_contract.py").read_bytes()
    tree = ast.parse(contract)
    constants = {"FORBIDDEN_FIELD_PARTS", "MAX_EVIDENCE_BYTES", "_SAFE_VALUE_RE", "_SENSITIVE_VALUE_RE"}
    functions = {"_normalized_key", "_safe_key", "_safe_string", "sanitize_aggregate", "assert_privacy_safe"}
    nodes = [
        node
        for node in tree.body
        if (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in constants)
        or (isinstance(node, ast.FunctionDef) and node.name in functions)
    ]
    namespace = {"Mapping": Mapping, "Sequence": Sequence, "re": re, "math": math, "json": json}
    compile_nodes(nodes, namespace)
    predicates = ast.literal_eval(
        next(
            node.value
            for node in ast.parse(candidate).body
            if isinstance(node, ast.Assign) and node.targets[0].id == "ACK_PREDICATES"
        )
    )
    detail = ack_case(candidate, predicates, "success")["observation"]
    phase = {"ack_observation": detail}
    observer = {"active_stages_at_freeze": dict.fromkeys(STAGES, 0)}
    values = (
        {"kind": "control_terminal", "result": phase},
        {"cells": [{"phases": [phase], "final": {"observer": observer}}]},
    )
    for value in values:
        require(namespace["assert_privacy_safe"](value) == value, "causal_fields_changed_at_privacy_boundary")
    legacy_nested = {"cells": [{"phases": [{"ack_observation": {"predicates": {"prepared_mapping": True}}}]}]}
    require(
        namespace["assert_privacy_safe"](legacy_nested) != legacy_nested,
        "privacy_depth_negative_control_not_exercised",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report: dict[str, Any] = {
        "schema": "workspace-causal-controls.v1",
        "passed_controls": [],
        "failures": [],
        "native_execution_performed": False,
        "guard_code_imported": False,
    }
    try:
        require(
            not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.") for name in sys.modules),
            "guard_module_already_loaded",
        )
        report["helper_binding"] = verify_helpers()
        manifest = json.loads((ROOT / "source-manifest.json").read_bytes())
        original, candidate = {}, {}
        report["source_bindings"] = []
        for path in (OBSERVER, SERVER):
            raw = (args.production_source / path).read_bytes()
            expected = manifest["helpers"][path]
            require(
                len(raw) == expected["bytes"] and digest(raw) == expected["sha256"], "original_control_source_changed"
            )
            original[path] = raw
            candidate[path] = (ROOT / "helpers" / path).read_bytes()
            report["source_bindings"].append(
                {"path": path, "original_sha256": digest(raw), "candidate_sha256": digest(candidate[path])}
            )
        source_transparency(original, candidate)
        report["passed_controls"].append("original_ast_after_removing_only_declared_observation")
        report["observer_cases"] = observer_transparency(original[OBSERVER], candidate[OBSERVER])
        report["passed_controls"].append("observer_nested_entry_exit_freeze_and_exception_transparency")
        report["ack_cases"] = ack_transparency(original[SERVER], candidate[SERVER])
        report["passed_controls"].append("ack_short_circuit_arguments_clock_sleep_and_exception_transparency")
        aggregate_boundary(candidate[SERVER])
        report["passed_controls"].append("exact_original_aggregate_sanitizer_preserves_ledger_and_collector_fields")
    except Exception as error:
        report["failures"].append(error_name(error))
    report["result"] = "passed" if not report["failures"] else "failed"
    write_json(args.output, report)
    print(
        json.dumps(
            {
                "result": report["result"],
                "controls": len(report["passed_controls"]),
                "observer_cases": report.get("observer_cases"),
                "ack_cases": report.get("ack_cases"),
                "failures": report["failures"],
                "native_execution_performed": False,
            }
        )
    )
    return int(report["result"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
