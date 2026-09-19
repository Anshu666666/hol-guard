"""Exercise exact qualification class bodies with explicit, non-running doubles.

No Guard module is imported from disk, no socket is created, and no subprocess
or thread is started. These controls prove fixture ordering/ownership behavior;
only a separately reviewed installed execution can prove native acceptance.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import shutil
import sys
import tempfile
import types
from collections.abc import Mapping
from contextlib import redirect_stdout, suppress
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from witness_support import error_name, require, verify_helpers, write_json  # noqa: E402


def module(name: str, **attributes: Any) -> types.ModuleType:
    result = types.ModuleType(name)
    result.__dict__.update(attributes)
    sys.modules[name] = result
    return result


def exact_class(name: str, class_name: str, namespace: dict[str, Any]) -> Any:
    path = ROOT / "helpers" / name
    tree = ast.parse(path.read_bytes(), filename=str(path))
    selected = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    require(len(selected) == 1, "class_source_selection")
    code = ast.Module(
        body=[
            ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0),
            *selected,
        ],
        type_ignores=[],
    )
    ast.fix_missing_locations(code)
    exec(compile(code, str(path), "exec"), namespace)
    return namespace[class_name]


class FixtureFailureError(RuntimeError):
    def __init__(self, detail: dict[str, Any]) -> None:
        super().__init__("fixed_control_fixture_failure")
        self.detail = detail


def failure_evidence(error: Exception) -> dict[str, Any]:
    return {"category": type(error).__name__, "original_identity": id(error)}


class Scenario:
    """One explicit factory/observer/daemon double population and private tree."""

    def __init__(self, parent: Path, *, fault: str = "", count: int = 10) -> None:
        self.parent, self.fault, self.count = parent, fault, count
        self.events: list[Any] = []
        self.original_error = RuntimeError("fixed_original_control_failure")
        self.calls: list[Any] = []
        self.cleanup_homes: list[Path] = []
        self.publisher: Any = None
        self.adapter: Any = None
        self.capture_scope = object()
        self.foreign_store, self.foreign_publisher = object(), object()
        self.thread_alive = False
        self.clock = types.SimpleNamespace(monotonic=lambda: 10.0)
        scenario = self

        class Publisher:
            def __init__(self) -> None:
                self._thread = None
                self._started = False
                self.closed = False
                self._workspace_paths: set[Path] = set()
                self._compiled_workspace_policies: dict[str, Any] = {}
                if fault == "already_started":
                    self._started = True
                if fault == "populated_cache":
                    self._compiled_workspace_policies["synthetic"] = object()
                if fault == "preexisting_registration":
                    self._workspace_paths.add(parent / "unowned-workspace")

            def register_workspace(self, workspace: Path) -> bool:
                scenario.events.append(("register", workspace, self._started))
                if fault == "registration" and len(self._workspace_paths) == 1:
                    raise scenario.original_error
                if workspace in self._workspace_paths:
                    return False
                self._workspace_paths.add(workspace)
                return True

            def start(self) -> None:
                require(
                    len(self._workspace_paths) == count,
                    "start_before_complete_registration",
                )
                require("observer_enter" in scenario.events, "start_before_observer")
                require("registry" in scenario.events, "start_before_private_ownership")
                scenario.events.append("publisher_start")
                self._started = True
                self._thread = types.SimpleNamespace(is_alive=lambda: scenario.thread_alive)
                scenario.thread_alive = True
                if fault == "publisher_start":
                    raise scenario.original_error

            def close(self, *, timeout_seconds: float) -> None:
                require(timeout_seconds == 1.0, "publisher_cleanup_budget_changed")
                scenario.events.append("publisher_close")
                if fault == "publisher_close":
                    raise scenario.original_error
                self.closed = True
                if fault != "publisher_thread_survives":
                    scenario.thread_alive = False

        class Observer:
            def __init__(self, publisher: Any, workspaces: tuple[Path, ...]) -> None:
                self.publisher = publisher
                self.workspaces = workspaces

            def __enter__(self) -> Any:
                scenario.events.append("observer_enter")
                if fault == "observer_enter":
                    raise scenario.original_error
                return self

            def close(self) -> None:
                scenario.events.append("observer_close")
                if fault == "observer_close":
                    raise scenario.original_error

        def factory(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((args, kwargs))
            if args and args[0] is self.foreign_store:
                return self.foreign_publisher
            require(
                len(args) == 1 and kwargs == {"config_capture": self.capture_scope},
                "factory_arguments_changed",
            )
            if fault == "factory":
                raise self.original_error
            self.publisher = Publisher()
            return self.publisher

        self.factory = factory
        self.hook_worker = module(
            "codex_plugin_scanner.guard.daemon.hook_worker",
            get_native_policy_snapshot_publisher=factory,
        )
        module("codex_plugin_scanner.guard.daemon", hook_worker=self.hook_worker)
        status = types.SimpleNamespace(
            mode="auto",
            available=True,
            compatible=True,
            reason="native_ready",
            identity=types.SimpleNamespace(path=parent / "runtime"),
            capabilities=types.SimpleNamespace(build_sha="c331bb1ac5d9ee2082ea379713490b5b6d41e782"),
        )
        module(
            "codex_plugin_scanner.guard.native_runtime",
            native_runtime_status=lambda: status,
        )
        self.WorkspaceFixture = exact_class(
            "scripts/native_slo_workspace_server.py",
            "WorkspaceScenarioFixture",
            {
                "__name__": "scripts.native_slo_workspace_server",
                "WORKSPACE_COUNTS": (1, 10, 100),
                "Mapping": Mapping,
                "time": self.clock,
                "PublicationObserver": Observer,
            },
        )
        module(
            "scripts.native_slo_workspace_server",
            WorkspaceScenarioFixture=self.WorkspaceFixture,
            WORKSPACE_PHASES=(
                "initial",
                "unchanged",
                "stricter_overlay",
                "coalesced_burst",
                "public_policy",
                "resident_restart",
            ),
        )
        module(
            "scripts.native_slo_failure",
            FixtureFailureError=FixtureFailureError,
            failure_evidence=failure_evidence,
        )

        def daemon(store: Any, **kwargs: Any) -> Any:
            require(kwargs == {"host": "127.0.0.1", "port": 0}, "daemon_arguments_changed")
            self.events.append("daemon_construct")
            # Exercise a distinct store through the same patched module binding.
            foreign = self.hook_worker.get_native_policy_snapshot_publisher(
                self.foreign_store, marker=self.capture_scope
            )
            require(foreign is self.foreign_publisher, "foreign_factory_object_changed")
            publisher = self.hook_worker.get_native_policy_snapshot_publisher(store, config_capture=self.capture_scope)
            require(publisher is self.publisher, "publisher_factory_object_changed")
            if fault == "duplicate_factory":
                self.hook_worker.get_native_policy_snapshot_publisher(store, config_capture=self.capture_scope)
            publisher.start()
            if fault in {
                "daemon_after_start",
                "publisher_close",
                "publisher_thread_survives",
                "resident_stop",
                "observer_close",
            }:
                raise self.original_error
            worker = types.SimpleNamespace(policy_snapshot_publisher=publisher, test_oracle=None)
            if fault == "worker_identity":
                worker.policy_snapshot_publisher = object()
            if fault == "test_oracle":
                worker.test_oracle = object()
            result = types.SimpleNamespace(
                _server=types.SimpleNamespace(hook_worker=worker),
                _finish_service_completed=False,
            )

            def stop() -> None:
                self.events.append("daemon_stop")
                if fault == "daemon_stop":
                    raise self.original_error
                result._finish_service_completed = fault != "daemon_uncontained"

            result.stop = stop
            return result

        def store(home: Path) -> Any:
            self.home = home
            self.events.append("store")
            if fault == "store":
                raise self.original_error
            return types.SimpleNamespace(guard_home=home)

        def stop_residents(home: Path) -> bool:
            self.cleanup_homes.append(home)
            self.events.append("resident_stop")
            require(home == self.home, "unowned_home_cleanup")
            return fault != "resident_stop"

        def progress(stage: str) -> None:
            if stage == "register_workspace" and fault == "fixture_close":

                def fail_close() -> None:
                    raise self.original_error

                self.adapter.workspace_fixture.witness = types.SimpleNamespace(close=fail_close)
                raise self.original_error
            if stage == "register_workspace" and fault in {
                "after_daemon",
                "daemon_stop",
                "daemon_uncontained",
            }:
                raise self.original_error

        self.progress = progress
        self.Adapter = exact_class(
            "scripts/native_slo_session.py",
            "AdapterSession",
            {
                "__name__": "scripts.native_slo_session",
                "Path": Path,
                "tempfile": tempfile,
                "shutil": shutil,
                "patch": patch,
                "_build_stop_diagnostic": lambda value: {"status": value},
                "GuardStore": store,
                "prepare_empty_command_authority": lambda selected: {"protected": True},
                "GuardDaemonServer": daemon,
                "close_native_residents": stop_residents,
                "suppress": suppress,
            },
        )
        self.original_construct = self.Adapter._construct_workspace_daemon

        def ownership(adapter: Any, *args: Any, **kwargs: Any) -> Any:
            self.adapter = adapter
            require(
                adapter._construction_publisher is None and not hasattr(adapter, "daemon"),
                "late_ownership",
            )
            self.events.append("registry")
            if fault == "registry":
                raise self.original_error
            return self.original_construct(adapter, *args, **kwargs)

        self.Adapter._construct_workspace_daemon = ownership

    def execute(self) -> Any:
        with patch.object(tempfile, "tempdir", str(self.parent)):
            return self.Adapter(
                self.parent / "runtime",
                workspace_count=self.count,
                progress=self.progress,
            )


def serve_controls(parent: Path, report: dict[str, Any]) -> None:
    """Execute the exact _serve function and AdapterSession context methods."""
    for stage in ("normal", "start_failure", "without_matrix"):
        events: list[str] = []
        scenario = Scenario(parent)
        adapter = scenario.Adapter.__new__(scenario.Adapter)
        original_error = RuntimeError("fixed_serve_start_failure")

        def start(_events=events, _stage=stage, _error=original_error) -> None:
            _events.append("adapter_start")
            if _stage == "start_failure":
                raise _error

        adapter.start = start
        adapter.close = lambda _events=events: _events.append("adapter_close")
        observer = types.SimpleNamespace(close=lambda _events=events: _events.append("observer_close"))
        adapter.workspace_fixture = types.SimpleNamespace(
            observer=observer,
            close=lambda _events=events: _events.append("fixture_close"),
            startup_failure=lambda: {"passed": False},
        )

        def construct(runtime: Path, _stage=stage, _events=events, _adapter=adapter, **kwargs: Any) -> Any:
            require(
                runtime == parent / "runtime" and kwargs["configuration"] is None, "serve_constructor_arguments_changed"
            )
            require(
                kwargs["workspace_count"] == (None if _stage == "without_matrix" else 10), "serve_count_not_forwarded"
            )
            _events.append("adapter_construct")
            return _adapter

        class Diagnostic:
            def __init__(self, emit: Any) -> None:
                pass

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_args: Any) -> None:
                pass

            def progress(self, value: str) -> None:
                pass

        module("scripts.native_slo_session", AdapterSession=construct)
        module("scripts.native_slo_faults", FaultFixture=object())
        path = ROOT / "helpers/scripts/native_slo_daemon_fixture.py"
        tree = ast.parse(path.read_bytes())
        selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_serve"]
        require(len(selected) == 1, "serve_source_selection")
        code = ast.Module(
            body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *selected],
            type_ignores=[],
        )
        ast.fix_missing_locations(code)
        namespace: dict[str, Any] = {
            "StartupDiagnostic": Diagnostic,
            "_emit": lambda value: None,
            "FixtureFailureError": FixtureFailureError,
            "failure_evidence": failure_evidence,
            "_serve_session": lambda *values, _events=events: _events.append("session_body"),
        }
        exec(compile(code, str(path), "exec"), namespace)
        try:
            namespace["_serve"](parent / "runtime", workspace_count=None if stage == "without_matrix" else 10)
        except FixtureFailureError as error:
            require(
                stage == "start_failure" and error.detail["original_identity"] == id(original_error),
                "serve_start_error_replaced",
            )
        else:
            require(stage != "start_failure", "serve_start_error_suppressed")
        expected = ["adapter_construct", "adapter_start"]
        if stage != "start_failure":
            expected.append("session_body")
        expected.append("adapter_close")
        if stage != "without_matrix":
            expected.extend(("fixture_close", "observer_close"))
        require(events == expected, "serve_lifetime_handoff_changed")
        report["passed_controls"].append("serve_lifetime_" + stage)


def binding_controls(parent: Path, report: dict[str, Any]) -> None:
    """Exercise the actual materializer with synthetic files and fixed Git doubles."""
    import materialize_helpers
    import witness_support

    for fault in ("none", "original_changed", "override_changed", "override_missing", "override_extra"):
        project = parent / ("binding-" + fault)
        selected = project / "ci/workspace_publication_diagnostic"
        selected.mkdir(parents=True)
        production = project / "original"
        manifest: dict[str, Any] = {
            "published_source_sha": witness_support.SOURCE_SHA,
            "source_tree": witness_support.SOURCE_TREE,
            "helpers": {},
            "resources": {},
            "diagnostic_overrides": {},
        }
        for name in sorted(witness_support.DIAGNOSTIC_HELPER_OVERRIDES):
            for base, content, section in (
                (production, b"original synthetic control\n", "helpers"),
                (project, b"explicit synthetic diagnostic override\n", "diagnostic_overrides"),
            ):
                path = base / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                manifest[section][name] = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        first = sorted(manifest["helpers"])[0]
        if fault == "original_changed":
            (production / first).write_bytes(b"changed original that must still be rejected\n")
        elif fault == "override_changed":
            (project / first).write_bytes(b"changed diagnostic override\n")
        elif fault == "override_missing":
            del manifest["diagnostic_overrides"][first]
        elif fault == "override_extra":
            manifest["diagnostic_overrides"]["scripts/unreviewed.py"] = manifest["diagnostic_overrides"][first]
        (selected / "source-manifest.json").write_text(json.dumps(manifest))

        def git_identity(arguments: Any, *, text: bool, _production=production) -> str:
            require(
                arguments == ["git", "-C", str(_production), "rev-parse", "HEAD", "HEAD^{tree}"] and text is True,
                "source_identity_command_changed",
            )
            return witness_support.SOURCE_SHA + "\n" + witness_support.SOURCE_TREE + "\n"

        with (
            patch.object(materialize_helpers, "ROOT", selected),
            patch.object(witness_support, "ROOT", selected),
            patch.object(materialize_helpers.subprocess, "check_output", git_identity),
            patch.object(sys, "argv", ["materialize_helpers.py", "--production-source", str(production)]),
            redirect_stdout(io.StringIO()),
        ):
            try:
                materialize_helpers.main()
            except RuntimeError:
                require(fault != "none", "valid_override_materialization_rejected")
            else:
                require(fault == "none", "unbound_helper_materialized")
                for name in manifest["helpers"]:
                    require(
                        (selected / "helpers" / name).read_bytes() == (project / name).read_bytes(),
                        "wrong_helper_source_materialized",
                    )
        report["passed_controls"].append("materializer_" + fault)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report: dict[str, Any] = {
        "scope": "exact_qualification_class_bodies_with_explicit_doubles",
        "native_execution_performed": False,
        "guard_code_imported": False,
        "passed_controls": [],
        "failures": [],
    }
    try:
        require(
            not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.") for name in sys.modules),
            "guard_module_already_loaded",
        )
        report["helper_binding"] = verify_helpers()
        for name in ("scripts", "codex_plugin_scanner", "codex_plugin_scanner.guard"):
            module(name)
        sys.modules["scripts"].__path__ = [str(ROOT / "helpers/scripts")]
        module("codex_plugin_scanner.guard.runtime")
        module("codex_plugin_scanner.guard.runtime.hook_review_engine", HOOK_ENGINE_NORMAL_BUDGET_MS=1000)
        from scripts.native_slo_contract import assert_privacy_safe

        original_failure_class = exact_class(
            "scripts/native_slo_failure.py", "FixtureFailureError", {"assert_privacy_safe": assert_privacy_safe}
        )
        with tempfile.TemporaryDirectory(prefix="construction-controls-", dir=ROOT) as temporary:
            parent = Path(temporary)
            binding_controls(parent, report)
            serve_controls(parent, report)
            for count in (1, 10, 100):
                scenario = Scenario(parent, count=count)
                adapter = scenario.execute()
                try:
                    require(
                        adapter.workspace_fixture.publisher is scenario.publisher,
                        "bound_publisher_identity",
                    )
                    require(
                        adapter.workspace_fixture.worker is adapter.daemon._server.hook_worker,
                        "bound_worker_identity",
                    )
                    require(len(scenario.calls) == 2, "factory_call_count")
                    require(
                        scenario.calls[0]
                        == (
                            (scenario.foreign_store,),
                            {"marker": scenario.capture_scope},
                        ),
                        "foreign_factory_arguments_changed",
                    )
                    require(
                        scenario.calls[1]
                        == (
                            (adapter.store,),
                            {"config_capture": scenario.capture_scope},
                        ),
                        "original_factory_call_changed",
                    )
                    require(
                        scenario.hook_worker.get_native_policy_snapshot_publisher is scenario.factory,
                        "factory_patch_not_restored",
                    )
                    registrations = [
                        event for event in scenario.events if isinstance(event, tuple) and event[0] == "register"
                    ]
                    require(
                        len(registrations) == count + 1
                        and all(event[2] is False for event in registrations[:-1])
                        and registrations[-1][2] is True,
                        "registration_boundary_changed",
                    )
                    require(
                        registrations[-1][1] == adapter.workspace,
                        "primary_noop_call_changed",
                    )
                    require(
                        scenario.events.index("registry")
                        < scenario.events.index("daemon_construct")
                        < scenario.events.index("observer_enter")
                        < scenario.events.index("publisher_start"),
                        "early_attachment_order",
                    )
                    report["passed_controls"].append(f"early_real_factory_identity_and_complete_registration_{count}")
                finally:
                    cleanup = adapter._close_failed_workspace_construction()
                    require(
                        cleanup["private_state_removed"] is True and scenario.cleanup_homes == [adapter.guard_home],
                        "owned_control_cleanup",
                    )
            faults = (
                "store",
                "registry",
                "factory",
                "already_started",
                "populated_cache",
                "preexisting_registration",
                "registration",
                "observer_enter",
                "duplicate_factory",
                "publisher_start",
                "daemon_after_start",
                "worker_identity",
                "test_oracle",
                "after_daemon",
                "publisher_close",
                "publisher_thread_survives",
                "resident_stop",
                "observer_close",
                "daemon_stop",
                "daemon_uncontained",
                "fixture_close",
            )
            for fault in faults:
                scenario = Scenario(parent, fault=fault)
                try:
                    scenario.execute()
                except FixtureFailureError as error:
                    cleanup = error.detail["workspace_construction_cleanup"]
                    require(
                        original_failure_class(error.detail).detail == error.detail,
                        "cleanup_fields_lost_at_actual_privacy_boundary",
                    )
                    nested = {"cells": [{"failure": {"primary": error.detail}}]}
                    require(assert_privacy_safe(nested) == nested, "nested_cleanup_evidence_truncated")
                    require(
                        scenario.hook_worker.get_native_policy_snapshot_publisher is scenario.factory,
                        "failed_factory_patch_not_restored",
                    )
                    require(
                        all(type(value) is bool for value in cleanup.values()),
                        "raw_cleanup_not_fixed_boolean",
                    )
                    if fault not in {
                        "already_started",
                        "populated_cache",
                        "preexisting_registration",
                        "duplicate_factory",
                        "worker_identity",
                        "test_oracle",
                    }:
                        require(
                            error.detail["original_identity"] == id(scenario.original_error),
                            "original_construction_error_lost",
                        )
                    if scenario.publisher is not None:
                        require(
                            "publisher_close" in scenario.events,
                            "captured_publisher_not_closed",
                        )
                    if fault not in {"store", "registry"}:
                        require(
                            scenario.cleanup_homes == [scenario.home],
                            "scoped_native_cleanup_missing",
                        )
                    if fault in {
                        "store",
                        "registry",
                        "worker_identity",
                        "test_oracle",
                        "after_daemon",
                    }:
                        require(
                            cleanup["private_state_removed"] is True and not scenario.home.parent.exists(),
                            "contained_home_not_removed",
                        )
                    else:
                        require(
                            cleanup["private_state_removed"] is False and scenario.home.parent.is_dir(),
                            "unconfirmed_home_deleted",
                        )
                    if fault == "publisher_thread_survives":
                        require(
                            cleanup["publisher_closed"] is True and cleanup["publisher_thread_stopped"] is False,
                            "thread_join_failure_hidden",
                        )
                    if fault == "resident_stop":
                        require(
                            cleanup["resident_contained"] is False,
                            "resident_failure_hidden",
                        )
                    if fault == "daemon_uncontained":
                        require(
                            cleanup["daemon_stop_completed"] is True
                            and cleanup["daemon_containment_confirmed"] is False,
                            "daemon_containment_assumed",
                        )
                    if fault == "observer_close":
                        require(
                            cleanup["observer_closed"] is False,
                            "observer_cleanup_failure_hidden",
                        )
                    if fault == "fixture_close":
                        require(
                            cleanup["fixture_closed"] is False and cleanup["observer_closed"] is True,
                            "failed_fixture_close_skipped_observer_cleanup",
                        )
                    if fault == "duplicate_factory":
                        require(
                            len(scenario.calls) == 2,
                            "duplicate_created_unowned_publisher",
                        )
                    report["passed_controls"].append("construction_failure_" + fault)
                else:
                    raise RuntimeError("construction_fault_was_accepted")
            # The retained failed home uses mkdtemp; there is no TemporaryDirectory
            # finalizer tied to an unsuccessfully constructed AdapterSession.
            require(scenario.adapter.temporary is None, "failed_home_has_implicit_finalizer")
            report["passed_controls"].append("failed_home_retention_has_explicit_ownership")

            class ReceiptWitness:
                def __enter__(self) -> Any:
                    return self

            module("scripts.native_slo_mixed_witness", ReceiptWitness=ReceiptWitness)
            module(
                "codex_plugin_scanner.guard.native_decision_receipt",
                validate_native_decision_receipt=lambda value: value,
            )
            from workspace_extension import install

            for boundary in ("normal", "wrong_parent"):
                scenario = Scenario(parent, count=1)
                module("scripts.native_slo_session", AdapterSession=scenario.Adapter)
                registry = parent / ("registry-" + boundary + ".jsonl")
                registry.touch(mode=0o600)
                original_construct = scenario.Adapter._construct_workspace_daemon

                def registered_before_factory(
                    adapter: Any, *args: Any, _registry=registry, _original=original_construct, **kwargs: Any
                ) -> Any:
                    values = [json.loads(line) for line in _registry.read_bytes().splitlines()]
                    require(
                        len(values) == 1 and values[0]["home"] == str(adapter.guard_home),
                        "actual_registry_missing_before_factory",
                    )
                    require(values[0]["root"] == str(adapter.root), "actual_registry_wrong_root")
                    require(args == (1,) and not kwargs, "construction_arguments_changed")
                    return _original(adapter, *args, **kwargs)

                scenario.Adapter._construct_workspace_daemon = registered_before_factory
                install(
                    {
                        "temporary_parent": str(parent if boundary == "normal" else parent / "wrong"),
                        "private_registry": str(registry),
                    }
                )
                if boundary == "normal":
                    adapter = scenario.execute()
                    require(len(scenario.calls) == 2, "extension_factory_call_count_changed")
                    require(
                        adapter._close_failed_workspace_construction()["private_state_removed"] is True,
                        "extension_control_cleanup",
                    )
                    report["passed_controls"].append("actual_private_registry_precedes_original_constructor")
                else:
                    try:
                        scenario.execute()
                    except FixtureFailureError as error:
                        require(
                            error.detail["category"] == "Failure" and not scenario.calls, "unsafe_home_reached_factory"
                        )
                        require(registry.read_bytes() == b"", "unsafe_home_registered")
                        require(
                            error.detail["workspace_construction_cleanup"]["private_state_removed"] is True,
                            "unstarted_unsafe_control_not_cleaned",
                        )
                        report["passed_controls"].append("actual_private_registry_rejects_wrong_parent_before_factory")
                    else:
                        raise RuntimeError("wrong_parent_accepted")
        report["result"] = "passed"
    except BaseException as error:
        report["result"] = "failed"
        report["failures"].append(error_name(error))
    write_json(args.output, report)
    print(
        json.dumps(
            {
                "result": report["result"],
                "controls": len(report["passed_controls"]),
                "failures": report["failures"],
                "native_execution_performed": False,
            }
        )
    )
    return int(report["result"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
