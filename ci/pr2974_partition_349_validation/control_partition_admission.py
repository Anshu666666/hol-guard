"""Admit only the declared class selectors and current module-local autouse fixtures."""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

from control_pi_aliases import PI_ALIASES

CLASS_METHODS = {
    "tests/test_guard_cli_17_update_driver.py::TestGuardCli": (
        "test_guard_update_runs_pip_upgrade_in_current_environment",
        "test_guard_update_uses_pipx_when_running_from_pipx",
        "test_guard_update_pins_detected_stable_release_from_uv_canary",
        "test_guard_update_marks_already_current_pipx_runs_as_current",
        "test_guard_update_treats_first_install_as_updated_when_only_dependencies_are_current",
        "test_guard_update_dry_run_emits_planned_command",
        "test_guard_update_dry_run_skips_guard_store_init",
        "test_guard_update_skips_editable_installs",
        "test_guard_update_ignores_malformed_guard_config",
        "test_guard_update_ignores_guard_store_failures",
        "test_guard_update_forwards_requested_wheel",
    ),
    "tests/test_guard_cli_18_update_codex_integrity.py::TestGuardCli": (
        "test_guard_update_repairs_stale_codex_native_hooks",
        "test_guard_update_repairs_authenticated_codex_hook_tampering_despite_shape_match",
        "test_guard_update_refuses_to_replace_altered_codex_identity_record",
        "test_guard_update_does_not_reauthenticate_same_version_tampered_packaged_hook",
    ),
    "tests/test_guard_cli_19_update_codex_config.py::TestGuardCli": (
        "test_guard_update_repairs_missing_codex_config_for_managed_install",
        "test_guard_update_repairs_workspace_codex_install_in_recorded_workspace",
        "test_guard_update_fails_closed_on_malformed_codex_config",
        "test_guard_update_does_not_adopt_unmanaged_codex_config",
        "test_guard_update_reports_malformed_codex_hooks_without_crashing",
        "test_guard_update_reports_codex_repair_write_failures",
    ),
    "tests/test_guard_cli_20_update_codex_workspace.py::TestGuardCli": (
        "test_guard_update_repairs_codex_when_managed_install_lookup_fails",
        "test_guard_update_does_not_infer_codex_repair_workspace_from_caller_cwd",
        "test_guard_update_does_not_adopt_empty_caller_workspace_during_backup_repair",
    ),
    "tests/test_guard_cli_28_update_output.py::TestGuardCli": (
        "test_guard_update_human_output_uses_notes_instead_of_stderr_for_current",
        "test_guard_update_failed_output_keeps_stdout_details",
        "test_guard_update_deferred_output_keeps_propagation_detail_calm",
    ),
    "tests/test_guard_command_executors_update.py::TestAppUpdateOperations": (
        "test_update_operations_in_app_operations",
        "test_update_check_returns_status_payload",
        "test_update_calls_run_guard_update",
        "test_update_handles_failure_exit_code",
        "test_unsupported_app_operation_returns_failure",
    ),
    "tests/test_guard_command_executors_update.py::TestAutoUpdateThrottle": (
        "test_auto_update_skipped_within_throttle_window",
        "test_auto_update_runs_after_throttle_window",
        "test_auto_update_skipped_when_not_auto_updatable",
        "test_auto_update_skipped_when_no_update_available",
        "test_auto_update_handles_malformed_state",
    ),
}
CLASS_NODES = {
    prefix + "::" + name for prefix, names in CLASS_METHODS.items() for name in names
} | set(PI_ALIASES)
assert len(CLASS_NODES) == 77

EXTRA_AUTOUSE = {
    "tests/test_dashboard_update.py": (
        ("_use_legacy_status_distribution", "tests.test_dashboard_update"),
    ),
    "tests/test_guard_phase03_local_install.py": (
        ("_use_legacy_update_context", "tests.test_guard_phase03_local_install"),
    ),
    "tests/test_guard_phase03_remainder.py": (
        ("_use_legacy_update_context", "tests.test_guard_phase03_remainder"),
    ),
    "tests/test_guard_update_daemon_external_owner.py": (
        ("_stub_locator_publish", "tests.test_guard_update_daemon_external_owner"),
    ),
    "tests/test_guard_update_daemon_handoff.py": (
        ("_stub_locator_publish", "tests.test_guard_update_daemon_handoff"),
    ),
    "tests/test_guard_cli_17_update_driver.py": (
        ("_isolate_codex_runtime_marker", "tests.guard_cli_test_fixtures"),
        ("_use_legacy_update_context", "tests.guard_cli_test_fixtures"),
    ),
    "tests/test_guard_cli_18_update_codex_integrity.py": (
        ("_isolate_codex_runtime_marker", "tests.guard_cli_test_fixtures"),
        ("_use_legacy_update_context", "tests.guard_cli_test_fixtures"),
    ),
    "tests/test_guard_cli_19_update_codex_config.py": (
        ("_isolate_codex_runtime_marker", "tests.guard_cli_test_fixtures"),
        ("_use_legacy_update_context", "tests.guard_cli_test_fixtures"),
    ),
    "tests/test_guard_cli_20_update_codex_workspace.py": (
        ("_isolate_codex_runtime_marker", "tests.guard_cli_test_fixtures"),
        ("_use_legacy_update_context", "tests.guard_cli_test_fixtures"),
    ),
    "tests/test_guard_cli_28_update_output.py": (
        ("_isolate_codex_runtime_marker", "tests.guard_cli_test_fixtures"),
        ("_use_legacy_update_context", "tests.guard_cli_test_fixtures"),
    ),
}


def admit_selector(selector: str, source_inputs: dict) -> None:
    path, *definition = selector.split("::")
    assert path.endswith(".py") and path in source_inputs
    if len(definition) <= 1:
        if definition:
            assert definition[0].split("[", 1)[0].isidentifier()
            assert definition[0].startswith("test_")
        return
    assert len(definition) == 2 and selector.split("[", 1)[0] in CLASS_NODES


def selected_junit(item) -> dict:
    address, bracket, parameters = item.nodeid.partition("[")
    parts = address.split("::")
    assert parts[0].endswith(".py") and item.name == parts[-1] + bracket + parameters
    if item.cls is None:
        assert len(parts) == 2
    else:
        assert len(parts) == 3 and address in CLASS_NODES
        cls, method = item.cls, parts[-1]
        assert cls is getattr(item.module, parts[1])
        assert cls.__name__ == cls.__qualname__ == parts[1]
        assert cls.__dict__[method] is item.function
        assert item.obj.__func__ is item.function and type(item.obj.__self__) is cls
    # Match pytest 9.0.3 mangle_test_address while preserving parameters in item.name.
    classname = ".".join([parts[0][:-3].replace("/", "."), *parts[1:-1]])
    return {"classname": classname, "name": item.name}


def extra_autouse_record(item, observed: list, expected: list, fixture_rows: dict, source_record) -> list:
    path = item.nodeid.split("::", 1)[0]
    declared = EXTRA_AUTOUSE.get(path, ())
    assert sorted(observed) == sorted([*expected, *(name for name, _module in declared)])
    records = []
    if not declared:
        return records
    selected_module = path[:-3].replace("/", ".")
    assert item.module is sys.modules[selected_module] and item.module.__name__ == selected_module
    selected_source = source_record(Path(item.module.__file__), retain=True)
    assert selected_source["origin"] == "candidate" and selected_source["path"] == path
    fixture_type = sys.modules["_pytest.fixtures"].FixtureFunctionDefinition
    for name, module_name in declared:
        module = sys.modules[module_name]
        provider_path = module_name.replace(".", "/") + ".py"
        provider_source = source_record(Path(module.__file__), retain=True)
        assert provider_source["origin"] == "candidate" and provider_source["path"] == provider_path
        assert module.__name__ == module_name
        wrapper = getattr(item.module, name)
        assert type(wrapper) is fixture_type and wrapper is getattr(module, name)
        marker = wrapper._fixture_function_marker
        assert marker.autouse is True and marker.scope == "function"
        assert marker.params is marker.ids is marker.name is None
        definitions = item._fixtureinfo.name2fixturedefs[name]
        assert len(definitions) == len(fixture_rows[name]) == 1
        definition = definitions[0]
        actual = definition.func
        assert wrapper._get_wrapped_function() is inspect.unwrap(wrapper) is actual
        assert inspect.unwrap(actual) is actual and actual.__globals__ is vars(module)
        assert actual.__module__ == module_name and actual.__name__ == actual.__qualname__ == name
        assert definition.baseid == path and definition.scope == "function"
        assert definition.params is definition.ids is None and definition.argnames == ("monkeypatch",)
        function = fixture_rows[name][0]["function"]
        assert function["origin"] == "candidate" and function["path"] == provider_path
        assert function["sha256"] == provider_source["sha256"]
        assert function["module"] == function["wrapped_module"] == module_name
        assert function["qualname"] == function["wrapped_qualname"] == function["code_qualname"] == name
        assert source_record(Path(actual.__code__.co_filename)) == provider_source
        records.append({
            "name": name, "selected_module": selected_module, "provider_module": module_name,
            "selected_source": selected_source, "provider_source": provider_source,
            "same_fixture_wrapper_and_function": True, "function_globals_are_provider": True,
            "scope": definition.scope, "baseid": definition.baseid, "argnames": list(definition.argnames),
        })
    return records
