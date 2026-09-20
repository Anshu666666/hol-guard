"""Bind the two C fixture registrations in the separate incoming2433 cohort."""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

C_PROVIDER_PATH = "tests/test_native_slo_sqlite_vfs.py"
C_PROVIDER_MODULE = "tests.test_native_slo_sqlite_vfs"
C_SELECTIONS = {
    C_PROVIDER_PATH + "::test_actual_compiled_callback_forwarding": 10,
    C_PROVIDER_PATH + "::test_actual_python_engine_commit_rollback_and_busy_equal_without_observer": 2,
    C_PROVIDER_PATH + "::test_writer_and_readback_connections_have_distinct_actual_opening_threads": 1,
    C_PROVIDER_PATH + "::test_cross_thread_connection_is_forwarded_but_scope_coverage_is_refused": 1,
    C_PROVIDER_PATH + "::test_live_file_retains_callbacks_until_actual_close_and_default_connections_continue": 1,
    C_PROVIDER_PATH + "::test_vfs_name_collision_refuses_without_changing_active_registry": 1,
    C_PROVIDER_PATH + "::test_extension_descriptor_admission_refuses_before_observation": 3,
    C_PROVIDER_PATH + "::"
    "test_store_factory_scope_does_not_intercept_unrelated_connections_and_restores_nested_readback": 1,
    C_PROVIDER_PATH + "::test_unadmitted_preloaded_library_is_refused_before_sqlite_extension_loading": 1,
    "tests/test_native_slo_sqlite_vfs_loader.py::"
    "test_two_real_images_and_repeated_first_image_keep_distinct_resident_loader_aliases": 1,
    "tests/test_native_slo_sqlite_vfs_loader.py::"
    "test_reused_loaded_image_still_requires_current_digest_and_metadata": 1,
    "tests/test_native_slo_sqlite_vfs_loader.py::"
    "test_failed_callback_attestation_never_enters_the_admitted_registry": 1,
}


def incoming_2433_c_fixture_record(items, function_record, source_record) -> dict:
    counts = {selector: 0 for selector in C_SELECTIONS}
    registrations = {}
    actual_definitions = {}
    actual_function = None
    for item in items:
        selector = item.nodeid.split("[", 1)[0]
        definitions = item._fixtureinfo.name2fixturedefs.get("sqlite_vfs_build", ())
        if selector not in C_SELECTIONS:
            assert not definitions, ("Unexpected C fixture consumer", item.nodeid)
            continue
        counts[selector] += 1
        assert len(definitions) == 1 and "sqlite_vfs_build" in item.fixturenames
        definition = definitions[0]
        baseid = item.nodeid.split("::", 1)[0]
        assert definition.baseid == baseid and definition.argname == "sqlite_vfs_build"
        assert definition.scope == "session" and definition.argnames == ("tmp_path_factory",)
        assert definition.params is definition.ids is None
        function = inspect.unwrap(definition.func)
        if actual_function is None:
            actual_function = function
        assert function is actual_function
        provider = sys.modules[C_PROVIDER_MODULE]
        assert getattr(item.module, "sqlite_vfs_build") is provider.sqlite_vfs_build
        assert provider.sqlite_vfs_build._get_wrapped_function() is function
        record = function_record(definition.func)
        assert record["origin"] == "candidate" and record["path"] == C_PROVIDER_PATH
        assert record["module"] == C_PROVIDER_MODULE
        assert record["qualname"] == record["code_qualname"] == "sqlite_vfs_build"
        collecting = source_record(Path(item.module.__file__), retain=True)
        assert collecting["origin"] == "candidate" and collecting["path"] == baseid
        assert item.module.__name__ == baseid[:-3].replace("/", ".")
        if baseid not in registrations:
            actual_definitions[baseid] = definition
            registrations[baseid] = {
                "baseid": baseid, "scope": "session", "provider": record,
                "collecting_source": collecting, "nodeids": [],
            }
        assert actual_definitions[baseid] is definition
        assert registrations[baseid]["provider"] == record
        registrations[baseid]["nodeids"].append(item.nodeid)
    assert counts == C_SELECTIONS
    assert set(registrations) == {
        "tests/test_native_slo_sqlite_vfs.py", "tests/test_native_slo_sqlite_vfs_loader.py",
    }
    assert len({id(value) for value in actual_definitions.values()}) == 2
    return {
        "scope": "exact_two_session_registrations_of_the_same_actual_C_fixture_function",
        "registrations": registrations, "selection_counts": counts,
        "fixture_instances_expected": 2, "selected_cases": 24,
        "same_unwrapped_provider_function_object": True,
        "same_imported_fixture_wrapper_object": True,
        "current_fixture_execution_claim": False,
    }
