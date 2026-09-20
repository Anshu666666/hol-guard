"""Bind the two real C fixture registrations used by incoming controls."""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

C_PROVIDER_PATH = "tests/test_native_slo_sqlite_vfs.py"
C_PROVIDER_MODULE = "tests.test_native_slo_sqlite_vfs"
C_SELECTIONS = {
    C_PROVIDER_PATH + "::test_failed_admission_cleanup_releases_observer_lock_before_real_retry": 1,
    "tests/test_native_slo_persistence_observation.py::"
    "test_wire_spec_installs_real_sqlite_and_queue_observation_in_mixed_dispatch": 1,
    "tests/test_native_slo_persistence_observation.py::"
    "test_failed_witness_start_releases_actual_vfs_before_a_valid_retry": 3,
}


def incoming_c_fixture_record(items, function_record, source_record) -> dict:
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
        "tests/test_native_slo_sqlite_vfs.py", "tests/test_native_slo_persistence_observation.py",
    }
    assert len({id(value) for value in actual_definitions.values()}) == 2
    return {
        "scope": "exact_two_session_registrations_of_the_same_actual_C_fixture_function",
        "registrations": registrations, "selection_counts": counts,
        "fixture_instances_expected": 2, "selected_cases": 5,
        "same_unwrapped_provider_function_object": True,
        "same_imported_fixture_wrapper_object": True,
        "current_fixture_execution_claim": False,
    }
