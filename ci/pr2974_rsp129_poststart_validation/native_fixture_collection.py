"""Admit both module registrations of the exact original native-log fixture."""

from __future__ import annotations

import inspect
from pathlib import Path
import sys


def admit_fixture(item, session, function_record, source_record, config: dict) -> dict:
    from _pytest.fixtures import FixtureFunctionDefinition

    names = {
        "tests.test_native_noncommand_review_rust": "tests/test_native_noncommand_review_rust.py",
        "tests.test_installed_ollama_legacy_retry": "tests/test_installed_ollama_legacy_retry.py",
    }
    modules = {name: sys.modules[name] for name in names}
    provider_module = modules["tests.test_native_noncommand_review_rust"]
    wrapper = provider_module.rust_cases
    assert type(wrapper) is FixtureFunctionDefinition
    assert all(module.rust_cases is wrapper for module in modules.values())
    assert item.module is modules[item.module.__name__]
    function = wrapper._get_wrapped_function()
    assert function.__module__ == provider_module.__name__ and function.__qualname__ == "rust_cases"
    assert inspect.unwrap(wrapper) is function
    expected_path = names[item.module.__name__]
    definitions = item._fixtureinfo.name2fixturedefs["rust_cases"]
    assert len(definitions) == 1 and definitions[0].baseid == expected_path
    registrations = session._fixturemanager._arg2fixturedefs["rust_cases"]
    assert len(registrations) == 2
    assert sorted(row.baseid for row in registrations) == sorted(names.values())
    retained = []
    for definition in sorted(registrations, key=lambda row: row.baseid):
        assert definition.func is function and definition.scope == "module"
        assert definition.argnames == () and definition.params is None and definition.ids is None
        retained.append({
            "baseid": definition.baseid, "scope": definition.scope,
            "argnames": list(definition.argnames), "params": None, "ids": None,
            "function": function_record(definition.func),
            "registered_wrapper_is_original_provider": True,
        })
    provider = source_record(Path(inspect.getfile(FixtureFunctionDefinition)), retain=True)
    assert provider["origin"] == "owned_dependency"
    assert provider["sha256"] == config["native_fixture"]["pytest_fixture_provider_sha256"]
    return {
        "fixture_name": "rust_cases", "selected_module": item.module.__name__,
        "selected_registration": definitions[0].baseid, "provider_module": provider_module.__name__,
        "module_aliases": list(names), "same_wrapper_and_unwrapped_function": True,
        "registrations": retained, "pytest_registration_provider": provider,
    }
