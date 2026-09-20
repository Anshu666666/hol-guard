"""Admit only the eleven pinned publisher functions collected through their facade."""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

FACADE_PATH = "tests/test_native_policy_snapshot_v3_publisher.py"
FACADE_MODULE = "tests.test_native_policy_snapshot_v3_publisher"
PROVIDER_PATH = "tests/test_native_policy_snapshot_publisher.py"
PROVIDER_MODULE = "tests.test_native_policy_snapshot_publisher"
PUBLISHER_ALIASES = {
    "tests/test_native_policy_snapshot_v3_publisher.py::"
    "test_publisher_startup_ack_and_mutation_push":
        "test_publisher_startup_ack_and_mutation_push",
    "tests/test_native_policy_snapshot_v3_publisher.py::"
    "test_publisher_does_not_ack_snapshot_after_concurrent_mutation":
        "test_publisher_does_not_ack_snapshot_after_concurrent_mutation",
    "tests/test_native_policy_snapshot_v3_publisher.py::"
    "test_publisher_repushes_after_resident_generation_change":
        "test_publisher_repushes_after_resident_generation_change",
    "tests/test_native_policy_snapshot_v3_publisher.py::"
    "test_publisher_does_not_republish_for_generation_created_by_own_ack":
        "test_publisher_does_not_republish_for_generation_created_by_own_ack",
    "tests/test_native_policy_snapshot_v3_publisher.py::"
    "test_publisher_rejects_ack_after_resident_restart_before_barrier":
        "test_publisher_rejects_ack_after_resident_restart_before_barrier",
    "tests/test_native_policy_snapshot_v3_publisher.py::"
    "test_publisher_rejects_mutated_ack_without_opening_barrier":
        "test_publisher_rejects_mutated_ack_without_opening_barrier",
    "tests/test_native_policy_snapshot_v3_publisher.py::"
    "test_auto_hook_uses_barrier_without_loading_config_per_request":
        "test_auto_hook_uses_barrier_without_loading_config_per_request",
    "tests/test_native_policy_snapshot_v3_publisher.py::"
    "test_prepare_workspace_policy_uses_bounded_first_workspace_handshake":
        "test_prepare_workspace_policy_uses_bounded_first_workspace_handshake",
    "tests/test_native_policy_snapshot_v3_publisher.py::"
    "test_prepare_workspace_policy_waits_publish_budget_without_caller_deadline":
        "test_prepare_workspace_policy_waits_publish_budget_without_caller_deadline",
    "tests/test_native_policy_snapshot_v3_publisher.py::"
    "test_prepare_workspace_policy_skips_wait_after_publisher_error":
        "test_prepare_workspace_policy_skips_wait_after_publisher_error",
    "tests/test_native_policy_snapshot_v3_publisher.py::"
    "test_same_generation_retries_reuse_exact_signed_snapshot_bytes":
        "test_same_generation_retries_reuse_exact_signed_snapshot_bytes",
}


def collecting_source_record(item, function: dict, source_record) -> dict | None:
    selected_path = item.nodeid.split("::", 1)[0]
    name = PUBLISHER_ALIASES.get(item.nodeid)
    assert function["origin"] == "candidate"
    if name is None:
        assert function["path"] == selected_path
        return None

    facade = sys.modules[FACADE_MODULE]
    provider = sys.modules[PROVIDER_MODULE]
    records = {}
    for role, module, expected_path in (
        ("facade", facade, FACADE_PATH), ("provider", provider, PROVIDER_PATH),
    ):
        record = source_record(Path(module.__file__), retain=True)
        records[role] = record
        assert record["origin"] == "candidate" and record["path"] == expected_path
    assert selected_path == FACADE_PATH and function["path"] == PROVIDER_PATH
    assert records["provider"]["sha256"] == function["sha256"]
    assert item.name == name and getattr(item, "callspec", None) is None
    assert item.module is facade and facade.__name__ == FACADE_MODULE
    assert provider.__name__ == PROVIDER_MODULE and facade._publisher_tests is provider
    assert getattr(provider, "__test__", None) is False
    assert getattr(facade, "__test__", True) is True
    actual = item.function
    assert item.obj is actual and inspect.unwrap(actual) is actual
    assert getattr(facade, name) is getattr(provider, name) is actual
    assert actual.__module__ == PROVIDER_MODULE
    assert actual.__name__ == actual.__qualname__ == name
    assert actual.__code__.co_name == actual.__code__.co_qualname == name
    assert function["module"] == function["wrapped_module"] == PROVIDER_MODULE
    assert function["qualname"] == function["wrapped_qualname"] == function["code_qualname"] == name
    assert source_record(Path(actual.__code__.co_filename)) == records["provider"]
    return {
        "scope": "exact_publisher_facade_alias", "nodeid": item.nodeid, "name": name,
        "facade_module": FACADE_MODULE, "provider_module": PROVIDER_MODULE,
        "sources": records, "same_unwrapped_function_object": True,
        "facade_provider_module_binding_identical": True,
        "provider_collecting": False, "facade_collecting": True,
    }
