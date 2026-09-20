"""Observe only the forty current Pi methods collected through the existing facade."""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

PI_FACADE_PATH = "tests/test_pi_adapter.py"
PI_FACADE_MODULE = "tests.test_pi_adapter"
PI_CLASSES = {
    "TestPiAdapterIdentity": (
        "tests.pi_adapter_identity_cases",
        (
            "test_harness_identifier_is_pi",
            "test_pi_aliases_resolve_to_pi",
            "test_omp_aliases_resolve_to_omp",
            "test_pi_is_registered",
            "test_contract_exists",
            "test_omp_contract_exists",
            "test_managed_approval_flow_auto_opens_approval_center_once_as_fallback",
            "test_unmanaged_approval_flow_keeps_browser_fallback_visible",
            "test_unmanaged_omp_approval_flow_names_oh_my_pi",
        ),
    ),
    "TestPiDetect": (
        "tests.pi_adapter_identity_cases",
        (
            "test_detect_marks_omp_cli_as_available",
            "test_detect_finds_omp_in_user_local_bin_when_gui_path_omits_it",
            "test_detect_omp_warning_mentions_omp",
            "test_detects_settings_extensions_skills_prompts_themes_and_packages",
            "test_detect_keeps_empty_settings_file",
            "test_detects_omp_settings_and_extensions",
            "test_pi_and_omp_managed_extensions_have_separate_harnesses",
            "test_pi_and_omp_shared_configured_extension_keeps_separate_harness_ids",
            "test_detect_expands_configured_extension_glob",
            "test_root_skill_uses_stable_identity",
        ),
    ),
    "TestPiInstall": (
        "tests.pi_adapter_install_cases",
        (
            "test_install_writes_managed_extension",
            "test_install_writes_managed_extension_that_denies_on_hook_errors",
            "test_managed_extension_fails_safe_on_ambiguous_success_payloads",
            "test_install_writes_managed_extension_that_truncates_post_tool_payloads",
            "test_omp_install_writes_only_omp_extension",
            "test_omp_display_name_does_not_rewrite_paths_containing_pi",
            "test_uninstall_removes_managed_extension",
        ),
    ),
    "TestPiRuntime": (
        "tests.pi_adapter_runtime_cases",
        (
            "test_pi_payload_normalizes_like_other_harnesses",
            "test_omp_payload_keeps_omp_identity",
            "test_pi_post_tool_payload_normalizes_like_other_harnesses",
            "test_pi_post_tool_output_creates_runtime_artifact",
            "test_pi_stdout_only_post_tool_output_creates_runtime_artifact",
            "test_pi_grep_post_tool_output_records_rendered_command",
            "test_pi_post_tool_use_allows_medium_matches_from_external_source_search",
            "test_pi_post_tool_use_rejects_external_source_search_outside_home",
            "test_pi_external_source_search_still_blocks_dangerous_variants",
            "test_pi_external_source_search_still_blocks_real_credentials",
            "test_pi_source_file_read_with_credential_like_code_does_not_block",
            "test_pi_focused_pytest_messages_label_pi_runtime",
            "test_pi_repeated_blocked_tool_output_reuses_pending_approval",
            "test_pi_block_emits_native_json_and_stderr",
        ),
    ),
}
PI_ALIASES = {
    PI_FACADE_PATH + "::" + class_name + "::" + name: (module, class_name, name)
    for class_name, (module, names) in PI_CLASSES.items()
    for name in names
}
assert len(PI_ALIASES) == 40


def pi_source_record(item, function: dict, source_record) -> dict:
    module_name, class_name, name = PI_ALIASES[item.nodeid]
    provider_path = module_name.replace(".", "/") + ".py"
    facade, provider = sys.modules[PI_FACADE_MODULE], sys.modules[module_name]
    records = {}
    for role, module, path in (
        ("facade", facade, PI_FACADE_PATH), ("provider", provider, provider_path),
    ):
        record = source_record(Path(module.__file__), retain=True)
        assert record["origin"] == "candidate" and record["path"] == path
        records[role] = record
    assert item.module is facade and facade.__name__ == PI_FACADE_MODULE
    assert provider.__name__ == module_name
    assert getattr(facade, "__test__", True) is True and getattr(provider, "__test__", None) is False
    assert item.name == name and getattr(item, "callspec", None) is None
    cls = item.cls
    assert cls is getattr(facade, class_name) is getattr(provider, class_name)
    assert cls.__name__ == cls.__qualname__ == class_name and cls.__module__ == module_name
    assert cls.__bases__ == (object,)
    actual, bound = item.function, item.obj
    assert inspect.isfunction(actual) and inspect.unwrap(actual) is actual
    assert cls.__dict__[name] is getattr(cls, name) is actual
    assert bound.__func__ is actual and type(bound.__self__) is cls
    assert actual.__globals__ is vars(provider)
    qualified = class_name + "." + name
    assert actual.__module__ == module_name and actual.__name__ == name and actual.__qualname__ == qualified
    assert actual.__code__.co_name == name and actual.__code__.co_qualname == qualified
    assert function["origin"] == "candidate" and function["path"] == provider_path
    assert function["sha256"] == records["provider"]["sha256"]
    assert function["module"] == function["wrapped_module"] == module_name
    assert function["qualname"] == function["wrapped_qualname"] == function["code_qualname"] == qualified
    assert source_record(Path(actual.__code__.co_filename)) == records["provider"]
    shared = sorted(set(actual.__code__.co_names) & vars(provider).keys() & vars(facade).keys())
    for global_name in shared:
        assert vars(provider)[global_name] is vars(facade)[global_name], global_name
    return {
        "scope": "exact_pi_class_facade_alias", "nodeid": item.nodeid,
        "class_name": class_name, "method_name": name,
        "facade_module": PI_FACADE_MODULE, "provider_module": module_name, "sources": records,
        "same_class_function_and_bound_descriptor": True, "function_globals_are_provider": True,
        "initial_shared_facade_globals": shared, "provider_collecting": False, "facade_collecting": True,
    }
