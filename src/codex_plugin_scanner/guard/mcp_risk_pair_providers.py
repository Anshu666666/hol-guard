"""Fixed application declarations and aliases reached before pair retirement."""

from __future__ import annotations

import base64
import builtins
import dataclasses
import hashlib
import json
import math
import pathlib
import re
import sys
import typing
from collections import abc as collections_abc
from contextvars import ContextVar
from types import FunctionType, MemberDescriptorType, ModuleType
from typing import cast

from .mcp_risk_pair_data import UnsupportedPairData, plain_snapshot
from .mcp_risk_pair_source import SourceDeclarations
from . import mcp_risk_pair as pair_lifetime
from . import mcp_risk_pair_regex as pair_regex

_PREFIX = "codex_plugin_scanner.guard."
_FUNCTIONS = {
    "codex_plugin_scanner.guard.mcp_tool_calls": [
        "build_tool_call_hash",
        "_build_tool_call_hash_for_categories",
        "_matching_tool_call_risk_snapshot",
        "_tool_call_policy_context",
        "_configured_risk_action",
        "_normalized_tool_call_workspace",
        "evaluate_tool_call",
        "_evaluate_current_tool_call",
        "tool_call_risk_categories",
        "_tool_call_risk_category_set",
        "_serialized_tool_arguments",
        "_contains_ip_address",
        "_matches_any",
        "_token_pattern",
        "_argument_key_risk_categories",
        "_argument_key_names",
        "_schema_risk_categories",
        "_schema_property_key_names",
        "_resolve_local_schema_ref",
        "_resolve_local_schema_anchor",
        "_description_risk_categories",
        "_tool_schema_understates_name",
        "_normalized_argument_key",
        "_tool_name_tokens",
        "_risk_match_text",
        "_camel_token_normalized"
    ],
    "codex_plugin_scanner.guard.config": [
        "GuardConfig.resolve_action_override",
        "GuardConfig.resolve_artifact_or_publisher_action_override",
        "resolve_risk_action",
        "_posture_or_level_defaults"
    ],
    "codex_plugin_scanner.guard.runtime.approval_context": [
        "build_approval_context_token",
        "_component_hash",
        "ApprovalContextToken._payload"
    ],
    "codex_plugin_scanner.guard.runtime.extension_control_runtime": [
        "current_extension_control_snapshot",
        "current_extension_control_binding_digest"
    ],
    "codex_plugin_scanner.guard.runtime.browser_mcp_intent": [
        "is_browser_mcp_server",
        "normalize_browser_mcp_intent"
    ],
    "codex_plugin_scanner.guard.mcp_authority_binding": [
        "exact_authority_digest",
        "ExactAuthorityBinding.check",
        "check_current_mcp_authority",
        "current_mcp_authority_check"
    ],
    "codex_plugin_scanner.guard.proxy.tool_call_binding": [
        "ToolCallBinding.check",
        "_matches_frame",
        "_json_parts",
        "current_tool_call_binding"
    ],
    "codex_plugin_scanner.guard.proxy.runtime_mcp": [
        "RuntimeMcpGuardProxy._check_tool_call_preparation"
    ],
    "codex_plugin_scanner.guard.mcp_literal_pattern_cache": [
        "StringLiteralCache.__call__"
    ],
    "typing": [
        "cast"
    ],
    "dataclasses": [
        "fields"
    ]
}
_ALIASES = [
    [
        "codex_plugin_scanner.guard.mcp_tool_calls",
        "GuardConfig",
        "codex_plugin_scanner.guard.config",
        "GuardConfig"
    ],
    [
        "codex_plugin_scanner.guard.mcp_tool_calls",
        "GuardArtifact",
        "codex_plugin_scanner.guard.models",
        "GuardArtifact"
    ],
    [
        "codex_plugin_scanner.guard.mcp_tool_calls",
        "resolve_risk_action",
        "codex_plugin_scanner.guard.config",
        "resolve_risk_action"
    ],
    [
        "codex_plugin_scanner.guard.mcp_tool_calls",
        "build_approval_context_token",
        "codex_plugin_scanner.guard.runtime.approval_context",
        "build_approval_context_token"
    ],
    [
        "codex_plugin_scanner.guard.mcp_tool_calls",
        "normalize_browser_mcp_intent",
        "codex_plugin_scanner.guard.runtime.browser_mcp_intent",
        "normalize_browser_mcp_intent"
    ],
    [
        "codex_plugin_scanner.guard.mcp_tool_calls",
        "check_current_mcp_authority",
        "codex_plugin_scanner.guard.mcp_authority_binding",
        "check_current_mcp_authority"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "GuardConfig",
        "codex_plugin_scanner.guard.config",
        "GuardConfig"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "GuardArtifact",
        "codex_plugin_scanner.guard.models",
        "GuardArtifact"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "HarnessContext",
        "codex_plugin_scanner.guard.adapters.base",
        "HarnessContext"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "ToolCatalog",
        "codex_plugin_scanner.guard.proxy.tool_catalog",
        "ToolCatalog"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "build_tool_call_hash",
        "codex_plugin_scanner.guard.mcp_tool_calls",
        "build_tool_call_hash"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "evaluate_tool_call",
        "codex_plugin_scanner.guard.mcp_tool_calls",
        "evaluate_tool_call"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "_normalized_tool_call_workspace",
        "codex_plugin_scanner.guard.mcp_tool_calls",
        "_normalized_tool_call_workspace"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "exact_authority_digest",
        "codex_plugin_scanner.guard.mcp_authority_binding",
        "exact_authority_digest"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "check_current_mcp_authority",
        "codex_plugin_scanner.guard.mcp_authority_binding",
        "check_current_mcp_authority"
    ],
    [
        "codex_plugin_scanner.guard.proxy.runtime_mcp",
        "current_tool_call_binding",
        "codex_plugin_scanner.guard.proxy.tool_call_binding",
        "current_tool_call_binding"
    ],
    [
        "codex_plugin_scanner.guard.runtime.approval_context",
        "current_extension_control_binding_digest",
        "codex_plugin_scanner.guard.runtime.extension_control_runtime",
        "current_extension_control_binding_digest"
    ],
    [
        "codex_plugin_scanner.guard.runtime.browser_mcp_intent",
        "GuardArtifact",
        "codex_plugin_scanner.guard.models",
        "GuardArtifact"
    ],
    [
        "codex_plugin_scanner.guard.mcp_authority_binding",
        "GuardArtifact",
        "codex_plugin_scanner.guard.models",
        "GuardArtifact"
    ],
    [
        "codex_plugin_scanner.guard.mcp_authority_binding",
        "GuardConfig",
        "codex_plugin_scanner.guard.config",
        "GuardConfig"
    ],
    [
        "codex_plugin_scanner.guard.mcp_authority_binding",
        "HarnessContext",
        "codex_plugin_scanner.guard.adapters.base",
        "HarnessContext"
    ],
    [
        "codex_plugin_scanner.guard.mcp_authority_binding",
        "McpServerIdentity",
        "codex_plugin_scanner.guard.runtime.mcp_protection",
        "McpServerIdentity"
    ]
]
_BUILTINS = tuple(
    (name, vars(builtins)[name])
    for name in (
        "type", "object", "str", "bytes", "int", "float", "bool", "list", "tuple",
        "dict", "set", "frozenset", "len", "any", "all", "id", "isinstance",
        "next", "iter", "sorted", "enumerate", "zip", "getattr", "ord", "chr", "repr", "map",
        "TypeError", "ValueError", "RuntimeError", "RecursionError", "OSError",
        "AttributeError", "UnicodeError", "Exception", "BaseException",
    )
)


def module_values(name: str) -> tuple[ModuleType, dict[str, object]]:
    runtime_values = ModuleType.__getattribute__(sys, "__dict__")
    if any(type(key) is not str for key in runtime_values):
        raise UnsupportedPairData
    registry = runtime_values.get("modules")
    if type(registry) is not dict or any(type(key) is not str for key in registry):
        raise UnsupportedPairData
    module = dict.get(registry, name)
    if type(module) is not ModuleType:
        raise UnsupportedPairData
    namespace = ModuleType.__getattribute__(module, "__dict__")
    if any(type(key) is not str for key in namespace):
        raise UnsupportedPairData
    module_name = namespace.get("__name__")
    if type(module_name) is not str or module_name != name:
        raise UnsupportedPairData
    return cast(ModuleType, module), cast(dict[str, object], namespace)


def declared(namespace: dict[str, object], qualified: str) -> object:
    components = qualified.split(".")
    value = namespace.get(components[0])
    for name in components[1:]:
        if type(value) is not type:
            raise UnsupportedPairData
        fields = type.__getattribute__(value, "__dict__")
        if any(type(key) is not str for key in fields):
            raise UnsupportedPairData
        value = fields.get(name)
    return value


def plain_builtin_bindings(namespace: dict[str, object]) -> bool:
    """Known bootstrap builtin roots; reject module shadows before invocation."""
    _, builtin_values = module_values("builtins")
    return all(
        builtin_values.get(name) is expected and namespace.get(name, expected) is expected
        for name, expected in _BUILTINS
    )


def application_providers(declarations: dict[str, SourceDeclarations]) -> bool:
    try:
        namespaces: dict[str, dict[str, object]] = {}
        for name, functions in _FUNCTIONS.items():
            module, namespace = module_values(name)
            namespaces[name] = namespace
            source = declarations.get(name)
            if type(source) is not SourceDeclarations:
                return False
            if not plain_builtin_bindings(namespace):
                return False
            for function_name in functions:
                if not source.matches(declared(namespace, function_name), module, function_name):
                    return False
        for owner, name, target, target_name in _ALIASES:
            _, owner_values = module_values(owner)
            _, target_values = module_values(target)
            if owner_values.get(name) is not declared(target_values, target_name):
                return False
        for namespace in namespaces.values():
            for name, expected in (
                ("cast", typing.cast), ("Mapping", collections_abc.Mapping),
                ("json", json), ("re", re), ("math", math), ("Path", pathlib.Path),
                ("PurePath", pathlib.PurePath), ("sha256", hashlib.sha256),
                ("hashlib", hashlib), ("base64", base64),
            ):
                if name in namespace and namespace[name] is not expected:
                    return False
        _, authority = module_values(_PREFIX + "mcp_authority_binding")
        _, wire = module_values(_PREFIX + "proxy.tool_call_binding")
        _, extension = module_values(_PREFIX + "runtime.extension_control_runtime")
        framing_module, _ = module_values(_PREFIX + "proxy.framing")
        if wire.get("framing") is not framing_module:
            return False
        if any(type(namespace.get(name)) is not ContextVar for namespace, name in (
            (authority, "_CHECK"), (wire, "_CURRENT"), (extension, "_ACTIVE_SNAPSHOT"),
        )):
            return False
        if authority.get("fields") is not dataclasses.fields or authority.get("cast") is not typing.cast:
            return False
        for owner, bindings in (
            (_PREFIX + "mcp_tool_calls", (
                ("categories_for_hash", pair_lifetime.categories_for_hash),
                ("categories_for_current_policy", pair_lifetime.categories_for_current_policy),
                ("risk_pair_policy_scope", pair_lifetime.risk_pair_policy_scope),
                ("observed_risk_regex_value", pair_regex.observed_risk_regex_value),
            )),
            (_PREFIX + "proxy.runtime_mcp", (
                ("arm_risk_pair_policy", pair_lifetime.arm_risk_pair_policy),
                ("use_risk_pair", pair_lifetime.use_risk_pair),
                ("use_risk_regex_witness", pair_regex.use_risk_regex_witness),
            )),
            (_PREFIX + "runtime.browser_mcp_intent", (
                ("observed_risk_regex_value", pair_regex.observed_risk_regex_value),
                ("unsupported_risk_regex_route", pair_regex.unsupported_risk_regex_route),
            )),
        ):
            _, values = module_values(owner)
            if any(values.get(name) is not expected for name, expected in bindings):
                return False
        paths = authority.get("_PATH_TYPES")
        expected_paths = (pathlib.PosixPath, pathlib.WindowsPath, pathlib.PurePosixPath, pathlib.PureWindowsPath)
        if type(paths) is not tuple or len(paths) != len(expected_paths) or any(
            actual is not expected for actual, expected in zip(paths, expected_paths, strict=True)
        ):
            return False
        record_names = ("GuardArtifact", "GuardConfig", "HarnessContext", "ManagedPolicy",
                        "ManagedNetworkPolicy", "ManagedUpdatePolicy", "ManagedIntegrityTrust", "McpServerIdentity")
        records = authority.get("_RECORD_TYPES")
        if type(records) is not tuple or len(records) != len(record_names) or any(
            actual is not authority.get(name) or type(actual) is not type
            for actual, name in zip(records, record_names, strict=True)
        ):
            return False
        return True
    except (UnsupportedPairData, TypeError, ValueError, RecursionError, RuntimeError):
        return False


def record_field_metadata(cls: type, names: tuple[str, ...]) -> None:
    """Prove the dataclasses.fields data read by the unchanged authority check."""
    namespace = type.__getattribute__(cls, "__dict__")
    if any(type(key) is not str for key in namespace):
        raise UnsupportedPairData
    metadata = namespace.get("__dataclass_fields__")
    if type(metadata) is not dict or any(type(key) is not str for key in metadata):
        raise UnsupportedPairData
    _, dataclass_values = module_values("dataclasses")
    field_name = dataclass_values.get("_FIELDS")
    if tuple(metadata) != names or type(field_name) is not str or field_name != "__dataclass_fields__":
        raise UnsupportedPairData
    field_type = dataclass_values.get("Field")
    if type(field_type) is not type:
        raise UnsupportedPairData
    bases = type.__getattribute__(field_type, "__bases__")
    if len(bases) != 1 or bases[0] is not object:
        raise UnsupportedPairData
    fields = type.__getattribute__(field_type, "__dict__")
    if any(type(key) is not str for key in fields) or any(
        key in fields for key in ("__getattribute__", "__getattr__")
    ):
        raise UnsupportedPairData
    for key in ("name", "_field_type"):
        descriptor = fields.get(key)
        if (
            type(descriptor) is not MemberDescriptorType
            or descriptor.__name__ != key or descriptor.__objclass__ is not field_type
        ):
            raise UnsupportedPairData
    for name, item in metadata.items():
        if type(item) is not field_type:
            raise UnsupportedPairData
        actual_name = fields["name"].__get__(item, field_type)
        if type(actual_name) is not str or actual_name != name:
            raise UnsupportedPairData
        if fields["_field_type"].__get__(item, field_type) is not dataclass_values.get("_FIELD"):
            raise UnsupportedPairData


def application_state() -> tuple[object, ...]:
    groups = (
        ("config", ("VALID_RISK_ACTION_KEYS", "DEFAULT_SECURITY_LEVEL", "SECURITY_LEVEL_RISK_ACTIONS")),
        ("mcp_tool_calls", ("_MCP_TOOL_CALL_EVALUATOR_POLICY_VERSION",)),
        ("runtime.approval_context", ("_TOKEN_DOMAIN", "_TOKEN_VERSION", "APPROVAL_CONTEXT_TOKEN_PREFIX")),
        ("runtime.browser_mcp_intent", ("_BROWSER_SERVER_NAME_PATTERNS", "_BROWSER_PACKAGE_PATTERNS")),
        ("runtime.extension_control_runtime", ("_NO_CONTROL_DIGEST",)),
        ("proxy.framing", ("MAX_LINE_BYTES",)),
    )
    result: list[object] = []
    for suffix, names in groups:
        _, namespace = module_values(_PREFIX + suffix)
        result.append(tuple((name, plain_snapshot(namespace[name])) for name in names))
    for suffix, name in (
        ("mcp_authority_binding", "_CHECK"), ("proxy.tool_call_binding", "_CURRENT"),
        ("runtime.extension_control_runtime", "_ACTIVE_SNAPSHOT"),
    ):
        _, namespace = module_values(_PREFIX + suffix)
        result.append(id(namespace[name]))
    return tuple(result)
