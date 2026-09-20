"""Fresh admission for one unchanged production hash/policy consumer pair.

The first supported route is exact plain data, canonical application callbacks,
the pinned POSIX CPython profile, and actual warm regex/ABC hits. Every other
route retains the original consumers. No request facts or admission results
survive this object.
"""

from __future__ import annotations

import pathlib
import re
from types import FunctionType, GetSetDescriptorType, ModuleType
from typing import cast

from .mcp_literal_cache_admission import literal_cache_is_canonical
from .mcp_literal_pattern_cache import StringLiteralCache
from .mcp_risk_pair_authority import inspect_pair_authority
from .mcp_risk_pair_data import UnsupportedPairData, plain_json_input, plain_snapshot, raw_instance_dict, slot_values
from .mcp_risk_pair_json import check_json_base64_providers
from .mcp_risk_pair_mapping import mapping_cache_supports
from .mcp_risk_pair_native import check_native_pair_providers
from .mcp_risk_pair_paths import check_path_providers
from . import mcp_risk_pair_profile as source_profile
from .mcp_risk_pair_providers import (
    application_providers, application_state, declared, module_values, record_field_metadata,
)
from .mcp_risk_pair_records import frozen_pair_record_supported
from .mcp_risk_pair_regex import RiskRegexWitness
from .mcp_risk_pair_regex_providers import check_risk_regex_providers
from .mcp_risk_pair_source import SourceDeclarations

_PREFIX = "codex_plugin_scanner.guard."
_INSPECT_TYPE = type
_INSPECT_ANY = any
_INSPECT_STR = str
_RECORDS = [
    [
        "codex_plugin_scanner.guard.config",
        "GuardConfig",
        [
            "guard_home",
            "workspace",
            "mode",
            "presentation_mode",
            "presentation_mode_explicit",
            "presentation_schema_version",
            "presentation_revision",
            "presentation_source",
            "presentation_diagnostic",
            "protection_posture",
            "protection_posture_explicit",
            "watch_auto_revert_hours",
            "watch_entered_at",
            "security_level",
            "default_action",
            "unknown_publisher_action",
            "changed_hash_action",
            "new_network_domain_action",
            "subprocess_action",
            "approval_wait_timeout_seconds",
            "approval_surface_policy",
            "approval_browser_delay_seconds",
            "approval_browser_immediate_severity",
            "desktop_notifications",
            "update_channel",
            "telemetry",
            "sync",
            "receipt_redaction_level",
            "billing",
            "runtime_detector_registry",
            "runtime_detector_timeout_ms",
            "runtime_detector_debug_trace",
            "runtime_detector_disabled_ids",
            "sandbox_analysis",
            "risk_actions",
            "harness_risk_actions",
            "harness_actions",
            "publisher_actions",
            "artifact_actions",
            "evidence_retain_days",
            "receipt_detail_limit",
            "guard_event_limit",
            "managed_policy_status",
            "managed_policy_hash",
            "managed_locked_settings",
            "install_owner",
            "managed_policy"
        ]
    ],
    [
        "codex_plugin_scanner.guard.models",
        "GuardArtifact",
        [
            "artifact_id",
            "name",
            "harness",
            "artifact_type",
            "source_scope",
            "config_path",
            "command",
            "args",
            "url",
            "transport",
            "publisher",
            "metadata",
            "runtime_private_metadata"
        ]
    ],
    [
        "codex_plugin_scanner.guard.adapters.base",
        "HarnessContext",
        [
            "home_dir",
            "workspace_dir",
            "guard_home",
            "executable_overrides",
            "home_override_explicit",
            "workspace_override_explicit"
        ]
    ],
    [
        "codex_plugin_scanner.guard.runtime.mcp_protection",
        "McpServerIdentity",
        [
            "config_path",
            "command",
            "args_hash",
            "package_name",
            "package_version",
            "package_source",
            "transport",
            "env_keys",
            "env_values_hash",
            "identity_hash"
        ]
    ]
]
_PROXY_CLASSES = (
    "RuntimeMcpGuardProxy", "ElicitationMcpGuardProxy", "CodexMcpGuardProxy",
    "CopilotMcpGuardProxy", "CursorMcpGuardProxy", "OpenCodeMcpGuardProxy",
)
_AUTHORITY_VALUES = (
    "command", "context", "harness", "server_name", "source_scope", "config_path",
    "transport", "server_id", "server_env_keys", "server_identity",
    "_active_executable_identity", "_active_runtime_launch_identity",
    "_active_server_env_values_hash", "_active_server_identity",
    "_tool_catalog_generation", "_tool_catalog_state",
)


def _catalog_data(catalog: object, expected: object) -> object:
    if type(catalog) is dict:
        return catalog
    if type(catalog) is not expected:
        raise UnsupportedPairData
    namespace = type.__getattribute__(expected, "__dict__")
    if any(type(key) is not str for key in namespace):
        raise UnsupportedPairData
    for owner in type.__getattribute__(expected, "__mro__"):
        fields = type.__getattribute__(owner, "__dict__")
        if any(type(key) is not str for key in fields) or "_definitions" in fields:
            raise UnsupportedPairData
    descriptor = namespace.get("__dict__")
    if (
        type(descriptor) is not GetSetDescriptorType
        or descriptor.__objclass__ is not expected or descriptor.__name__ != "__dict__"
    ):
        raise UnsupportedPairData
    values = descriptor.__get__(catalog, expected)
    if type(values) is not dict or any(type(key) is not str for key in values):
        raise UnsupportedPairData
    result = values.get("_definitions")
    if type(result) is not dict:
        raise UnsupportedPairData
    return result


def _mapping_types(arguments: object, metadata: dict[str, object]) -> tuple[type, ...]:
    # Recursive Mapping checks reach arguments and the schema, not every scalar
    # carried in identity metadata. Identity/fingerprint checks inspect only
    # their top-level values on the supported non-browser route.
    found = {
        dict, str, type(None),
        type(metadata.get("server_fingerprint")),
        type(metadata.get("mcp_server_identity")),
        type(metadata.get("mcp_tool_identity")),
    }
    pending = [arguments, metadata.get("tool_schema")]
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        kind = type(item)
        found.add(kind)
        if kind is dict:
            if id(item) in seen:
                continue
            seen.add(id(item))
            pending.extend(item.values())
        elif kind is list or kind is tuple:
            if id(item) in seen:
                continue
            seen.add(id(item))
            pending.extend(item)
    return tuple(found)


class PrivateRiskPairAdmission:
    __slots__ = ("proxy", "artifact", "arguments", "config", "regex", "_initial")

    def __init__(self, proxy: object, artifact: object, arguments: object, config: object) -> None:
        self.proxy = proxy
        self.artifact = artifact
        self.arguments = arguments
        self.config = config
        regex_values = ModuleType.__getattribute__(re, "__dict__")
        if _INSPECT_ANY(_INSPECT_TYPE(key) is not _INSPECT_STR for key in regex_values):
            raise UnsupportedPairData
        self.regex = RiskRegexWitness(re, regex_values.get("Pattern"))
        self._initial: tuple[object, ...] | None = None

    def _capture(self, declarations: dict[str, SourceDeclarations]) -> tuple[object, ...]:
        runtime, runtime_values = module_values(_PREFIX + "proxy.runtime_mcp")
        calls, call_values = module_values(_PREFIX + "mcp_tool_calls")
        token_module, token_values = module_values(_PREFIX + "runtime.approval_context")
        cache_module, cache_values = module_values(_PREFIX + "mcp_literal_pattern_cache")
        records: list[tuple[type, tuple[str, ...]]] = []
        for module_name, name, field_names in _RECORDS:
            _, values = module_values(module_name)
            cls = values.get(name)
            if type(cls) is not type:
                raise UnsupportedPairData
            names = tuple(field_names)
            record_field_metadata(cls, names)
            records.append((cls, names))
        record_types = tuple(records)
        artifact_type = records[1][0]
        config_type = records[0][0]
        if type(self.artifact) is not artifact_type or type(self.config) is not config_type:
            raise UnsupportedPairData
        # Initial scope excludes the separate posture-default provider route.
        config_data = dict(zip(records[0][1], slot_values(self.config, config_type, records[0][1]), strict=True))
        if config_data["protection_posture_explicit"] is not False or config_data["workspace"] is None:
            raise UnsupportedPairData
        literal_type = call_values.get("_LiteralRiskPattern")
        if not frozen_pair_record_supported(literal_type, calls, token=False):
            raise UnsupportedPairData
        if not frozen_pair_record_supported(token_values.get("ApprovalContextToken"), token_module, token=True):
            raise UnsupportedPairData
        wrapped = call_values.get("_literal_pattern")
        if type(wrapped) is not FunctionType:
            raise UnsupportedPairData
        wrapper_values = wrapped.__dict__
        if any(type(key) is not str for key in wrapper_values):
            raise UnsupportedPairData
        cache = wrapper_values.get("_guard_literal_cache")
        factory = wrapper_values.get("__wrapped__")
        if cache_values.get("StringLiteralCache") is not StringLiteralCache or type(cache) is not StringLiteralCache:
            raise UnsupportedPairData
        if not declarations[_PREFIX + "mcp_tool_calls"].matches(factory, calls, "_literal_pattern"):
            raise UnsupportedPairData
        if not declarations[_PREFIX + "mcp_literal_pattern_cache"].matches(
            wrapped, cache_module, "string_literal_lru.<locals>.decorate.<locals>.wrapped", closure=(cache,)
        ):
            raise UnsupportedPairData
        if not literal_cache_is_canonical(cache, literal_type, factory):
            raise UnsupportedPairData
        allowed = tuple(runtime_values[name] for name in _PROXY_CLASSES) + (object,)
        raw = raw_instance_dict(self.proxy, allowed)
        if "_check_tool_call_preparation" in raw:
            raise UnsupportedPairData
        expected_prepare = declared(runtime_values, "RuntimeMcpGuardProxy._check_tool_call_preparation")
        for owner in type.__getattribute__(type(self.proxy), "__mro__"):
            namespace = type.__getattribute__(owner, "__dict__")
            if any(name in namespace for name in ("context", "store")):
                raise UnsupportedPairData
            if "_disable_saved_allow_without_complete_catalog" in namespace and type(
                namespace["_disable_saved_allow_without_complete_catalog"]
            ) is not FunctionType:
                raise UnsupportedPairData
            if "_check_tool_call_preparation" in namespace:
                if namespace["_check_tool_call_preparation"] is not expected_prepare:
                    raise UnsupportedPairData
        catalog = _catalog_data(raw["_tool_catalog"], runtime_values["ToolCatalog"])
        context = raw["context"]
        workspace = slot_values(context, records[2][0], ("workspace_dir",))[0]
        if workspace is None:
            raise UnsupportedPairData
        artifact_data = dict(zip(records[1][1], slot_values(self.artifact, artifact_type, records[1][1]), strict=True))
        metadata = artifact_data["metadata"]
        if type(metadata) is not dict or any(type(key) is not str for key in metadata):
            raise UnsupportedPairData
        plain_json_input(self.arguments)
        plain_json_input(metadata)
        plain_json_input(catalog)
        payload = (
            self.config, raw["config"], self.artifact, self.arguments,
            tuple(raw[name] for name in _AUTHORITY_VALUES), catalog,
        )
        captured = plain_snapshot(payload, records=record_types, path_types=(pathlib.PosixPath, pathlib.PurePath))
        if not mapping_cache_supports(declarations, _mapping_types(self.arguments, metadata)):
            raise UnsupportedPairData
        authority = inspect_pair_authority(
            runtime=runtime, declarations=declarations, proxy=self.proxy,
            artifact=self.artifact, arguments=self.arguments, config=self.config,
        )
        _, extension = module_values(_PREFIX + "runtime.extension_control_runtime")
        active = extension["_ACTIVE_SNAPSHOT"].get()
        extension_data = None
        if active is not None:
            cls = extension["ExtensionControlRuntimeSnapshot"]
            digest = slot_values(active, cls, ("effective_digest",))[0]
            if type(digest) is not str:
                raise UnsupportedPairData
            extension_data = (id(active), digest)
        return (
            captured, plain_snapshot(authority, records=record_types, path_types=(pathlib.PosixPath, pathlib.PurePath)),
            application_state(), extension_data, id(raw["store"]), id(raw["_current_config_provider"]),
        )

    def check(self) -> bool:
        declarations = source_profile.DECLARATIONS
        if declarations is None:
            return False
        try:
            if not (
                check_native_pair_providers()
                and check_json_base64_providers(declarations)
                and check_path_providers(declarations)
                and check_risk_regex_providers(declarations)
                and application_providers(declarations)
                and self.regex.check()
            ):
                return False
            current = self._capture(declarations)
            if self._initial is None:
                self._initial = current
            return current == self._initial
        except (UnsupportedPairData, AttributeError, KeyError, TypeError, ValueError, RecursionError, RuntimeError):
            return False


def make_risk_pair_admission(
    proxy: object, artifact: object, arguments: object, config: object,
) -> PrivateRiskPairAdmission | None:
    if source_profile.DECLARATIONS is None:
        return None
    try:
        admission = PrivateRiskPairAdmission(proxy, artifact, arguments, config)
    except (UnsupportedPairData, TypeError, ValueError):
        return None
    return admission if admission.check() else None
