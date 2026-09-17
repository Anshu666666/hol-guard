"""Capability contract for the decision-critical I/O ownership gate."""

from __future__ import annotations

from collections.abc import Iterable

_GUARD = "src/codex_plugin_scanner/guard/"
_INITIAL_HEADER_PATH = _GUARD + "daemon/initial_header_reader.py"
INITIAL_HEADER_ROOTS = tuple(
    (_INITIAL_HEADER_PATH, name, "InitialHeaderReader") for name in ("__init__", "readinto", "close")
)
_INITIAL_HEADER_OPERATIONS = frozenset({"gettimeout", "dup", "setblocking", "recv_into", "register", "select", "close"})
# Each entry names a complete lexical function and its observed primitives.
# Other functions and primitives do not inherit these purpose classifications.
_SCOPED_IO = {
    # Generic Windows setup preserves existing directories. This existence
    # observation neither reads source content nor admits a discovery key;
    # the producer separately retains and verifies its private parent binding.
    ("daemon/discovery_windows.py", "create_private_directory_if_missing", "filesystem"): (
        "synchronous_discovery_setup",
        frozenset({"is_dir"}),
    ),
    ("daemon/initial_header_reader.py", "InitialHeaderReader.__init__", "socket_transport"): (
        "initial_header_transport",
        frozenset({"gettimeout", "dup", "setblocking"}),
    ),
    ("daemon/initial_header_reader.py", "InitialHeaderReader.readinto", "socket_transport"): (
        "initial_header_transport",
        frozenset({"recv_into"}),
    ),
    ("daemon/initial_header_reader.py", "InitialHeaderReader._wait_for_data", "socket_transport"): (
        "initial_header_transport",
        frozenset({"register", "select"}),
    ),
    ("daemon/initial_header_reader.py", "InitialHeaderReader._close_observer", "socket_transport"): (
        "initial_header_transport",
        frozenset({"close"}),
    ),
    ("daemon/initial_header_reader.py", "InitialHeaderReader.close", "socket_transport"): (
        "initial_header_transport",
        frozenset({"close"}),
    ),
    ("native_command_control_binding.py", "native_command_control_floor_mac", "decode"): (
        "transport_decode",
        frozenset({"decode"}),
    ),
    ("native_command_control_authority_io.py", "_unix_directory", "filesystem"): (
        "synchronous_authority_fence",
        frozenset({"open", "lstat"}),
    ),
    ("native_command_control_authority_io.py", "hold_command_control_authority_lock", "filesystem"): (
        "synchronous_authority_fence",
        frozenset({"open", "stat"}),
    ),
    ("daemon/hook_native_review_binding.py", "native_review_action_identity", "hash"): (
        "approval_identity",
        frozenset({"sha256"}),
    ),
    # Decode a bounded in-memory original hook. Its action/source identity is
    # the verified Rust request digest, not Python normalization or hashing.
    ("daemon/codex_native_live_decision.py", "_decode_hook_input", "decode"): (
        "continuation_transport_decode",
        frozenset({"loads"}),
    ),
    # These hashes bind continuation protocol metadata, never action/source
    # equivalence, policy classification, or approval artifact identity.
    ("continuation_payload.py", "offer_hash", "hash"): ("continuation_protocol_identity", frozenset({"sha256"})),
    ("continuation_runtime.py", "_opaque_target_id", "hash"): ("continuation_protocol_identity", frozenset({"sha256"})),
    ("codex_app_server.py", "_is_safe_local_socket_path", "filesystem"): (
        "continuation_endpoint_identity",
        frozenset({"resolve"}),
    ),
    ("codex_app_server.py", "_is_trusted_local_socket", "filesystem"): (
        "continuation_endpoint_identity",
        frozenset({"lstat"}),
    ),
    # The captured bridge PID's start marker and trusted platform probe
    # executable metadata prove the original waiting process is still live.
    ("live_process_identity.py", "_linux_proc_stat", "filesystem"): (
        "continuation_process_identity",
        frozenset({"open", "read"}),
    ),
    ("live_process_identity.py", "_trusted_posix_ps_path", "filesystem"): (
        "continuation_process_identity",
        frozenset({"resolve", "stat"}),
    ),
    ("durable_io.py", "fsync_directory", "filesystem"): ("synchronous_control_durability", frozenset({"open"})),
}


def initial_header_transport_operation(path: str, operation: str | None) -> bool:
    """Inventory only this helper's socket primitives, without exempting content I/O."""
    return path == _INITIAL_HEADER_PATH and operation in _INITIAL_HEADER_OPERATIONS


def scoped_io_category(path: str, kind: str, function: str, operation: str = "") -> str | None:
    if not path.startswith(_GUARD):
        return None
    entry = _SCOPED_IO.get((path[len(_GUARD) :], function, kind))
    if entry is None or (operation and operation not in entry[1]):
        return None
    return entry[0]


def capability_contract(compatibility_modes: Iterable[str]) -> list[dict[str, object]]:
    return [
        {
            "id": "windows_discovery_directory_setup",
            "authority": "python_control_plane",
            "python_decision_time_disk_io": True,
            "inventory_category": "synchronous_discovery_setup",
            "python_semantic_fallback": False,
            "scope": "existing_directory_observation_before_private_at_birth_setup",
            "failure": "producer_private_parent_binding_still_required",
        },
        {
            "id": "initial_http_header_transport",
            "authority": "python_byte_transport",
            "python_decision_time_disk_io": False,
            "inventory_category": "initial_header_transport",
            "python_semantic_fallback": False,
            "scope": "initially_incomplete_headers_original_absolute_deadline_and_atomic_ownership_transfer",
            "failure": "request_closed_without_dispatch",
        },
        {
            "id": "native_codex_browser_continuation_control",
            "authority": "python_control_plane_with_verified_rust_decision",
            "python_decision_time_disk_io": True,
            "inventory_categories": [
                "continuation_transport_decode",
                "continuation_protocol_identity",
                "continuation_endpoint_identity",
                "continuation_process_identity",
                "synchronous_control_durability",
            ],
            "python_semantic_fallback": False,
            "action_source_identity": "verified_rust_request_digest",
            "scope": "bounded_envelope_decode_continuation_metadata_endpoint_and_waiter_liveness_local_durability",
            "failure": "continuation_not_completed",
        },
        {
            "id": "command_review_mutation_fence",
            "authority": "shared_python_native_coordination",
            "python_decision_time_disk_io": True,
            "inventory_category": "synchronous_authority_fence",
            "python_semantic_fallback": False,
            "scope": "owned_lock_identity_and_shared_lease_through_review_response",
            "failure": "existing_event_specific_availability_contract",
        },
        {
            "id": "hook_posture_and_availability_response",
            "authority": "python_bridge",
            "python_decision_time_disk_io": True,
            "inventory_category": "synchronous_posture_config",
            "python_semantic_fallback": False,
            "failure": "event_specific_availability_contract",
        },
        {
            "id": "post_tool_source_read",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::read_bounded", "guard_hook_core::review_post_tool"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "sensitive_path_and_symlink_classification",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::classify_source_path", "guard_secure_fs::contains_symlink_component"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "pre_post_identity_and_equivalence",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::FileIdentity", "guard_hook_core::review_post_tool"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "archive_decode_package_inspection",
            "authority": "rust_when_hook_reachable",
            "rust_symbols": [
                "guard_command::pretool::evaluate_pre_tool_envelope",
                "guard_runtime::strict_json::parse",
                "guard_hook_core::extract_payload_output",
            ],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "policy_snapshot_admission",
            "authority": "rust",
            "rust_symbols": [
                "guard_runtime::policy_store::PolicySnapshotStore",
                "guard_runtime::edge::evaluate_envelope_with_store",
            ],
            "python_semantic_fallback": False,
            "python_decision_time_disk_io": False,
            "failure": "fail_closed",
        },
    ]
