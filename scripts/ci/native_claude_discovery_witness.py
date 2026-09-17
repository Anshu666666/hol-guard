"""Untimed Windows fixture observations, never native authorization evidence."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
from typing import Any


def _private_object(path: Path, *, directory: bool) -> str:
    """Inspect fresh security on one no-reparse handle; never repair a DACL.

    This is an independent current-object observation, not the Rust reader's
    retained relative ancestry walk or a proof about an earlier failed request.
    No write, create, DELETE, WRITE_DAC or WRITE_OWNER right is requested.
    """
    from ctypes import wintypes

    from codex_plugin_scanner.guard import native_policy_snapshot as api

    kernel = api._windows_dll("kernel32")
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    # READ_CONTROL | FILE_READ_ATTRIBUTES; OPEN_EXISTING, no reparse following.
    handle = create(str(path), 0x00020080, 0x3, None, 3, 0x02200000, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        return "open_failed"
    try:
        information_type = api._windows_file_information_type()
        information = information_type()
        get_information = kernel.GetFileInformationByHandle
        get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(information_type)]
        get_information.restype = wintypes.BOOL
        if not get_information(handle, ctypes.byref(information)):
            return "metadata_unavailable"
        attributes = int(information.dwFileAttributes)
        if attributes & 0x400 or bool(attributes & 0x10) != directory:
            return "identity_rejected"
        if not directory and int(information.nNumberOfLinks) != 1:
            return "identity_rejected"
        try:
            api._windows_verify_private_dacl(handle, owner_sid=api._windows_owner_sid(), directory=directory)
        except Exception:
            return "security_rejected"
        return "passed"
    finally:
        api._windows_close_handle(kernel, handle)


def windows_discovery_preflight(guard_home: Path, config_path: Path, config_sha256: str) -> dict[str, Any]:
    """Record fixed stage results before offers; diagnostic faults do not gate."""
    result: dict[str, Any] = {
        "schema": "hol-guard.claude-discovery-preflight.v1",
        "scope": "fixture_preflight_current_state",
        "native_reader_executed": False,
        "failed_request_cause_proven": False,
        "authorization_evidence": False,
        "supported": os.name == "nt",
        "observer_error": False,
    }
    stages = (
        "guard_directory",
        "key_file",
        "state_file",
        "config_read",
        "key_read",
        "state_read",
        "state_authentication",
        "peer_identity",
    )
    result.update(dict.fromkeys(stages, "not_observed"))
    if os.name != "nt":
        return result
    try:
        for stage, path, directory in (
            ("guard_directory", guard_home, True),
            ("key_file", guard_home / "daemon-discovery-key", False),
            ("state_file", guard_home / "daemon-state.json", False),
        ):
            result[stage] = _private_object(path, directory=directory)
        _discovery_stages(guard_home, config_path, config_sha256, result)
    except Exception:
        # No exception text, path, handle, SID, key or state is copied out.
        result["observer_error"] = True
    return result


def _discovery_stages(guard_home: Path, config_path: Path, config_sha256: str, result: dict[str, Any]) -> None:
    from codex_plugin_scanner.guard.daemon.discovery import load_daemon_discovery_key, verify_daemon_state
    from codex_plugin_scanner.guard.private_file_io import read_private_regular_bytes

    raw_config = read_private_regular_bytes(config_path, max_bytes=16 * 1024)
    if raw_config is None or hashlib.sha256(raw_config).hexdigest() != config_sha256:
        result["config_read"] = "identity_rejected"
        return
    try:
        config = json.loads(raw_config)
    except (ValueError, UnicodeError):
        result["config_read"] = "decode_rejected"
        return
    if not isinstance(config, dict) or not isinstance(config.get("daemon"), dict):
        result["config_read"] = "identity_rejected"
        return
    result["config_read"] = "passed"
    key = load_daemon_discovery_key(guard_home)
    result["key_read"] = "passed" if key is not None else "read_rejected"
    raw_state = read_private_regular_bytes(guard_home / "daemon-state.json", max_bytes=64 * 1024)
    if raw_state is None:
        result["state_read"] = "read_rejected"
        return
    try:
        state = json.loads(raw_state)
    except (ValueError, UnicodeError):
        result["state_read"] = "decode_rejected"
        return
    if not isinstance(state, dict):
        result["state_read"] = "decode_rejected"
        return
    result["state_read"] = "passed"
    if key is None:
        return
    result["state_authentication"] = "passed" if verify_daemon_state(state, discovery_key=key) else "rejected"
    peer_fields = ("compatibility_version", "package_version", "source_root", "runtime_fingerprint")
    same = all(state.get(name) == config["daemon"].get(name) for name in peer_fields)
    same = same and state.get("guard_home") == config.get("guard_home") == str(guard_home)
    result["peer_identity"] = "passed" if same else "rejected"
