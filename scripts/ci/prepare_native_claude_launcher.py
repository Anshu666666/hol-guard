"""Explicit dormant-pilot argv preparation; never edits harness registration."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import cast
from urllib.parse import urlencode

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.daemon.discovery import load_authenticated_daemon_state
from codex_plugin_scanner.guard.native_command_control_authority_io import read_private_state, write_private_state

# Explicit preparation requests full validation through the existing identity implementation.
# pyright: reportPrivateUsage=false

_MAX_CONFIG = 16 * 1024
_CAPABILITY = "claude-launcher-pilot-v1"
_MANIFEST_TARGETS = {
    "x86_64-unknown-linux-musl": "x86_64-linux",
    "x86_64-apple-darwin": "x86_64-macos",
    "aarch64-apple-darwin": "aarch64-macos",
    "x86_64-pc-windows-msvc": "x86_64-windows",
}


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _supported_signed_domain(value: object, depth: int = 0) -> bool:
    if depth > 32:
        return False
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        return -(2**63) <= value <= 2**64 - 1
    if isinstance(value, str):
        return all(not 0xD800 <= ord(character) <= 0xDFFF for character in value)
    if isinstance(value, list):
        items = cast(list[object], value)
        return len(items) <= 4096 and all(_supported_signed_domain(item, depth + 1) for item in items)
    if isinstance(value, dict):
        items = cast(dict[object, object], value)
        return len(items) <= 4096 and all(
            isinstance(key, str)
            and _supported_signed_domain(key, depth + 1)
            and _supported_signed_domain(item, depth + 1)
            for key, item in items.items()
        )
    return False


def prepare(*, guard_home: Path, home: Path, workspace: Path | None, event: str) -> tuple[str, ...]:
    """Prepare one immutable digest-bound vector for a deliberately built wheel.

    Uses complete installed validation, never an environment override or loose
    binary. The private config is content-addressed; a preexisting different
    file is rejected. The atomic writer never follows a destination symlink.
    """
    _require(event in {"PreToolUse", "PostToolUse"}, "launcher_event_unsupported")
    guard_home, home = guard_home.resolve(strict=True), home.resolve(strict=True)
    workspace = workspace.resolve(strict=True) if workspace is not None else None
    _require(
        guard_home.is_dir() and home.is_dir() and (workspace is None or workspace.is_dir()), "launcher_context_invalid"
    )
    status = native_runtime._inspect_native_runtime_status(allow_attestation=False)
    identity, capabilities = status.identity, status.capabilities
    _require(status.mode == "auto" and status.available and status.compatible, "launcher_bundled_runtime_unavailable")
    _require(identity is not None and capabilities is not None, "launcher_runtime_identity_missing")
    assert identity is not None and capabilities is not None
    _require(
        identity.path == native_runtime._bundled_runtime_candidate().resolve(strict=True),
        "launcher_runtime_not_bundled",
    )
    _require(_CAPABILITY in capabilities.features, "launcher_pilot_capability_missing")
    manifest_path = identity.path.with_name("runtime-manifest.json")
    _require(manifest_path.stat().st_size <= _MAX_CONFIG, "launcher_manifest_too_large")
    # Bound the actual read too: a file that grows after stat must not allocate
    # an unbounded buffer during explicit preparation.
    with manifest_path.open("rb") as stream:
        manifest = stream.read(_MAX_CONFIG + 1)
    _require(len(manifest) <= _MAX_CONFIG, "launcher_manifest_too_large")
    parsed_manifest = native_runtime._decode_runtime_manifest(cast(object, json.loads(manifest)))
    _require(parsed_manifest is not None, "launcher_manifest_invalid")
    assert parsed_manifest is not None
    _require(
        parsed_manifest.runtime_sha256 == identity.sha256
        and parsed_manifest.runtime_size == identity.size
        and parsed_manifest.package_version == capabilities.runtime_version
        and parsed_manifest.source_sha == capabilities.build_sha
        and parsed_manifest.rule_digest == capabilities.rule_digest,
        "launcher_manifest_identity_changed",
    )
    _require(
        _MANIFEST_TARGETS.get(parsed_manifest.target) == capabilities.target,
        "launcher_manifest_target_unsupported",
    )
    state = load_authenticated_daemon_state(guard_home)
    _require(isinstance(state, dict) and _supported_signed_domain(state), "launcher_signed_state_profile_unsupported")
    assert isinstance(state, dict)
    _require(
        state.get("guard_home") == str(guard_home)
        and state.get("host") in {"127.0.0.1", "::1"}
        and state.get("compatibility_version") == 2
        and state.get("package_version") == capabilities.runtime_version,
        "launcher_daemon_identity_unsupported",
    )
    peer = {
        key: state.get(key)
        for key in ("compatibility_version", "package_version", "source_root", "runtime_fingerprint")
    }
    _require(
        all(
            isinstance(peer[key], str) and peer[key]
            for key in ("package_version", "source_root", "runtime_fingerprint")
        ),
        "launcher_daemon_identity_incomplete",
    )
    query = {"guard-home": str(guard_home), "home": str(home)}
    if workspace is not None:
        query["workspace"] = str(workspace)
    payload = {
        "schema": "hol-guard.claude-launcher-pilot.v1",
        "guard_home": str(guard_home),
        "home": str(home),
        "workspace": str(workspace) if workspace is not None else None,
        "query": urlencode(query),
        "runtime_path": str(identity.path),
        "runtime_size": identity.size,
        "runtime_sha256": identity.sha256,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "package_version": capabilities.runtime_version,
        "target": capabilities.target,
        "manifest_target": parsed_manifest.target,
        "build_sha": capabilities.build_sha,
        "rule_digest": capabilities.rule_digest,
        "daemon": peer,
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    _require(len(encoded) <= _MAX_CONFIG, "launcher_config_too_large")
    digest = hashlib.sha256(encoded).hexdigest()
    name = f"claude-launcher-pilot-{digest}.json"
    current = read_private_state(guard_home, name, _MAX_CONFIG)
    _require(current is None or current == encoded, "launcher_config_conflict")
    if current is None:
        write_private_state(guard_home, name, encoded, _MAX_CONFIG)
    _require(read_private_state(guard_home, name, _MAX_CONFIG) == encoded, "launcher_config_publication_failed")
    return (
        str(identity.path),
        "claude-launcher-v1",
        "--config",
        str(guard_home / "native-runtime" / name),
        "--config-sha256",
        digest,
        "--event",
        event,
    )


class _Arguments(argparse.Namespace):
    guard_home: Path = Path()
    home: Path = Path()
    workspace: Path | None = None
    event: str = ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--allow-dormant-pilot", action="store_true", required=True)
    _ = parser.add_argument("--guard-home", type=Path, required=True)
    _ = parser.add_argument("--home", type=Path, required=True)
    _ = parser.add_argument("--workspace", type=Path)
    _ = parser.add_argument("--event", choices=("PreToolUse", "PostToolUse"), required=True)
    args = parser.parse_args(namespace=_Arguments())
    argv = prepare(guard_home=args.guard_home, home=args.home, workspace=args.workspace, event=args.event)
    print(json.dumps({"schema": "hol-guard.claude-launcher-pilot-argv.v1", "argv": argv, "registered": False}))


if __name__ == "__main__":
    main()
