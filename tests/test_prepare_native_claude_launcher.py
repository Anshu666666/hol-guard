from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime
from scripts.ci import prepare_native_claude_launcher as pilot


@pytest.fixture
def installed(tmp_path, monkeypatch):
    package = tmp_path / "package" / "_native"
    package.mkdir(parents=True)
    runtime = package / ("hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime")
    runtime.write_bytes(b"fixture runtime identity; never executed")
    digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
    identity = native_runtime.NativeRuntimeIdentity(runtime, runtime.stat().st_size, runtime.stat().st_mtime_ns, digest)
    capabilities = native_runtime.NativeRuntimeCapabilities(
        1, "3.0.1", "a" * 64, "b" * 40, "x86_64-linux", ("claude-launcher-pilot-v1",)
    )
    status = native_runtime.NativeRuntimeStatus("auto", True, True, "native_available", identity, capabilities)
    manifest = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": "3.0.1",
        "target": "x86_64-unknown-linux-musl",
        "platform_tag": "fixture-platform",
        "source_sha": "b" * 40,
        "rule_digest": "a" * 64,
        "runtime_sha256": digest,
        "runtime_size": identity.size,
    }
    runtime.with_name("runtime-manifest.json").write_text(json.dumps(manifest))
    home, guard_home, workspace = tmp_path / "home", tmp_path / "guard", tmp_path / "workspace"
    for path in (home, guard_home, workspace):
        path.mkdir(mode=0o700)
    (home / "settings.json").write_text('{"foreign":true}')
    state = {
        "guard_home": str(guard_home.resolve()),
        "host": "127.0.0.1",
        "compatibility_version": 2,
        "package_version": "3.0.1",
        "source_root": str(package.parent.resolve()),
        "runtime_fingerprint": "c" * 64,
    }
    inspected: list[bool] = []

    def inspect(*, allow_attestation):
        inspected.append(allow_attestation)
        return status

    monkeypatch.setattr(native_runtime, "_inspect_native_runtime_status", inspect)
    monkeypatch.setattr(native_runtime, "_bundled_runtime_candidate", lambda: runtime)
    monkeypatch.setattr(pilot, "load_authenticated_daemon_state", lambda _: state)
    return home, guard_home, workspace, runtime, status, state, inspected


def test_preparation_is_explicit_private_identity_bound_and_leaves_registration(installed):
    home, guard_home, workspace, runtime, _, _, inspected = installed
    argv = pilot.prepare(guard_home=guard_home, home=home, workspace=workspace, event="PreToolUse")
    assert argv[:2] == (str(runtime), "claude-launcher-v1")
    assert argv[-2:] == ("--event", "PreToolUse")
    config_path = Path(argv[3])
    encoded = config_path.read_bytes()
    assert hashlib.sha256(encoded).hexdigest() == argv[5]
    config = json.loads(encoded)
    assert config["runtime_sha256"] == hashlib.sha256(runtime.read_bytes()).hexdigest()
    assert config["target"] == "x86_64-linux"
    assert config["manifest_target"] == "x86_64-unknown-linux-musl"
    assert config["workspace"] == str(workspace.resolve())
    assert config["home"] == str(home.resolve())
    assert config["daemon"]["runtime_fingerprint"] == "c" * 64
    assert inspected == [False]
    assert (home / "settings.json").read_text() == '{"foreign":true}'
    assert pilot.prepare(guard_home=guard_home, home=home, workspace=workspace, event="PreToolUse") == argv
    if os.name != "nt":
        assert config_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("mode", ["force", "shadow", "off"])
def test_preparation_rejects_non_auto_mode(installed, monkeypatch, mode):
    home, guard_home, workspace, _, status, _, _ = installed
    changed = dataclasses.replace(status, mode=mode)
    monkeypatch.setattr(native_runtime, "_inspect_native_runtime_status", lambda **_: changed)
    with pytest.raises(ValueError, match="launcher_bundled_runtime_unavailable"):
        pilot.prepare(guard_home=guard_home, home=home, workspace=workspace, event="PreToolUse")
    assert not list(guard_home.rglob("claude-launcher-pilot-*"))


def test_missing_pilot_capability_and_stale_manifest_reject(installed, monkeypatch):
    home, guard_home, workspace, runtime, status, _, _ = installed
    assert status.capabilities is not None
    absent = dataclasses.replace(status, capabilities=dataclasses.replace(status.capabilities, features=()))
    monkeypatch.setattr(native_runtime, "_inspect_native_runtime_status", lambda **_: absent)
    with pytest.raises(ValueError, match="launcher_pilot_capability_missing"):
        pilot.prepare(guard_home=guard_home, home=home, workspace=workspace, event="PreToolUse")
    monkeypatch.setattr(native_runtime, "_inspect_native_runtime_status", lambda **_: status)
    manifest = runtime.with_name("runtime-manifest.json")
    changed = json.loads(manifest.read_text())
    changed["runtime_sha256"] = "0" * 64
    manifest.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="launcher_manifest_identity_changed"):
        pilot.prepare(guard_home=guard_home, home=home, workspace=workspace, event="PreToolUse")


@pytest.mark.parametrize("extra", [1.5, {"nested": -0.0}, "\ud800", 2**64, -(2**63) - 1])
def test_signed_domain_outside_proven_profile_is_explicit(installed, extra):
    home, guard_home, workspace, _, _, state, _ = installed
    state["unknown_signed_field"] = extra
    with pytest.raises(ValueError, match="launcher_signed_state_profile_unsupported"):
        pilot.prepare(guard_home=guard_home, home=home, workspace=workspace, event="PreToolUse")


@pytest.mark.parametrize("event", ["pre_tool_use", "PermissionRequest", "SessionStart", "Stop"])
def test_canonical_scope_cannot_expand_from_event(installed, event):
    home, guard_home, workspace, *_ = installed
    with pytest.raises(ValueError, match="launcher_event_unsupported"):
        pilot.prepare(guard_home=guard_home, home=home, workspace=workspace, event=event)


@pytest.mark.parametrize(
    "manifest_target,logical_target",
    [
        ("x86_64-unknown-linux-musl", "x86_64-linux"),
        ("x86_64-apple-darwin", "x86_64-macos"),
        ("aarch64-apple-darwin", "aarch64-macos"),
        ("x86_64-pc-windows-msvc", "x86_64-windows"),
    ],
)
def test_shipping_target_domains_are_separately_bound(installed, monkeypatch, manifest_target, logical_target):
    home, guard_home, workspace, runtime, status, _, _ = installed
    assert status.capabilities is not None
    manifest = runtime.with_name("runtime-manifest.json")
    payload = json.loads(manifest.read_bytes())
    payload["target"] = manifest_target
    manifest.write_bytes(json.dumps(payload, separators=(",", ":")).encode())
    changed = dataclasses.replace(status, capabilities=dataclasses.replace(status.capabilities, target=logical_target))
    monkeypatch.setattr(native_runtime, "_inspect_native_runtime_status", lambda **_: changed)
    argv = pilot.prepare(guard_home=guard_home, home=home, workspace=workspace, event="PreToolUse")
    encoded = Path(argv[3]).read_bytes()
    config = json.loads(encoded)
    assert config["target"] == logical_target and config["manifest_target"] == manifest_target
    assert config["manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert hashlib.sha256(encoded).hexdigest() == argv[5]


@pytest.mark.parametrize(
    "manifest_target,logical_target",
    [
        ("x86_64-linux", "x86_64-linux"),
        ("fixture-target", "fixture-target"),
        ("x86_64-unknown-linux-gnu", "x86_64-linux"),
        ("x86_64-pc-windows-gnu", "x86_64-windows"),
        ("aarch64-apple-darwin", "x86_64-macos"),
        ("x86_64-apple-darwin", "x86_64-linux"),
        ("x86_64-unknown-linux-musl", "x86_64-unknown-linux-musl"),
    ],
)
def test_unknown_equal_or_crossed_target_domains_reject(installed, monkeypatch, manifest_target, logical_target):
    home, guard_home, workspace, runtime, status, _, _ = installed
    assert status.capabilities is not None
    manifest = runtime.with_name("runtime-manifest.json")
    payload = json.loads(manifest.read_bytes())
    payload["target"] = manifest_target
    manifest.write_text(json.dumps(payload))
    changed = dataclasses.replace(status, capabilities=dataclasses.replace(status.capabilities, target=logical_target))
    monkeypatch.setattr(native_runtime, "_inspect_native_runtime_status", lambda **_: changed)
    with pytest.raises(ValueError, match="launcher_manifest_target_unsupported"):
        pilot.prepare(guard_home=guard_home, home=home, workspace=workspace, event="PreToolUse")
    assert not list(guard_home.rglob("claude-launcher-pilot-*"))
