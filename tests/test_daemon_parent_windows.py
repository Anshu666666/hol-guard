"""Daemon directory provisioning preserves existing child authority on Windows."""

from __future__ import annotations

import ctypes
import json
import os
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as api
from codex_plugin_scanner.guard import native_policy_snapshot_windows_atomic as atomic
from codex_plugin_scanner.guard import native_policy_snapshot_windows_io as windows_io
from codex_plugin_scanner.guard import native_policy_snapshot_windows_state as windows_state
from codex_plugin_scanner.guard.daemon import discovery, discovery_windows, manager

from .windows_failure_witness import WindowsParentWitness, _descriptor_components, _nt_descriptor_for_handle


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "created",
        "already-private",
        "owner",
        "acl-unavailable",
        "identity-missing",
        "exclusive-open",
        "exclusive-identity",
        "exclusive-owner",
        "apply",
        "verify",
        "restore-open",
        "restore-identity",
        "restore-acl",
    ],
)
def test_manager_parent_provisioning_retains_identity_ownership_and_exclusive_mutation(tmp_path, monkeypatch, fault):
    target = tmp_path / "guard"
    events, active = [], set()
    target_opens = []

    @contextmanager
    def descriptor(_directory):
        yield "advapi", "descriptor", "dacl", "owner"

    def fail():
        raise api.NativePolicySnapshotError("injected failure")

    def opened(path, **kwargs):
        if path == target:
            handle = ["barrier", "exclusive", "restored"][len(target_opens)]
            target_opens.append(handle)
            if handle == "exclusive":
                assert kwargs == {"directory": True, "repair": True, "exclusive_directory": True}
                assert "barrier" not in active and active, "ancestor barriers must remain held"
                if fault == "exclusive-open":
                    fail()
            if handle == "restored" and fault == "restore-open":
                fail()
        else:
            handle = str(path)
            assert kwargs.get("repair", False) is False
        events.append(("open", handle))
        active.add(handle)
        if handle == "barrier" and fault == "identity-missing":
            return "kernel", handle, object()
        changed = (handle, fault) in {("exclusive", "exclusive-identity"), ("restored", "restore-identity")}
        return (
            "kernel",
            handle,
            SimpleNamespace(dwVolumeSerialNumber=7, nFileIndexHigh=0, nFileIndexLow=2 if changed else 1),
        )

    def closed(_kernel, handle):
        events.append(("close", handle))
        active.remove(handle)

    def owner(handle, **_kwargs):
        events.append(("owner", handle))
        if (handle, fault) in {("barrier", "owner"), ("exclusive", "exclusive-owner")}:
            fail()

    def verify(handle, **_kwargs):
        events.append(("verify", handle))
        if handle == "barrier" and fault not in {"created", "already-private"}:
            reason = (
                "native_policy_windows_acl_verify_failed"
                if fault == "acl-unavailable"
                else "native_policy_windows_acl_not_private"
            )
            raise api.NativePolicySnapshotError(reason)
        if (handle, fault) in {("exclusive", "verify"), ("restored", "restore-acl")}:
            fail()

    def apply(handle, descriptor, *, api):
        assert (handle, descriptor) == ("exclusive", "descriptor")
        assert events[-1] == ("owner", "exclusive")
        events.append(("apply", handle))
        if fault == "apply":
            fail()

    monkeypatch.setattr(manager, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(api, "_windows_private_descriptor", descriptor)
    monkeypatch.setattr(api, "_windows_open_handle", opened)
    monkeypatch.setattr(api, "_windows_close_handle", closed)
    monkeypatch.setattr(api, "_windows_verify_private_owner", owner)
    monkeypatch.setattr(api, "_windows_verify_private_dacl", verify)
    monkeypatch.setattr(windows_state, "_windows_apply_parent_only_dacl", apply)
    monkeypatch.setattr(
        api,
        "_windows_apply_private_dacl",
        lambda *_args: pytest.fail("parent-only provisioning must not use the recursive setter"),
    )
    monkeypatch.setattr(
        windows_state, "_windows_create_directory", lambda path, *_args: fault == "created" and path == target
    )
    if fault in {None, "created", "already-private"}:
        manager._ensure_private_directory(target)
    else:
        with pytest.raises(api.NativePolicySnapshotError):
            manager._ensure_private_directory(target)
    assert not active, "every opened handle must close exactly once"
    assert events.count(("apply", "exclusive")) == int(
        fault in {None, "apply", "verify", "restore-open", "restore-identity", "restore-acl"}
    )
    if fault is None:
        assert target_opens == ["barrier", "exclusive", "restored"]
        assert events.index(("close", "exclusive")) < events.index(("open", "restored"))
    elif fault in {"created", "already-private", "owner", "acl-unavailable", "identity-missing"}:
        assert target_opens == ["barrier"]


@pytest.mark.parametrize("exclusive", [False, True])
def test_parent_only_open_uses_zero_sharing_without_changing_default(exclusive):
    configuration = windows_io._windows_open_configuration(
        api,
        directory=True,
        create_new=False,
        descriptor=None,
        repair=True,
        lock=True,
        rename_source=False,
        add_file=False,
        share_delete=False,
        rename_parent=False,
        exclusive_directory=exclusive,
    )
    assert configuration.share_mode == (0 if exclusive else 0x3)
    assert configuration.desired_access == api._WINDOWS_GENERIC_READ | api._WINDOWS_WRITE_DAC
    assert configuration.flags & api._WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    assert configuration.flags & api._WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
    assert configuration.disposition == api._WINDOWS_OPEN_EXISTING


@pytest.mark.parametrize(
    "options", [{"directory": False}, {"repair": False}, {"create_new": True}, {"rename_parent": True}]
)
def test_exclusive_directory_open_rejects_unrelated_operations(options):
    kwargs = dict(
        directory=True,
        create_new=False,
        descriptor=None,
        repair=True,
        lock=True,
        rename_source=False,
        add_file=False,
        share_delete=False,
        rename_parent=False,
        exclusive_directory=True,
    )
    kwargs.update(options)
    with pytest.raises(api.NativePolicySnapshotError, match="exclusive_directory_invalid"):
        windows_io._windows_open_configuration(api, **kwargs)


@pytest.mark.parametrize("status", [0, 1, 0xC0000022, -1073741790])
def test_parent_only_setter_targets_one_handle_and_only_dacl(monkeypatch, status):
    from ctypes import wintypes

    calls = []

    def setter(*args):
        calls.append(args)
        return status

    def library(name):
        assert name == "ntdll"
        return SimpleNamespace(NtSetSecurityObject=setter)

    monkeypatch.setattr(api, "_windows_dll", library)
    descriptor = ctypes.c_void_p(0x1234)
    if status == 0:
        windows_state._windows_apply_parent_only_dacl(17, descriptor, api=api)
    else:
        with pytest.raises(api.NativePolicySnapshotError, match="parent_acl_apply_failed"):
            windows_state._windows_apply_parent_only_dacl(17, descriptor, api=api)
    assert calls == [(17, api._WINDOWS_SECURITY_INFORMATION, descriptor)]
    assert setter.argtypes == [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
    assert setter.restype is ctypes.c_int32
    assert api._WINDOWS_SECURITY_INFORMATION == 0x80000004


@pytest.mark.parametrize("missing_library", [False, True])
def test_parent_only_setter_has_no_fallback_when_unavailable(monkeypatch, missing_library):
    def library(name):
        assert name == "ntdll"
        if missing_library:
            raise OSError("unavailable")
        return SimpleNamespace()

    monkeypatch.setattr(api, "_windows_dll", library)
    with pytest.raises(api.NativePolicySnapshotError, match="parent_acl_apply_unavailable"):
        windows_state._windows_apply_parent_only_dacl(17, object(), api=api)


def _windows_child_snapshot(path, *, directory=False):
    """Keep the GetSecurityInfo representation for the separate finite witness."""
    from ctypes import wintypes

    kernel, handle, information = api._windows_open_handle(path, directory=directory)
    descriptor = ctypes.c_void_p()
    advapi = api._windows_dll("advapi32")
    owner, group, dacl = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    get_security = advapi.GetSecurityInfo
    get_security.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, *([ctypes.POINTER(ctypes.c_void_p)] * 5)]
    get_security.restype = wintypes.DWORD
    free = kernel.LocalFree
    free.argtypes, free.restype = [ctypes.c_void_p], ctypes.c_void_p
    try:
        assert (
            get_security(
                handle,
                1,
                0x7,
                ctypes.byref(owner),
                ctypes.byref(group),
                ctypes.byref(dacl),
                None,
                ctypes.byref(descriptor),
            )
            == 0
        )
        assert descriptor and owner and group and dacl
        sid_length = advapi.GetLengthSid
        sid_length.argtypes, sid_length.restype = [ctypes.c_void_p], wintypes.DWORD
        get_control = advapi.GetSecurityDescriptorControl
        get_control.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)]
        get_control.restype = wintypes.BOOL
        control, revision = wintypes.WORD(), wintypes.DWORD()
        assert get_control(descriptor, ctypes.byref(control), ctypes.byref(revision))
        acl_size = ctypes.cast(dacl, ctypes.POINTER(wintypes.WORD))[1]
        security = (
            ctypes.string_at(owner, sid_length(owner)),
            ctypes.string_at(group, sid_length(group)),
            ctypes.string_at(dacl, acl_size),
            control.value,
            revision.value,
        )
        return atomic._windows_file_identity(information), security, None if directory else path.read_bytes()
    finally:
        if descriptor:
            free(descriptor)
        api._windows_close_handle(kernel, handle)


def _windows_native_child_snapshot(path, *, directory=False):
    """Compare complete native bytes, identity and payload without normalization.

    Actual tenth witnesses showed stable native descriptor bytes while the Get
    representation changed after parent provisioning. Keep Get as a diagnostic;
    the preservation oracle uses the documented self-relative native query.
    """
    kernel, handle, information = api._windows_open_handle(path, directory=directory)
    try:
        raw = _nt_descriptor_for_handle(handle)
        _descriptor_components(raw)  # Validate the format; retain every returned byte.
        identity = atomic._windows_file_identity(information)
        assert identity is not None
        return identity, raw, None if directory else path.read_bytes()
    finally:
        api._windows_close_handle(kernel, handle)


@pytest.mark.skipif(os.name != "nt", reason="actual Windows parent-only ACL propagation contract")
def test_windows_parent_provisioning_preserves_inherited_key_and_nested_child(tmp_path):
    parent = tmp_path / "legacy"
    parent.mkdir()
    key_path = parent / "daemon-discovery-key"
    key_path.write_bytes(b"19" * 32)
    nested = parent / "nested"
    nested.mkdir()
    child = nested / "child"
    child.write_bytes(b"unchanged child")
    objects = [(key_path, False), (nested, True), (child, False)]
    before = [_windows_native_child_snapshot(path, directory=directory) for path, directory in objects]
    get_before = [_windows_child_snapshot(path, directory=directory) for path, directory in objects]
    parent_identity = _windows_child_snapshot(parent, directory=True)[0]
    witness = WindowsParentWitness(objects, get_before, _windows_child_snapshot)
    with witness.failure_only():
        witness.capture("before_key_verification")
        with pytest.raises(api.NativePolicySnapshotError, match="acl_not_private"):
            api._windows_verify_private_file(key_path)
        witness.capture("after_key_verification")
        manager._ensure_private_directory(parent)
        witness.capture("after_manager")
        with discovery_windows._directory_binding(parent, verify_existing=True):
            pass
        witness.capture("after_discovery_binding")
        assert _windows_child_snapshot(parent, directory=True)[0] == parent_identity
        assert [_windows_native_child_snapshot(path, directory=directory) for path, directory in objects] == before
        assert discovery.ensure_daemon_discovery_key(parent) == "19" * 32
        assert [_windows_native_child_snapshot(path, directory=directory) for path, directory in objects] == before
        with pytest.raises(api.NativePolicySnapshotError, match="acl_not_private"):
            api._windows_verify_private_file(key_path)


@pytest.mark.skipif(os.name != "nt", reason="actual Windows existing-parent bootstrap publication")
def test_windows_ordinary_existing_parent_supports_fresh_discovery_state(tmp_path):
    parent = tmp_path / "ordinary"
    parent.mkdir()
    manager.clear_guard_daemon_state(parent)
    assert (parent / "daemon-state.json").read_bytes() == b"{}"
    key = discovery.ensure_daemon_discovery_key(parent)
    manager.write_guard_daemon_state(parent, 12345, "fixture-token", write_auth_token=False)
    api._windows_verify_private_file(parent / "daemon-discovery-key")
    api._windows_verify_private_file(parent / "daemon-state.json")
    raw = (parent / "daemon-state.json").read_bytes()
    assert b"\r\n" in raw
    assert discovery.verify_daemon_state(json.loads(raw), discovery_key=key)
