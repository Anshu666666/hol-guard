"""Fresh Windows discovery publication never repairs pre-existing authority."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as api
from codex_plugin_scanner.guard import native_policy_snapshot_windows_atomic as atomic
from codex_plugin_scanner.guard.daemon import discovery, discovery_windows, manager


def _identity(index=1):
    return SimpleNamespace(dwVolumeSerialNumber=7, nFileIndexHigh=0, nFileIndexLow=index)


@contextmanager
def _descriptor(_directory):
    yield object(), object(), object(), "owner"


@pytest.mark.parametrize("collision,wrong_committed_identity", [(False, False), (True, False), (False, True)])
def test_nonrepair_atomic_publication_preserves_no_clobber_and_verifies_commit(
    tmp_path, monkeypatch, collision, wrong_committed_identity
):
    events = []
    old_bytes = b"old authority"
    stored = {"state": old_bytes} if collision else {}
    new_bytes = b"complete new authority"

    def opened(path, **kwargs):
        if kwargs.get("create_new"):
            assert kwargs["descriptor"] is not None
            events.append("create-private")
            return "kernel", "temporary", _identity()
        assert stored.get("state") == new_bytes, "old destination must not be opened or repaired"
        assert path.name == "state"
        events.append("open-committed")
        return "kernel", "committed", _identity(2 if wrong_committed_identity else 1)

    def rename(_kernel, handle, parent, name, *, replace_if_exists):
        assert (handle, parent, name) == ("temporary", "parent", "state")
        assert replace_if_exists is False
        events.append("rename")
        if collision:
            raise FileExistsError(name)
        stored[name] = stored.pop("temporary")

    monkeypatch.setattr(api, "_windows_private_descriptor", _descriptor)
    monkeypatch.setattr(api, "_windows_open_handle", opened)
    monkeypatch.setattr(api, "_windows_verify_private_dacl", lambda handle, **_kwargs: events.append(("acl", handle)))
    monkeypatch.setattr(api, "_windows_close_handle", lambda _kernel, handle: events.append(("close", handle)))
    monkeypatch.setattr(api, "_windows_apply_private_dacl", lambda *_args: pytest.fail("existing ACL repair"))
    monkeypatch.setattr(
        atomic, "_windows_write_chunks_and_flush", lambda _kernel, handle, data: stored.update({handle: data})
    )
    monkeypatch.setattr(atomic, "_windows_rename_file_handle", rename)
    monkeypatch.setattr(
        atomic, "_windows_delete_file_handle", lambda _kernel, handle: events.append(("delete", handle))
    )

    def publish():
        atomic._windows_write_private_file_atomic(
            parent_path=tmp_path,
            parent_handle="parent",
            temporary_name="temporary",
            destination_name="state",
            payload=new_bytes,
            maximum_bytes=256,
            kind="discovery",
            replace_existing=False,
            repair_destination=False,
        )

    if collision:
        with pytest.raises(FileExistsError):
            publish()
        assert stored["state"] == old_bytes
        assert ("delete", "temporary") in events
        assert "open-committed" not in events
    else:
        if wrong_committed_identity:
            with pytest.raises(api.NativePolicySnapshotError, match="identity_failed"):
                publish()
        else:
            publish()
            assert ("acl", "committed") in events
        assert stored["state"] == new_bytes
        assert ("delete", "temporary") not in events
        assert ("close", "committed") in events
    assert events[-1] == ("close", "temporary")


def test_state_replacement_never_prepares_old_destination(tmp_path, monkeypatch):
    events = []
    monkeypatch.setattr(
        atomic, "_windows_prepare_replace_destination", lambda **_kwargs: pytest.fail("old target access")
    )
    monkeypatch.setattr(
        atomic,
        "_windows_rename_releasing_barrier",
        lambda **kwargs: events.append(("rename", kwargs["replace_existing"])),
    )
    fake = SimpleNamespace(
        _windows_verify_private_dacl=lambda handle, **_kwargs: events.append(("verify", handle)),
        _windows_open_handle=lambda *_args, **_kwargs: ("kernel", "committed", _identity()),
        _windows_close_handle=lambda _kernel, handle: events.append(("close", handle)),
    )
    atomic._windows_commit_private_file_handle(
        api=fake,
        kernel32="kernel",
        source_handle="source",
        source_information=_identity(),
        parent_path=tmp_path,
        parent_handle="parent",
        destination_name="state",
        descriptor=None,
        dacl=None,
        owner_sid="owner",
        kind="discovery",
        replace_existing=True,
        repair_destination=False,
    )
    assert events == [
        ("verify", "source"),
        ("rename", True),
        ("verify", "source"),
        ("verify", "committed"),
        ("close", "committed"),
    ]


@pytest.mark.parametrize("fault", [None, "rename-identity", "rename-failure", "restore-identity"])
def test_rename_parent_is_acquired_before_release_and_restoration_is_identity_checked(tmp_path, monkeypatch, fault):
    events = []
    handles = [("kernel", "ancestor"), ("kernel", "barrier")]
    renamed = [False]

    def opened(_path, **kwargs):
        name = "rename-parent" if kwargs.get("rename_parent") else "restored"
        events.append(("open", name))
        index = 2 if fault == ("rename-identity" if name == "rename-parent" else "restore-identity") else 1
        return "kernel", name, _identity(index)

    def rename(_kernel, _source, parent, _name, *, replace_if_exists):
        assert parent == "rename-parent" and replace_if_exists is False
        assert handles == [("kernel", "ancestor")]
        events.append(("rename", parent))
        if fault == "rename-failure":
            raise FileExistsError("key")

    fake = SimpleNamespace(
        _windows_open_handle=opened,
        _windows_close_handle=lambda _kernel, handle: events.append(("close", handle)),
    )
    monkeypatch.setattr(atomic, "_windows_handle_identity", lambda *_args: (7, 0, 1))
    monkeypatch.setattr(atomic, "_windows_rename_file_handle", rename)

    def run():
        atomic._windows_rename_releasing_barrier(
            api=fake,
            kernel32="kernel",
            source_handle="source",
            parent_path=tmp_path,
            parent_handle="barrier",
            destination_name="key",
            replace_existing=False,
            directory_handles=handles,
            rename_state=renamed,
        )

    if fault:
        with pytest.raises(FileExistsError if fault == "rename-failure" else api.NativePolicySnapshotError):
            run()
    else:
        run()
    assert events[0] == ("open", "rename-parent")
    assert events[-1] == ("close", "rename-parent")
    if fault == "rename-identity":
        assert handles[-1] == ("kernel", "barrier")
        assert ("close", "barrier") not in events
    else:
        assert events[1] == ("close", "barrier")
        assert handles[-1] == ("kernel", "restored")
    assert renamed[0] is (fault in {None, "restore-identity"})


@pytest.mark.parametrize("created,rejected", [(True, False), (False, False), (False, True)])
def test_producer_parent_binding_creates_private_at_birth_and_never_repairs(tmp_path, monkeypatch, created, rejected):
    target = tmp_path / "fresh"
    opened, closed, verified = [], [], []
    monkeypatch.setattr(api, "_windows_private_descriptor", _descriptor)

    def create(path, descriptor, _api):
        assert descriptor is not None
        return created and path == target

    def open_handle(path, **kwargs):
        assert kwargs.get("repair", False) is False
        assert kwargs["lock"] is True
        opened.append(path)
        return "kernel", path, _identity()

    def verify(handle, **_kwargs):
        verified.append(handle)
        if rejected:
            raise api.NativePolicySnapshotError("private-parent-rejected")

    monkeypatch.setattr(discovery_windows, "_windows_create_directory", create)
    monkeypatch.setattr(api, "_windows_open_handle", open_handle)
    monkeypatch.setattr(api, "_windows_verify_private_dacl", verify)
    monkeypatch.setattr(api, "_windows_apply_private_dacl", lambda *_args: pytest.fail("parent repair"))
    monkeypatch.setattr(api, "_windows_close_handle", lambda _kernel, handle: closed.append(handle))
    if rejected:
        with (
            pytest.raises(api.NativePolicySnapshotError, match="private-parent-rejected"),
            discovery_windows._directory_binding(target, verify_existing=True),
        ):
            pytest.fail("rejected parent admitted")
    else:
        with discovery_windows._directory_binding(target, verify_existing=True) as binding:
            assert binding.path == target and binding.handle == target
            assert not closed
    assert verified == [target]
    assert closed == list(reversed(opened))
    assert not target.exists(), "test must not create an ordinary directory"


def test_generic_existing_directory_is_neither_verified_nor_repaired(tmp_path, monkeypatch):
    monkeypatch.setattr(
        discovery_windows, "_directory_binding", lambda *_args, **_kwargs: pytest.fail("legacy binding")
    )
    discovery_windows.create_private_directory_if_missing(tmp_path)


@pytest.mark.parametrize("existing,race", [(True, False), (False, False), (False, True)])
def test_key_existing_branch_and_exclusive_creation_preserve_key_bytes(tmp_path, monkeypatch, existing, race):
    key_path = tmp_path / "daemon-discovery-key"
    old_key, new_key = "ab" * 32, "cd" * 32
    if existing:
        key_path.write_text(old_key, encoding="utf-8")
        key_path.chmod(0o600)
    windows_os = SimpleNamespace(name="nt", O_WRONLY=os.O_WRONLY, O_CREAT=os.O_CREAT, O_EXCL=os.O_EXCL)
    monkeypatch.setattr(discovery, "os", windows_os)
    monkeypatch.setattr(discovery.secrets, "token_hex", lambda _count: new_key)
    monkeypatch.setattr(discovery_windows, "create_private_directory_if_missing", lambda _path: None)
    calls = []

    def create(path, payload):
        calls.append(payload)
        assert payload == new_key.encode()
        path.write_bytes(old_key.encode() if race else payload)
        path.chmod(0o600)
        if race:
            raise FileExistsError(path)

    monkeypatch.setattr(discovery_windows, "create_discovery_key", create)
    assert discovery.ensure_daemon_discovery_key(tmp_path) == (old_key if existing or race else new_key)
    assert key_path.read_bytes() == (old_key if existing or race else new_key).encode()
    assert calls == ([] if existing else [new_key.encode()])


def test_state_seam_preserves_crlf_serialization_and_signature(tmp_path, monkeypatch):
    key = "17" * 32
    state = discovery.authenticate_daemon_state({"guard_home": "fixture", "port": 123}, discovery_key=key)
    text = json.dumps(state, indent=2)
    captured = []
    monkeypatch.setattr(manager, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        discovery_windows, "_write", lambda path, payload, **kwargs: captured.append((path, payload, kwargs))
    )
    path = tmp_path / "daemon-state.json"
    manager._write_private_atomic_text(path, text)
    assert captured == [(path, text.replace("\n", "\r\n").encode(), {"replace_existing": True, "maximum_bytes": 65536})]
    assert discovery.verify_daemon_state(json.loads(captured[0][1]), discovery_key=key)


@pytest.mark.skipif(os.name != "nt", reason="actual Windows private creation and rename semantics")
@pytest.mark.parametrize("creator", ["config", "store", "start-lock"])
def test_windows_fresh_start_then_discovery_publication_is_private_and_exclusive(tmp_path, creator):
    from codex_plugin_scanner.guard.config import load_guard_config
    from codex_plugin_scanner.guard.daemon.start_lock import guard_daemon_start_lock
    from codex_plugin_scanner.guard.store import GuardStore

    guard_home = tmp_path / "fresh" / "guard"
    if creator == "config":
        load_guard_config(guard_home)
    elif creator == "store":
        GuardStore(guard_home, prime_policy_integrity=False, allow_system_keyring=False)
    else:
        with guard_daemon_start_lock(guard_home):
            assert guard_home.is_dir()
    key = discovery.ensure_daemon_discovery_key(guard_home)
    manager.write_guard_daemon_state(guard_home, 12345, "fixture-token", write_auth_token=False)
    key_path, state_path = guard_home / "daemon-discovery-key", guard_home / "daemon-state.json"
    api._windows_verify_private_file(key_path)
    api._windows_verify_private_file(state_path)
    original_key = key_path.read_bytes()
    with pytest.raises(FileExistsError):
        discovery_windows.create_discovery_key(key_path, b"ee" * 32)
    assert key_path.read_bytes() == original_key == key.encode()
    manager.write_guard_daemon_state(guard_home, 12346, "fixture-token", write_auth_token=False)
    assert key_path.read_bytes() == original_key
    raw = state_path.read_bytes()
    assert b"\r\n" in raw
    state = json.loads(raw)
    assert state["port"] == 12346 and discovery.verify_daemon_state(state, discovery_key=key)
    assert not list(guard_home.glob("*.tmp"))
