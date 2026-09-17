"""Immutable transition history uses the existing private file contract."""

from __future__ import annotations

import math
import os
from pathlib import Path

import pytest

from scripts.ci import installed_transition_state as state


def _path(root: Path, phase: str) -> Path:
    return root / state.CHECKPOINT_DIRECTORY / f"{phase}.json"


def _raw(path: Path, content: bytes) -> None:
    state.files.atomic_exclusive(path, content)


def test_complete_five_phase_prefix_retains_every_private_checkpoint(tmp_path):
    original = {}
    for index, phase in enumerate(state.PHASE_NAMES):
        previous = state.read_previous(tmp_path, phase)
        assert previous == (None if index == 0 else {"phase": state.PHASE_NAMES[index - 1], "sequence": index - 1})
        state.write_checkpoint(tmp_path, phase, {"phase": phase, "sequence": index})
        original[phase] = _path(tmp_path, phase).read_bytes()
        assert all(_path(tmp_path, name).read_bytes() == data for name, data in original.items())
    for phase in state.PHASE_NAMES:
        with pytest.raises(state.TransitionStateError, match="history_invalid"):
            state.read_previous(tmp_path, phase)
    assert len(list((tmp_path / state.CHECKPOINT_DIRECTORY).iterdir())) == 5


@pytest.mark.parametrize("missing", ["first", "middle"])
def test_missing_prior_checkpoint_never_bootstraps_or_skips_a_phase(tmp_path, missing):
    phase = state.PHASE_NAMES[2]
    if missing == "middle":
        state.write_checkpoint(tmp_path, state.PHASE_NAMES[0], {"phase": state.PHASE_NAMES[0]})
    with pytest.raises(state.TransitionStateError, match="history_invalid"):
        state.write_checkpoint(tmp_path, phase, {"phase": phase})
    assert not _path(tmp_path, phase).exists()


@pytest.mark.parametrize("extra", ["candidate_restore.json", "CLEAN_BASELINE.json", ".pending", "future.json"])
def test_future_or_unknown_checkpoint_filenames_fail_closed(tmp_path, extra):
    first = state.PHASE_NAMES[0]
    state.write_checkpoint(tmp_path, first, {"phase": first})
    _raw(tmp_path / state.CHECKPOINT_DIRECTORY / extra, b"{}")
    with pytest.raises(state.TransitionStateError, match="history_invalid"):
        state.read_previous(tmp_path, state.PHASE_NAMES[1])


def test_every_prior_file_is_validated_not_only_the_latest(tmp_path):
    for phase in state.PHASE_NAMES[:2]:
        state.write_checkpoint(tmp_path, phase, {"phase": phase})
    # Corrupt an earlier file while leaving the immediate predecessor valid.
    _path(tmp_path, state.PHASE_NAMES[0]).unlink()
    _raw(_path(tmp_path, state.PHASE_NAMES[0]), b'{"phase":"candidate_restore"}')
    with pytest.raises(state.TransitionStateError, match="history_invalid"):
        state.read_previous(tmp_path, state.PHASE_NAMES[2])


def test_checkpoint_replay_and_generic_write_never_overwrite(tmp_path):
    phase = state.PHASE_NAMES[0]
    state.write_checkpoint(tmp_path, phase, {"phase": phase, "value": 1})
    path = _path(tmp_path, phase)
    original = path.read_bytes()
    with pytest.raises(state.TransitionStateError, match="history_invalid"):
        state.write_checkpoint(tmp_path, phase, {"phase": phase, "value": 2})
    with pytest.raises(state.TransitionStateError, match="write_failed"):
        state.write_private(path, {"value": 2})
    assert path.read_bytes() == original
    assert not list(path.parent.glob(".evidence-*.tmp"))


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b"null",
        b"",
        b'{"x":1,"x":2}',
        b'{"a":{"x":1,"x":2}}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":-Infinity}',
        b'{"x":1e400}',
        b'{"x":"\xff"}',
        '{"x":1}'.encode("utf-16"),
    ],
)
def test_invalid_json_never_becomes_private_state(tmp_path, raw):
    path = tmp_path / "invalid.json"
    _raw(path, raw)
    with pytest.raises(state.TransitionStateError, match="private_state_invalid"):
        state.read_private(path)


@pytest.mark.parametrize("value", [{"x": math.nan}, {"x": math.inf}, {"x": -math.inf}, {"x": {1, 2}}, []])
def test_invalid_writes_publish_nothing(tmp_path, value):
    path = tmp_path / "invalid.json"
    with pytest.raises(state.TransitionStateError, match="private_state_invalid"):
        state.write_private(path, value)
    assert not path.exists()


def test_exact_byte_limit_and_oversize_read_write(tmp_path):
    path = tmp_path / "exact.json"
    value = {"x": "a" * (state.STATE_LIMIT - len(b'{"x":""}'))}
    state.write_private(path, value)
    assert path.stat().st_size == state.STATE_LIMIT
    assert state.read_private(path) == value
    value["x"] += "a"
    with pytest.raises(state.TransitionStateError, match="private_state_limit"):
        state.write_private(tmp_path / "too-large.json", value)
    _raw(tmp_path / "oversize.json", b" " * (state.STATE_LIMIT + 1))
    with pytest.raises(state.TransitionStateError, match="private_state_unavailable"):
        state.read_private(tmp_path / "oversize.json")


@pytest.mark.parametrize("kind", ["symlink", "dangling", "hardlink", "directory"])
def test_private_read_rejects_aliased_or_nonregular_files(tmp_path, kind):
    source = tmp_path / "source.json"
    state.write_private(source, {"value": "retained"})
    target = tmp_path / "alias.json"
    try:
        if kind in {"symlink", "dangling"}:
            target.symlink_to(source if kind == "symlink" else tmp_path / "absent")
        elif kind == "hardlink":
            os.link(source, target)
        else:
            target.mkdir()
    except OSError:
        pytest.skip("link privilege unavailable")
    with pytest.raises(state.TransitionStateError, match="private_state_unavailable"):
        state.read_private(target)


def test_checkpoint_directory_symlink_is_not_empty_history(tmp_path):
    target = tmp_path / state.CHECKPOINT_DIRECTORY
    try:
        target.symlink_to(tmp_path / "missing", target_is_directory=True)
    except OSError:
        pytest.skip("symlink privilege unavailable")
    with pytest.raises(state.TransitionStateError, match="history_unavailable"):
        state.read_previous(tmp_path, state.PHASE_NAMES[0])


@pytest.mark.skipif(os.name == "nt", reason="Windows private ACL behavior is exercised by the shared backend")
def test_private_mode_required_and_creation_remains_private(tmp_path):
    path = tmp_path / "state.json"
    state.write_private(path, {"value": 1})
    assert path.stat().st_mode & 0o777 == 0o600
    path.chmod(0o644)
    with pytest.raises(state.TransitionStateError, match="private_state_unavailable"):
        state.read_private(path)


def test_read_and_write_use_shared_private_backend(monkeypatch, tmp_path):
    calls = []

    def read(path, maximum, *, private=False):
        calls.append(("read", path, maximum, private))
        return b'{"ok":true}'

    monkeypatch.setattr(state.files, "read_file", read)
    monkeypatch.setattr(state.files, "atomic_exclusive", lambda path, data: calls.append(("write", path, data)))
    path = tmp_path / "state.json"
    assert state.read_private(path) == {"ok": True}
    state.write_private(path, {"ok": True})
    assert calls == [("read", path, state.STATE_LIMIT, True), ("write", path, b'{"ok":true}')]


def test_inventory_change_during_read_rejects_history(monkeypatch, tmp_path):
    phase = state.PHASE_NAMES[0]
    state.write_checkpoint(tmp_path, phase, {"phase": phase})
    original = state.read_private

    def changed(path):
        value = original(path)
        # Inject an entry without opening a second Windows publication barrier
        # while the read holds the checkpoint directory against replacement.
        (path.parent / "future.json").write_bytes(b"{}")
        return value

    monkeypatch.setattr(state, "read_private", changed)
    with pytest.raises(state.TransitionStateError, match="history_invalid"):
        state.read_previous(tmp_path, state.PHASE_NAMES[1])


@pytest.mark.parametrize("phase", ["unknown", "../clean_baseline", "CLEAN_BASELINE"])
def test_unknown_phase_never_selects_a_path(tmp_path, phase):
    with pytest.raises(state.TransitionStateError, match="phase_invalid"):
        state.write_checkpoint(tmp_path, phase, {"phase": phase})
    assert not list(tmp_path.iterdir())


def test_phase_payload_mismatch_publishes_nothing(tmp_path):
    with pytest.raises(state.TransitionStateError, match="history_invalid"):
        state.write_checkpoint(tmp_path, state.PHASE_NAMES[0], {"phase": state.PHASE_NAMES[1]})
    assert not list(tmp_path.iterdir())


def test_errors_do_not_echo_private_json_or_paths(tmp_path):
    path = tmp_path / "PRIVATE_PATH.json"
    _raw(path, b'{"PRIVATE_PAYLOAD":')
    with pytest.raises(state.TransitionStateError) as captured:
        state.read_private(path)
    assert "PRIVATE" not in str(captured.value)
    assert str(tmp_path) not in str(captured.value)


def test_failed_publication_preserves_prior_checkpoint_and_retry_prefix(monkeypatch, tmp_path):
    first, second = state.PHASE_NAMES[:2]
    state.write_checkpoint(tmp_path, first, {"phase": first, "value": 1})
    original = state.files.atomic_exclusive

    def fail(_path, _content):
        raise OSError("PRIVATE_IO_DIAGNOSTIC")

    with monkeypatch.context() as patch:
        patch.setattr(state.files, "atomic_exclusive", fail)
        with pytest.raises(state.TransitionStateError, match="write_failed") as captured:
            state.write_checkpoint(tmp_path, second, {"phase": second})
        assert "PRIVATE" not in str(captured.value)
    assert state.files.atomic_exclusive is original
    assert not _path(tmp_path, second).exists()
    assert state.read_previous(tmp_path, second) == {"phase": first, "value": 1}
    state.write_checkpoint(tmp_path, second, {"phase": second})
