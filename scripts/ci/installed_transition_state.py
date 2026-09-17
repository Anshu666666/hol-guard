"""Private, bounded, immutable checkpoints for stopped artifact transitions.

This records fixture history, not rollback-resistant production authority. The
caller still verifies installed artifacts and process retirement independently.
All file I/O uses the evidence backend, including its Windows private DACL and
retained-handle checks. No checkpoint is repaired or overwritten.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import NoReturn, cast

from scripts import native_slo_evidence_files as files

STATE_LIMIT = 64 * 1024
PHASE_NAMES = ("clean_baseline", "candidate_upgrade", "candidate_reinstall", "baseline_rollback", "candidate_restore")
CHECKPOINT_DIRECTORY = "transition-checkpoints"
_CHECKPOINT_NAMES = frozenset(f"{phase}.json" for phase in PHASE_NAMES)


class TransitionStateError(RuntimeError):
    """A fixed error that never includes private paths or checkpoint contents."""


def _invalid() -> NoReturn:
    raise TransitionStateError("qualification_transition_private_state_invalid") from None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _constant(_value: str) -> NoReturn:
    _invalid()


def _encode(value: object) -> bytes:
    if not isinstance(value, dict):
        _invalid()
    try:
        content = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode(
            "utf-8"
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _invalid()
    if len(content) > STATE_LIMIT:
        raise TransitionStateError("qualification_transition_private_state_limit")
    return content


def read_private(path: Path) -> dict[str, object]:
    """Read one private regular file without following links, at most 64 KiB."""
    try:
        content = files.read_file(path, STATE_LIMIT, private=True)
    except (OSError, ValueError):
        raise TransitionStateError("qualification_transition_private_state_unavailable") from None
    try:
        value = cast(
            object, json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_constant)
        )
        # Re-encoding also rejects overflowing exponents such as 1e400, which
        # json.loads otherwise accepts as infinity without parse_constant.
        _ = _encode(value)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _invalid()
    return cast(dict[str, object], value)


def write_private(path: Path, value: object) -> None:
    """Publish once, durably and privately; an existing destination is an error."""
    content = _encode(value)
    try:
        files.atomic_exclusive(path, content)
    except (OSError, ValueError):
        raise TransitionStateError("qualification_transition_private_state_write_failed") from None


def _phase_index(phase: str) -> int:
    if phase not in PHASE_NAMES:
        raise TransitionStateError("qualification_transition_phase_invalid")
    return PHASE_NAMES.index(phase)


def _inventory(parent: Path, descriptor: int | None) -> dict[str, tuple[int, ...]]:
    result: dict[str, tuple[int, ...]] = {}
    with os.scandir(descriptor if descriptor is not None else parent) as entries:
        for entry in entries:
            if len(result) >= len(PHASE_NAMES) or entry.name not in _CHECKPOINT_NAMES:
                raise TransitionStateError("qualification_transition_checkpoint_history_invalid")
            result[entry.name] = files.fingerprint(entry.stat(follow_symlinks=False))
    return result


def read_previous(root: Path, phase: str) -> dict[str, object] | None:
    """Require exactly the preceding phase prefix; reject gaps, replay and drift."""
    index = _phase_index(phase)
    checkpoint_root = root / CHECKPOINT_DIRECTORY
    try:
        # Retain the root while checking absence: a dangling link is not an
        # empty history, and a linked ancestor is never followed.
        with files.directory(root):
            try:
                _ = checkpoint_root.lstat()
            except FileNotFoundError:
                if index == 0:
                    return None
                raise TransitionStateError("qualification_transition_checkpoint_history_invalid") from None
            with files.directory(checkpoint_root) as (parent, descriptor):
                before = _inventory(parent, descriptor)
                expected = {f"{name}.json" for name in PHASE_NAMES[:index]}
                if set(before) != expected:
                    raise TransitionStateError("qualification_transition_checkpoint_history_invalid")
                previous = None
                for name in PHASE_NAMES[:index]:
                    previous = read_private(parent / f"{name}.json")
                    if previous.get("phase") != name:
                        raise TransitionStateError("qualification_transition_checkpoint_history_invalid")
                if _inventory(parent, descriptor) != before:
                    raise TransitionStateError("qualification_transition_checkpoint_history_changed")
                return previous
    except (OSError, ValueError):
        raise TransitionStateError("qualification_transition_checkpoint_history_unavailable") from None


def write_checkpoint(root: Path, phase: str, value: object) -> None:
    """Advance the fixed history by one exclusive publication, never overwrite."""
    _ = _phase_index(phase)
    if not isinstance(value, dict):
        raise TransitionStateError("qualification_transition_checkpoint_history_invalid")
    checkpoint = cast(dict[str, object], value)
    if checkpoint.get("phase") != phase:
        raise TransitionStateError("qualification_transition_checkpoint_history_invalid")
    _ = read_previous(root, phase)
    # Do not retain a second Windows directory barrier during atomic publish:
    # the backend owns the exact parent/source handle handoff for that operation.
    write_private(root / CHECKPOINT_DIRECTORY / f"{phase}.json", checkpoint)
