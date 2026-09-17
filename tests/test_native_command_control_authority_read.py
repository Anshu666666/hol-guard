"""The signed-marker shared-read guard has distinct success and refusal paths."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.native_command_control_authority import (
    AUTHORITY_FILE_NAME,
    AUTHORITY_MAX_BYTES,
    AUTHORITY_SCHEMA,
    authority_key_id,
    encode_authority,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    NativeCommandControlMutationRequiredError,
    hold_command_control_authority_lock,
    write_private_state,
)
from codex_plugin_scanner.guard.native_command_control_authority_store import read_committed_projection_authority
from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.store import GuardStore

_POLICY_KEY = b"p" * 32
_CONTROL_KEY = b"c" * 32
_EFFECTIVE_DIGEST = "e" * 64


@dataclass
class _KeyProvider:
    """Fixed test key backend; marker I/O, codec and verification stay real."""

    guard_home: Path

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes, str]:
        assert create
        return _POLICY_KEY, "test-key"

    def _authority_key(self, *, required: bool) -> bytes:
        assert not required
        return _CONTROL_KEY


def _marker() -> dict[str, object]:
    return {
        "schema": AUTHORITY_SCHEMA,
        "epoch": 2,
        "mutation_revision": 7,
        "authority_key_id": authority_key_id(_CONTROL_KEY),
        "phase": "committed",
        "effective_digest": _EFFECTIVE_DIGEST,
        "recovery": None,
    }


@pytest.mark.parametrize("state", ["missing", "closed", "digest-mismatch", "key-mismatch", "matching"])
def test_shared_projection_checks_each_authenticated_marker_state(tmp_path: Path, state: str) -> None:
    provider = _KeyProvider(tmp_path)
    marker = _marker()
    if state == "closed":
        marker.update(phase="closed", effective_digest=None)
    elif state == "digest-mismatch":
        marker["effective_digest"] = "d" * 64
    elif state == "key-mismatch":
        marker["authority_key_id"] = authority_key_id(b"x" * 32)
    if state != "missing":
        encoded = encode_authority(marker, derive_native_policy_verifier_key(_POLICY_KEY))
        write_private_state(tmp_path, AUTHORITY_FILE_NAME, encoded, AUTHORITY_MAX_BYTES)
    store = cast(GuardStore, cast(object, provider))
    with hold_command_control_authority_lock(tmp_path, shared=True):
        if state == "matching":
            assert read_committed_projection_authority(store, {"effective_digest": _EFFECTIVE_DIGEST}) == {
                "epoch": 2,
                "mutation_revision": 7,
                "authority_key_id": authority_key_id(_CONTROL_KEY),
                "recovery": None,
            }
        else:
            with pytest.raises(NativeCommandControlMutationRequiredError):
                _ = read_committed_projection_authority(store, {"effective_digest": _EFFECTIVE_DIGEST})


def test_shared_projection_never_trusts_matching_fields_with_wrong_signature(tmp_path: Path) -> None:
    encoded = encode_authority(_marker(), derive_native_policy_verifier_key(b"x" * 32))
    write_private_state(tmp_path, AUTHORITY_FILE_NAME, encoded, AUTHORITY_MAX_BYTES)
    store = cast(GuardStore, cast(object, _KeyProvider(tmp_path)))
    with (
        hold_command_control_authority_lock(tmp_path, shared=True),
        pytest.raises(NativePolicySnapshotError),
    ):
        _ = read_committed_projection_authority(store, {"effective_digest": _EFFECTIVE_DIGEST})
