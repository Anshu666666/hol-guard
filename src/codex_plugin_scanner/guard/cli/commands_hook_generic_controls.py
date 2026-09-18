"""Carry captured terminal controls across the generic command boundary."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_authority import AuthorityHealth
from ..runtime.extension_control_contract import ControlSurface
from ..runtime.extension_control_resolver import resolve_extension_controls
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot

if TYPE_CHECKING:
    from ..store import GuardStore


def generic_command_control_is_terminal(
    store: GuardStore,
    snapshot: ExtensionControlRuntimeSnapshot | None,
    *,
    event: str | None,
    command: str | None,
) -> bool:
    """Generic commands have no catalog observations, while Lockdown still applies."""
    if event != "PreToolUse" or not isinstance(command, str) or not command.strip():
        return False
    if snapshot is None:
        # Direct calls and post-claim revalidation must capture fresh authority;
        # caller-provided payload fields are never a source for this boundary.
        snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
            store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
        )
    if snapshot.health is AuthorityHealth.UNENROLLED:
        # No protected authority exists yet. Preserve the existing generic
        # configuration contract; an enrolled failure is handled below.
        return False
    resolution = resolve_extension_controls(
        snapshot.layers,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(),
        permission_ids=(),
        surface=ControlSurface.COMMAND_EVALUATION,
        authority_failure=snapshot.authority_failure,
    )
    return resolution.blocked
