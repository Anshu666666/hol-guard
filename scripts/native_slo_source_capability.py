"""Select source-read evidence from the exact installed runtime's capability."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.native_runtime import native_runtime_status

SOURCE_HANDLE_READ_FEATURE = "native-source-handle-read-v1"


def verified_runtime_features(runtime: Path) -> tuple[str, ...]:
    """Read features only after bundled identity, compatibility and path agree.

    The older post-tool-source-read-v1 feature was advertised by Windows
    artifacts with a deliberately unimplemented source opener. It is not proof
    of the handle-bound Windows implementation. Missing/invalid identity is an
    experiment failure, never a reason to downgrade the candidate's oracle.
    """
    status = native_runtime_status()
    if (
        status.mode != "auto"
        or not status.available
        or not status.compatible
        or status.reason != "native_ready"
        or status.identity is None
        or status.capabilities is None
    ):
        raise RuntimeError("source_capability_runtime_not_verified")
    if runtime.resolve() != status.identity.path.resolve():
        raise RuntimeError("source_capability_runtime_path_mismatch")
    return status.capabilities.features
