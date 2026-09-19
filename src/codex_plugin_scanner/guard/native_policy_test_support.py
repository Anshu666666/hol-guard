"""Helpers for exercising the native resident with an authenticated policy."""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from types import FrameType

from .native_policy_snapshot import get_native_policy_snapshot_publisher
from .store import GuardStore

_MAX_OBSERVED_FRAMES = 32
_PUBLISHER_MODULE = "codex_plugin_scanner.guard.native_policy_snapshot_publisher"
_PHASES = {
    (_PUBLISHER_MODULE, "_run"): "publisher_loop",
    (_PUBLISHER_MODULE, "_publish_once"): "publication",
    (_PUBLISHER_MODULE, "_publication_context"): "context",
    ("codex_plugin_scanner.guard.native_policy_snapshot_publisher_context", "publication_context"): "context",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs",
        "_current_input_fingerprint",
    ): "input_fingerprint",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs",
        "_compiled_effective_policy",
    ): "configuration",
    ("codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport", "_publish_snapshot_v3"): "v3_transport",
    ("codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped", "publish_scoped"): "scoped_publication",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher_context",
        "compiled_v3_compatible_policy",
    ): "v3_input_capture",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs",
        "_resident_directory_fingerprint",
    ): "resident_directory",
    (
        "codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs",
        "_confirm_resident_fingerprint",
    ): "resident_confirmation",
}


def _observed_worker_phase(frame: FrameType | None) -> tuple[str, bool]:
    """Classify one worker's stack without returning stack or frame data."""

    for _ in range(_MAX_OBSERVED_FRAMES):
        if frame is None:
            return "unknown", False
        phase = _PHASES.get((frame.f_globals.get("__name__"), frame.f_code.co_name))
        if phase is not None:
            return phase, False
        frame = frame.f_back
    return "unknown", frame is not None


def _publication_failure_observation(publisher: object) -> dict[str, bool | str]:
    """Take one lock-free, non-atomic observation after a test wait fails."""

    result: dict[str, bool | str] = {
        "phase": "unknown",
        "started": False,
        "closed": False,
        "acked": False,
        "snapshot_present": False,
        "error_present": False,
        "worker_present": False,
        "worker_alive": False,
        "worker_frame_present": False,
        "frame_limit_reached": False,
        "observation_failed": False,
    }
    try:
        state = vars(publisher)
        result["started"] = state.get("_started") is True
        result["closed"] = state.get("_closed") is True
        result["acked"] = state.get("_acked") is True
        result["snapshot_present"] = state.get("_snapshot") is not None
        result["error_present"] = state.get("_last_error") is not None
        worker = state.get("_thread")
        result["worker_present"] = isinstance(worker, threading.Thread)
        if isinstance(worker, threading.Thread):
            result["worker_alive"] = worker.is_alive()
        if isinstance(worker, threading.Thread) and result["worker_alive"] and worker.ident is not None:
            # Only this publisher worker is inspected. Do not retain frame data,
            # locals, paths, thread identifiers or policy/error contents.
            frame = sys._current_frames().get(worker.ident)
            try:
                result["worker_frame_present"] = frame is not None
                result["phase"], result["frame_limit_reached"] = _observed_worker_phase(frame)
            finally:
                del frame
    except Exception:
        result["observation_failed"] = True
    return result


def _emit_publication_failure_observation(publisher: object) -> None:
    try:
        observation = _publication_failure_observation(publisher)
        print(
            "native_policy_readiness_observation=" + json.dumps(observation, sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
        )
    except Exception:
        # Diagnostic collection/output must not replace the original failure.
        pass


@contextmanager
def native_policy_snapshot(guard_home: Path) -> Iterator[Mapping[str, object]]:
    """Publish and yield the current ACKed snapshot for a test Guard home."""

    publisher = get_native_policy_snapshot_publisher(GuardStore(guard_home))
    publisher.start()
    try:
        ready_wait_seconds = 25.0 if sys.platform == "win32" else 3.0
        if not publisher.wait_until_ready(time.monotonic() + ready_wait_seconds):
            _emit_publication_failure_observation(publisher)
            raise AssertionError(f"native policy publisher was not ready: {publisher.last_error}")
        snapshot = publisher.current_snapshot()
        if snapshot is None:
            raise AssertionError("native policy publisher returned no ACKed snapshot")
        yield snapshot
    finally:
        publisher.close()
