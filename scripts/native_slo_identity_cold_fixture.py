"""Explicit fixture-only launch option; normal fixture argv is unchanged."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

_active_observer: Any = None


def fixture_command(session: Any, script: str) -> tuple[str, ...]:
    argv = (
        sys.executable,
        "-u",
        script,
        "--serve",
        str(session.runtime),
        session.setup or "none",
        session.policy or "none",
    )
    return cold_fixture_arguments(argv, session.cold_identity)


def cold_fixture_arguments(argv: tuple[str, ...], config: Mapping[str, object] | None) -> tuple[str, ...]:
    if config is None:
        return argv
    encoded = json.dumps(dict(config), separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 4096:
        raise ValueError("qualification cold fixture options exceeded bound")
    return (*argv, "--identity-lifecycle", encoded)


def serve_fixture_entry(serve: Callable[..., int], argv: Sequence[str]) -> int:
    global _active_observer
    if len(argv) not in (5, 7) or argv[1] != "--serve":
        raise ValueError("private daemon fixture invocation required")
    runtime = Path(argv[2]).resolve(strict=True)
    if len(argv) == 5:
        return serve(runtime, argv[3], argv[4])
    if argv[5] != "--identity-lifecycle" or len(argv[6].encode("utf-8")) > 4096:
        raise ValueError("qualification cold fixture options invalid")
    from scripts.native_slo_identity_lifecycle import LifecycleObserver
    from scripts.native_slo_identity_lifecycle_record import binding

    config = json.loads(argv[6])
    if not isinstance(config, dict) or set(config) != {"path", "binding"} or not isinstance(config["path"], str):
        raise ValueError("qualification cold fixture options invalid")
    path = Path(config["path"])
    if not path.is_absolute() or argv[3] != "normal" or argv[4] != "none" or _active_observer is not None:
        raise ValueError("qualification cold fixture lifecycle invalid")
    with LifecycleObserver(path, binding(config["binding"])) as observer:
        _active_observer = observer
        try:
            with observer.preparation():
                return serve(runtime, argv[3], argv[4])
        finally:
            _active_observer = None


def lifecycle_ready() -> None:
    if _active_observer is not None:
        _active_observer.phase("ready")


def lifecycle_retiring() -> None:
    if _active_observer is not None:
        _active_observer.phase("cleanup")


def retain_startup_failure(session: Any, error: BaseException) -> None:
    if session.cold_identity is not None and isinstance(error, Exception):
        from scripts.native_slo_failure import failure_evidence

        session.cold_startup_failure = failure_evidence(error)
