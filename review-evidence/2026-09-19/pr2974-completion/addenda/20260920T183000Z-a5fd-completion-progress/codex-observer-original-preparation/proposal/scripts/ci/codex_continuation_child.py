"""Private fixture entry point; export trace only after original fixture cleanup."""

from __future__ import annotations

import json
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from codex_plugin_scanner.guard.daemon import codex_native_live_decision
from scripts.ci.codex_continuation_observer import NativeReturns, production_observer
from scripts.native_slo_daemon_entrypoint import main as original_main
from scripts.native_slo_daemon_fixture import _emit, _serve
from scripts.native_slo_launcher_review import LauncherReviewFixture


def main() -> int:
    destination = Path(os.environ["RSP136_CODEX_OBSERVER_FILE"])
    if not destination.is_absolute() or destination.exists() or not destination.parent.is_dir():
        raise ValueError("codex_observer_destination_unowned")
    observer = production_observer(codex_native_live_decision)
    native = NativeReturns()
    original_capture = LauncherReviewFixture._capture_completion
    attached: list[object] = []
    try:
        with ExitStack() as stack:

            def capture(fixture):
                if not attached:
                    worker = fixture.session.daemon._server.hook_worker
                    stack.enter_context(
                        patch.object(worker, "_review_raw_hook_native", native.wrap(worker._review_raw_hook_native))
                    )
                    attached.append(worker)
                return original_capture(fixture)

            stack.enter_context(patch.object(LauncherReviewFixture, "_capture_completion", capture))
            stack.enter_context(
                patch.object(codex_native_live_decision, "complete_native_codex_live_decision", observer)
            )
            return original_main(_serve, _emit)
    finally:
        # No trace serialization or filesystem write occurs inside the completion.
        # A failed export is an incomplete diagnostic, never a substitute outcome.
        try:
            with destination.open("x", encoding="utf-8") as stream:
                destination.chmod(0o600)
                json.dump(
                    {"guards": observer.report(), "native_returns": native.report()},
                    stream,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                stream.write("\n")
        except BaseException:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
