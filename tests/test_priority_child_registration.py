"""Use real generated registrations; never launch the product commands."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from scripts.ci.priority_launcher_child import profile_runtime
from tests import test_native_slo_priority_launchers as registration_controls


@pytest.mark.parametrize("harness", ("claude-code", "codex"))
@pytest.mark.parametrize("event", ("PreToolUse", "PostToolUse"))
def test_actual_generated_pre_post_registrations_admit_one_original_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str, event: str
) -> None:
    # These existing fixtures call both real adapters and read back their actual
    # registrations. The owned Codex executable fixture is never launched.
    session = cast(Any, registration_controls.session).__wrapped__(tmp_path)
    registrations = cast(Any, registration_controls.registrations).__wrapped__(session, monkeypatch)
    assert len(registrations) == 4
    argv = [list(row.argv) for row in registrations]
    assert len({tuple(value) for value in argv}) == 2
    selected = next(row for row in registrations if (row.harness, row.event) == (harness, event))
    selected_argv = list(selected.argv)
    assert argv.count(selected_argv) == 2
    config = {
        "argv": argv,
        "observed_argv0": selected_argv[0],
        "executable": selected_argv[0],
        "parent_pid": os.getppid(),
        "python": list(sys.version_info[:3]),
    }
    path = tmp_path / "profile-config.json"
    body = profile_runtime.encoded(config)
    path.write_bytes(body)
    starts: list[str] = []
    admitted: list[dict[str, Any]] = []

    def profile(value: dict[str, Any]) -> Any:
        admitted.append(value)
        return SimpleNamespace(start=lambda: starts.append("start"), finish=lambda: None)

    with monkeypatch.context() as scoped:
        scoped.setattr(profile_runtime, "Profile", profile)
        scoped.setattr(profile_runtime.atexit, "register", lambda *_args: None)
        scoped.setattr(sys, "executable", selected_argv[0])
        scoped.setattr(sys, "orig_argv", selected_argv)
        scoped.setattr(sys, "flags", SimpleNamespace(isolated="-I" in selected_argv[1:2]))
        profile_runtime.activate(str(path), hashlib.sha256(body).hexdigest(), 1, ())
    assert starts == ["start"] and len(admitted) == 1
    assert admitted[0]["active_registered_argv"] == selected_argv
    assert admitted[0]["argv"] == argv
    assert len({row.registration_sha256 for row in registrations}) == 4
