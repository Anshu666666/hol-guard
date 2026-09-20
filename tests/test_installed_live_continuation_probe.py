"""Local controls for the installed probe; installed admission is not inferred.

The action cases call the shipped probe function in an owned child against a
real daemon and Store, with the explicitly enrolled test signing/Python oracle.
CLI refusal cases use controlled admission ports and never claim native receipt
or ordinary-login qualification.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ci.native_runtime import probe_installed_live_continuation as probe
from tests.test_guard_codex_live_action_boundary import (
    LiveAction,
)

_CHILD = r"""
import json,sys
from pathlib import Path
from ci.native_runtime.probe_installed_live_continuation import run_waiting_action
p=json.loads(sys.stdin.read())
def emit(row):
    with Path(p['events']).open('a',encoding='utf-8') as f:
        f.write(json.dumps(row)+'\n')
record=run_waiting_action(guard_home=Path(p['guard_home']),home=Path(p['home']),workspace=Path(p['workspace']),emit=emit)
print(json.dumps(record),flush=True)
"""


@pytest.mark.parametrize("default_action", ["review", "allow"])
def test_real_daemon_without_pending_review_does_not_execute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, default_action: str
) -> None:
    # Bare pwd creates no Python-oracle artifact in either configuration. A
    # default action is not evidence of a genuinely pending native review.
    monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "0")
    action = LiveAction(tmp_path, "normal")
    events = tmp_path / "events.jsonl"
    config = action.store.guard_home / "config.toml"
    config.write_text(config.read_text().replace('default_action="review"', f'default_action="{default_action}"'))
    try:
        action.daemon.start()
        action.child = subprocess.Popen(
            [sys.executable, "-c", _CHILD],
            stdin=subprocess.PIPE,
            stdout=action.output,
            stderr=action.errors,
            start_new_session=os.name == "posix",
        )
        assert action.child.stdin is not None
        action.child.stdin.write(
            json.dumps(
                {
                    "guard_home": str(action.store.guard_home),
                    "home": str(action.home),
                    "workspace": str(action.workspace),
                    "events": str(events),
                }
            ).encode()
        )
        action.child.stdin.close()
        result = action.finish()
        assert result["completed"] is False and result["actionCount"] == 0
        assert result["actualPendingObserved"] is False and result["requestId"] is None
        assert not events.exists()
        assert action.store.list_approval_requests() == []
        assert action.store.list_guard_operations() == []
    finally:
        action.close()


def test_unprompted_allow_never_runs_probe_action(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "daemon-state.json").write_text("{}")

    def immediate_allow(**_kwargs: Any) -> int:
        print(json.dumps(probe.resume.allow_pretool_response()))
        return 0

    def unexpected_action(*_args: Any, **_kwargs: Any) -> None:
        pytest.fail("unprompted action executed")

    monkeypatch.setattr(probe.bridge, "main", immediate_allow)
    monkeypatch.setattr(probe.subprocess, "run", unexpected_action)
    rows: list[dict[str, object]] = []
    result = probe.run_waiting_action(guard_home=tmp_path, home=tmp_path, workspace=tmp_path, emit=rows.append)
    assert rows == [] and result["bridgeAllowed"] is True
    assert result["actualPendingObserved"] is False and result["completed"] is False and result["actionCount"] == 0


def test_cli_admission_failure_is_finite_and_creates_no_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "status.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "probe",
            "--guard-home",
            str(tmp_path),
            "--home",
            str(tmp_path),
            "--workspace",
            str(tmp_path),
            "--status",
            str(target),
        ],
    )

    def refuse() -> dict[str, object]:
        raise ValueError("CANARY_TOKEN_PRIVATE_EXCEPTION")

    monkeypatch.setattr(probe, "installed_context", refuse)
    assert probe.main() == 1
    output = capsys.readouterr()
    assert output.err == "" and "CANARY" not in output.out and not target.exists()
    assert json.loads(output.out) == {
        "schema": "guard.installed-live-continuation.v1",
        "phase": "failed",
        "completed": False,
        "actionCount": None,
        "failure": "installed_admission_failed",
    }


def test_cli_preserves_existing_status_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "status.json"
    target.write_text("owned-before")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "probe",
            "--guard-home",
            str(tmp_path),
            "--home",
            str(tmp_path),
            "--workspace",
            str(tmp_path),
            "--status",
            str(target),
        ],
    )
    monkeypatch.setattr(probe, "installed_context", lambda: {"installedRuntimeAvailable": True})
    assert probe.main() == 1
    assert target.read_text() == "owned-before"
    output = capsys.readouterr()
    assert output.err == "" and json.loads(output.out)["failure"] == "owned_status_unavailable"
