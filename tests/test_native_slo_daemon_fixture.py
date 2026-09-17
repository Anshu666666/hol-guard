from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import native_slo_daemon_fixture as fixture


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX fake process launch; production uses the tested Windows Job launcher"
)
def test_private_fixture_control_uses_separate_process_and_acknowledged_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready = {
        "state": "ready",
        "root": str(tmp_path),
        "workspace": str(tmp_path),
        "guard_home": str(tmp_path),
        "readiness_ms": 10,
        "port": 8123,
        "auth_token": "synthetic-private-token",
    }
    program = f"""
import json, sys
print({json.dumps(json.dumps(ready))}, flush=True)
for line in sys.stdin:
    op=json.loads(line)['op']
    if op=='snapshot':
        print(json.dumps({{'routes': {{'native_resident': 1}}}}), flush=True)
    elif op=='close':
        print(json.dumps({{'closed': True}}), flush=True)
        break
"""
    launched: list[subprocess.Popen[bytes]] = []

    def spawn(*_args: object, **_kwargs: object) -> tuple[object, None, None]:
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", program],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        launched.append(process)
        return process, None, None

    monkeypatch.setattr(fixture, "_spawn_hook_process", spawn)
    with fixture.DaemonFixture(tmp_path / "unused-runtime") as session:
        assert session.pid != os.getpid()
        assert session.startup_ms > 0
        assert session.control("snapshot") == {"routes": {"native_resident": 1}}
        assert session.daemon._server.auth_token == "synthetic-private-token"
    assert launched[0].poll() == 0
    session.close()
