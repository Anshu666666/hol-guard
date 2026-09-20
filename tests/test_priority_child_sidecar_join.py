"""Exact modeled PID/argv/coordinate joins, plus original-file corruption checks."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from scripts.ci.priority_launcher_child.installation import canonical
from scripts.ci.priority_launcher_child.reader import coordinates, read_profiles
from tests.test_priority_child_reader import document


def fixture(tmp_path):
    registrations = [
        SimpleNamespace(harness=h, event=e, argv=("python", "-I", f"{h}-{e}"))
        for h in ("claude-code", "codex")
        for e in ("PreToolUse", "PostToolUse")
    ]
    rows = []
    stages = set()
    for index, coordinate in enumerate(coordinates()):
        pid = 101 + index
        launcher = next(
            item for item in registrations if (item.harness, item.event) == (coordinate["harness"], coordinate["event"])
        )
        body = document()
        body.update(pid=pid, parent_pid=98, argv_sha256=hashlib.sha256(canonical(list(launcher.argv))).hexdigest())
        bridge = "claude" if launcher.harness == "claude-code" else "codex"
        names = [
            f"codex_plugin_scanner.guard.adapters.{bridge}_daemon_hook_bridge:main",
            "codex_plugin_scanner.guard.adapters.claude_daemon_hook_transport:authenticated_claude_hook_response"
            if bridge == "claude"
            else "codex_plugin_scanner.guard.adapters.codex_daemon_hook_transport:_daemon_response_once",
            "codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth:_verify_challenge_response",
            "stdlib_http:HTTPConnection.request",
            "stdlib_http:HTTPConnection.getresponse",
            "stdlib_http:HTTPConnection.request",
            "stdlib_http:HTTPConnection.getresponse",
        ]
        body["records"] = [
            {
                "index": i,
                "stage": name,
                "thread": int(i == 1 and bridge == "claude"),
                "thread_kind": "worker" if i == 1 and bridge == "claude" else "main",
                "parent": None,
                "start_ns": 100 + i * 10,
                "end_ns": 105 + i * 10,
                "termination": "profile_return_or_unwind",
            }
            for i, name in enumerate(names)
        ]
        stages.update(names)
        raw = canonical(body) + b"\n"
        path = tmp_path / f"{pid}.json"
        path.write_bytes(raw)
        path.chmod(0o600)
        done = path.with_suffix(".json.done")
        done.write_bytes(
            canonical(
                {
                    "schema": "hol-guard.priority-child-export.v1",
                    "pid": pid,
                    "report_sha256": hashlib.sha256(raw).hexdigest(),
                    "finish_through_report_export_ns": 10,
                }
            )
            + b"\n"
        )
        done.chmod(0o600)
        rows.append({"coordinate": coordinate, "facts": {"children": [{"pid": pid}]}})
    registry = {"frames": [{"id": value} for value in stages], "modules": {}}
    return {"rows": rows}, registrations, registry


def test_all24_exact_bindings_are_admitted(tmp_path):
    parent, registrations, registry = fixture(tmp_path)
    result = read_profiles(tmp_path, parent, registrations, "a" * 64, registry, 98)
    assert result["observation_complete"] is True and len(result["rows"]) == 24


@pytest.mark.parametrize(
    "fault", ["pid", "argv", "footer", "extra_file", "missing_file", "stage_coverage", "private_field"]
)
def test_each_independent_child_binding_or_scope_failure_refused(tmp_path, fault):
    parent, registrations, registry = fixture(tmp_path)
    path = tmp_path / "101.json"
    if fault == "pid":
        parent["rows"][1]["facts"]["children"][0]["pid"] = 101
    elif fault == "argv":
        registrations[0].argv = ("python", "-I", "different")
    elif fault == "footer":
        path.with_suffix(".json.done").unlink()
    elif fault == "extra_file":
        (tmp_path / "unexpected").write_text("no admission")
    elif fault == "missing_file":
        path.unlink()
    else:
        body = json.loads(path.read_bytes())
        if fault == "private_field":
            body["private_payload"] = "PRIVATE_VALUE"
        else:
            body["records"] = []
        raw = canonical(body) + b"\n"
        path.write_bytes(raw)
        footer_path = path.with_suffix(".json.done")
        footer = json.loads(footer_path.read_bytes())
        footer["report_sha256"] = hashlib.sha256(raw).hexdigest()
        footer_path.write_bytes(canonical(footer))
    result = read_profiles(tmp_path, parent, registrations, "a" * 64, registry, 98)
    assert result["observation_complete"] is False
    assert "PRIVATE_VALUE" not in json.dumps(result)
