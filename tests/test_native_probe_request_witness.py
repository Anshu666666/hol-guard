from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import native_probe_request_witness as witness
from scripts.native_slo_contract import assert_privacy_safe


@pytest.mark.parametrize(
    ("error", "category"),
    [
        (TimeoutError("private URL and payload"), "timeout"),
        (urllib.error.URLError(TimeoutError("private address")), "timeout"),
        (urllib.error.URLError("timed out /private/path"), "request_exception"),
        (ValueError("private payload"), "request_exception"),
        (KeyboardInterrupt("private interruption"), "request_exception"),
    ],
    ids=["timeout", "wrapped-timeout", "unproven-text", "other", "interrupt"],
)
def test_original_exception_and_finite_failure_context(error, category, capsys):
    calls = []
    with (
        pytest.raises(type(error)) as caught,
        witness.installed_request_witness("cursor", "PostToolUse", validated_routes_before=8),
    ):
        calls.append("original")
        raise error
    assert caught.value is error
    assert calls == ["original"]
    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(captured.err.splitlines()) == 1 and len(captured.err) < 512
    report = json.loads(captured.err)
    assert report == {
        "schema": "hol-guard.installed-corpus-request-failure.v1",
        "harness": "cursor",
        "event": "PostToolUse",
        "validated_routes_before": 8,
        "failure": category,
        "transport_timeout_seconds": 5,
        "original_request_calls": 1,
        "request_returned": False,
        "retry_attempted": False,
        "native_route_proven": False,
        "cause_proven": False,
    }
    assert "private" not in captured.err
    assert assert_privacy_safe(report) == report


def test_observer_failure_does_not_replace_original(monkeypatch):
    original = TimeoutError("private")

    def fail(_report):
        raise KeyboardInterrupt("observer failed")

    monkeypatch.setattr(witness, "_emit", fail)
    with (
        pytest.raises(TimeoutError) as caught,
        witness.installed_request_witness("cline", "PreToolUse", validated_routes_before=2),
    ):
        raise original
    assert caught.value is original


def test_success_is_unchanged_and_emits_nothing(capsys):
    result = object()
    with witness.installed_request_witness("codex", "PreToolUse", validated_routes_before=4):
        returned = result
    assert returned is result
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("count", [-1, 33, True, "private", {}, None])
def test_projection_rejects_unknown_values_and_non_counts(count):
    report = witness.request_failure_report("private/path", {"payload": "private"}, count, TimeoutError("secret"))
    assert report["harness"] == report["event"] == "other"
    assert report["validated_routes_before"] is None
    assert "private" not in json.dumps(report) and "secret" not in json.dumps(report)


@pytest.mark.parametrize("successful_first", [False, True])
def test_real_corpus_loop_retains_validated_prefix_and_stops_at_exact_exception(
    tmp_path, monkeypatch, capsys, successful_first
):
    from ci.native_runtime import probe_native_default_auto as probe

    original = TimeoutError("private endpoint")
    calls = []
    receipts = []
    daemon = cast(probe.GuardDaemonServer, object())
    home, workspace = tmp_path / "private-home", tmp_path / "private-workspace"

    def request(actual_daemon, actual_home, actual_workspace, harness, event, payload):
        assert (actual_daemon, actual_home, actual_workspace) == (daemon, home, workspace)
        calls.append((harness, event, payload))
        if successful_first and len(calls) == 1:
            return {"reason_code": "fixed_allow"}
        raise original

    monkeypatch.setattr(probe, "_installed_hook_request", request)
    monkeypatch.setattr(probe, "is_allowed", lambda *_args: True)
    with pytest.raises(TimeoutError) as caught:
        probe._exercise_installed_routes(
            daemon,
            home,
            workspace,
            {
                "cline": {"pre_tool_use": "installed_canonical", "post_tool_use": "installed_observation_only"},
                "zcode": {"pre_tool_use": "installed_canonical", "post_tool_use": "unavailable"},
            },
            receipts,
            {},
        )
    assert caught.value is original
    assert len(calls) == 1 + successful_first
    assert len(receipts) == successful_first
    report = json.loads(capsys.readouterr().err)
    assert report["harness"] == "cline"
    assert report["event"] == ("PostToolUse" if successful_first else "PreToolUse")
    assert report["validated_routes_before"] == successful_first
    assert "private" not in json.dumps(report)


@pytest.mark.parametrize("harness", ["claude-code", "codex", "cline"])
def test_original_client_transport_timeout_and_exception_are_unchanged(harness, monkeypatch):
    from ci.native_runtime import probe_native_default_auto as probe

    client = probe._HOOK_CLIENT_MODULE
    original = TimeoutError("private")
    observed = []

    def fail(*args, **kwargs):
        observed.append(kwargs.get("timeout_seconds", kwargs.get("timeout")))
        raise original

    monkeypatch.setattr(client, "authenticated_claude_hook_response", fail)
    monkeypatch.setattr(client, "_daemon_response_once", fail)
    monkeypatch.setattr(client.urllib.request, "urlopen", fail)
    daemon = SimpleNamespace(port=1234, _server=SimpleNamespace(auth_token="private-token"))
    with (
        pytest.raises(TimeoutError) as caught,
        witness.installed_request_witness(harness, "PreToolUse", validated_routes_before=0),
    ):
        client.installed_hook_request(
            daemon, Path("private-home"), Path("private-workspace"), harness, "PreToolUse", {}
        )
    assert caught.value is original
    assert observed == [5]
