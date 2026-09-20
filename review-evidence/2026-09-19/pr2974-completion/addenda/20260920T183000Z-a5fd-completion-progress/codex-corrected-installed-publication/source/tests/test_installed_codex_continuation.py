"""Corrected installed entry controls; no installed/native workload is executed."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from scripts.ci import verify_installed_codex_continuation as entry
from scripts.native_slo_failure import failure_evidence


def test_single_original_codex_selection_preserves_hint_and_native_review(tmp_path, monkeypatch):
    from .test_native_slo_launcher_review import _case

    original = _case(tmp_path, "codex")
    claude = _case(tmp_path, "claude-code")
    runtime = tmp_path / "native-runtime"
    launcher = SimpleNamespace(harness="codex", event="PreToolUse")
    calls = []

    def control(operation, **kwargs):
        calls.append((operation, kwargs))
        return {"state": "waiting", "operation_id": "owned-operation"}

    session = SimpleNamespace(workspace=tmp_path, control=control)
    monkeypatch.setattr(entry, "install_priority_launchers", lambda current: [launcher])

    def cases(workspace, *, runtime):
        assert workspace is tmp_path and runtime.name == "native-runtime"
        return (claude, original)

    monkeypatch.setattr(entry, "build_cases", cases)
    offered = []

    def attempt(current, selected_launcher, case, **kwargs):
        assert current is session and selected_launcher is launcher
        offered.append(case)
        assert case.harness == "codex" and case.event == "PreToolUse"
        assert case.payload["tool_input"] == {"command": "cat .env"}
        assert case.payload["guard_remaining_ms"] == original.payload["guard_remaining_ms"] == 4000
        assert case.expected.decision == "implicit_allow"
        assert case.native_expected.fields == {
            "decision": "deny",
            "policy_action": "review",
            "minimum_action": "review",
            "reason_code": "native_sensitive_access_review",
        }
        assert kwargs["stage"] == "browser_wait_completion" and kwargs["operation_id"] == "owned-operation"
        kwargs["evidence"].write('{"status":"validated"}\n')

    monkeypatch.setattr(entry, "_attempt", attempt)
    report = {"offered": 0, "original_passed": False}
    ledger = tmp_path / "case.jsonl"
    entry._one_case(session, runtime, ledger, report)
    assert len(offered) == 1 and report == {"offered": 1, "original_passed": True}
    assert calls == [
        (
            "launcher_approval_begin",
            {
                "harness": "codex",
                "payload": dict(offered[0].payload),
                "resolution": "allow",
                "timeout_seconds": 8,
            },
        )
    ]
    assert original.payload["tool_input"]["command"].startswith("git diff ")
    assert ledger.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("failure", ["setup", "attempt", "cleanup", "attempt_cleanup", "alive", None])
def test_one_owned_fixture_preserves_first_failure_and_requires_containment(tmp_path, monkeypatch, failure):
    runtime = tmp_path / "native-runtime"
    first, cleanup = RuntimeError("original private failure"), ValueError("cleanup private failure")
    calls = []
    session = SimpleNamespace(_closed=False, process=SimpleNamespace(poll=lambda: None if failure == "alive" else 0))

    class Fixture:
        def __init__(self, value, *, setup):
            calls.append((value, setup))

        def __enter__(self):
            if failure == "setup":
                raise first
            return session

        def __exit__(self, *args):
            session._closed = True
            if failure in {"cleanup", "attempt_cleanup"}:
                raise cleanup
            return False

    def attempt(current, value, ledger, report):
        assert current is session and value is runtime
        report["offered"] = 1
        ledger.write_text('{"status":"offered"}\n')
        if failure in {"attempt", "attempt_cleanup"}:
            raise first
        report["original_passed"] = True

    monkeypatch.setattr(entry, "DaemonFixture", Fixture)
    monkeypatch.setattr(entry, "_one_case", attempt)
    report = entry.run_attempt(runtime, tmp_path / "ledger.jsonl")
    assert calls == [(runtime, "normal")]
    assert report["fixture_closed"] is (failure not in {"setup", "alive"})
    if failure in {"attempt", "attempt_cleanup"}:
        assert report["original_failure"] == failure_evidence(first) and report["original_passed"] is False
    if failure in {"cleanup", "attempt_cleanup"}:
        assert report["cleanup_failure"] == failure_evidence(cleanup)
    if failure == "setup":
        assert report["setup_failure"] == failure_evidence(first) and report["offered"] == 0


@pytest.mark.parametrize("fault", [None, "pending", "cleanup", "alive", "package"])
def test_installed_entry_requires_real_original_success_and_keeps_partial_ledger(tmp_path, monkeypatch, fault):
    runtime = tmp_path / "admitted-native-runtime"
    distribution = object()
    identity = {"installed_package_sha256": "same"}
    monkeypatch.setattr(entry, "admit_installed", lambda *_: (identity, distribution, SimpleNamespace(path=runtime)))
    monkeypatch.setattr(entry, "assert_installed_import_origin", lambda value: None)
    monkeypatch.setattr(entry, "installed_package_digest", lambda value: "changed" if fault == "package" else "same")
    original = {"offered": 1, "original_passed": fault != "pending", "fixture_closed": fault != "alive"}
    if fault == "pending":
        original["original_failure"] = {"category": "RuntimeError"}
    if fault == "cleanup":
        original["cleanup_failure"] = {"category": "ValueError"}
    calls = []
    body = b'{"status":"offered"}\n'

    def run(value, ledger):
        calls.append(value)
        ledger.write_bytes(body)
        return original

    monkeypatch.setattr(entry, "run_attempt", run)
    result = entry.verify(tmp_path / "wheel.whl", "a" * 40, tmp_path / "case.json")
    assert calls == [runtime] and result["original"] is original and result["identity"] is identity
    assert result["passed"] is (fault is None)
    assert result["case_ledger_sha256"] == hashlib.sha256(body).hexdigest()
    assert result["executed_line_observer"] is False
    assert result["qualification_complete"] is result["native_approval_consume_qualified"] is False
