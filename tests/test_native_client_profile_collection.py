from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime, native_hook_edge
from codex_plugin_scanner.guard.native_route_receipt import record_native_hook_route
from scripts import native_slo_session
from scripts.ci import measure_native_client_profile as collector
from scripts.native_client_profile_records import PHASES
from scripts.native_client_profile_report import IDENTITY_HASHES, validate_report
from tests.native_client_profile_support import record

SHA = "a" * 40


def identity():
    return {
        **dict.fromkeys(IDENTITY_HASHES, "b" * 64),
        "build_sha": SHA,
        "target": "x86_64-linux",
        "artifact_scope": "explicit_diagnostic_feature_wheel",
        "production_selected": False,
    }


def inject_worker(monkeypatch, *, cleanup="already-stopped", missing_phase=None, total=70, wrong_route=False):
    profiles = []

    class Observer:
        def __init__(self, *_args):
            self.requests = []
            self.records = profiles
            self.spawns = 1
            self.failure = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def request_profile(self, _before):
            value = record(sequence=len(profiles) + 1)
            value["helper_request_nanoseconds"] = total
            if missing_phase:
                value["phases"][missing_phase] = {"calls": 0, "succeeded": 0, "nanoseconds": None}
            profiles.append(value)
            return {"helper": 1, "profile": value}

    class Session:
        def __init__(self, *_args, **_kwargs):
            self.root = self.guard_home = self.workspace = Path("/fixture")
            self.readiness_ms = 5
            self.last_stop_diagnostic = {"status": cleanup}
            worker = SimpleNamespace(
                test_oracle=None, prepare_workspace_policy=lambda *_args, **_kwargs: {"generation": 1}
            )
            self.daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=worker))

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    calls = []

    def review(**kwargs):
        calls.append(kwargs)
        record_native_hook_route("native_fail_safe" if wrong_route else "native_resident")
        malicious = "credential" in kwargs["payload"]["tool_response"][0]["text"]
        return {
            "authority": "rust",
            "result": {
                "decision": "deny" if malicious else "allow",
                "model_output_action": "block" if malicious else "allow_original",
                "reason_code": "output_secret_match" if malicious else "output_scan_allow",
            },
        }

    monkeypatch.setattr(collector, "installed_identity", lambda *_args: (Path("/runtime"), identity()))
    monkeypatch.setattr(collector, "ClientObserver", Observer)
    monkeypatch.setattr(native_slo_session, "AdapterSession", Session)
    monkeypatch.setattr(native_hook_edge, "review_raw_hook_native", review)
    return calls


def test_complete_collection_preserves_actual_routes_and_phase_values(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    calls = inject_worker(monkeypatch)
    value = collector.worker(wheel=Path("fixture.whl"), source_sha=SHA, private=tmp_path, count=1)
    assert value["collection_complete"] and len(calls) == 2
    assert validate_report(value, 2, SHA) == value
    assert value["profiles"]["credential_fixture"]["phases"]["response_read"]["duration_ms"]["count"] == 1
    rows = [json.loads(line) for line in (tmp_path / "attempts.jsonl").read_text().splitlines()]
    assert [row["status"] for row in rows] == ["offered", "completed", "offered", "completed"]
    assert all(
        row["route"] == "native_resident" and len(row["edge_sha256"]) == 64
        for row in rows
        if row["status"] == "completed"
    )


@pytest.mark.parametrize("missing", ["connect", "authentication", "request_write", "response_read", "total", "route"])
def test_required_span_or_route_omission_cannot_complete(tmp_path, monkeypatch, missing):
    tmp_path.chmod(0o700)
    inject_worker(
        monkeypatch,
        missing_phase=missing if missing in PHASES else None,
        total=None if missing == "total" else 70,
        wrong_route=missing == "route",
    )
    value = collector.worker(wheel=Path("fixture.whl"), source_sha=SHA, private=tmp_path, count=1)
    assert not value["collection_complete"] and value["failed"] == 1 and value["completed"] == 0
    assert validate_report(value, 2, SHA) == value
    assert json.loads((tmp_path / "attempts.jsonl").read_text().splitlines()[-1])["status"] == "failed"


@pytest.mark.parametrize("cleanup", ["failed", "contained_client_cleanup_failed", "not-run"])
def test_fixture_cleanup_failure_keeps_completed_requests_but_fails_collection(tmp_path, monkeypatch, cleanup):
    tmp_path.chmod(0o700)
    inject_worker(monkeypatch, cleanup=cleanup)
    value = collector.worker(wheel=Path("fixture.whl"), source_sha=SHA, private=tmp_path, count=1)
    assert not value["collection_complete"] and value["completed"] == 2 and value["failed"] == 0
    assert value["stage"] == "fixture_closed"
    assert validate_report(value, 2, SHA) == value


@pytest.mark.parametrize("change", ["extra", "boolean_count", "fake_complete", "unknown_phase", "source", "cleanup"])
def test_public_report_contract_does_not_sanitize_tampering_into_success(tmp_path, monkeypatch, change):
    tmp_path.chmod(0o700)
    inject_worker(monkeypatch)
    value = collector.worker(wheel=Path("fixture.whl"), source_sha=SHA, private=tmp_path, count=1)
    if change == "extra":
        value["message"] = "private"
    elif change == "boolean_count":
        value["completed"] = True
    elif change == "fake_complete":
        value["completed"] = 1
    elif change == "unknown_phase":
        value["profiles"]["benign"]["phases"]["unknown"] = {}
    elif change == "source":
        value["identity"]["build_sha"] = "c" * 40
    else:
        value["cleanup_status"] = "failed"
    with pytest.raises(ValueError):
        validate_report(value, 2, SHA)


def test_hard_exit_retains_plan_partial_journal_capture_and_unknown_actual_count(tmp_path, monkeypatch):
    private = tmp_path / "private_samples"

    def run(argv, **kwargs):
        assert "-I" in argv and kwargs["timeout_seconds"] == 180 and kwargs["output_limit"] == 256 * 1024
        assert json.loads((private / "plan.json").read_text())["planned"] == 2
        (private / "attempts.jsonl").write_bytes(b'{"status":"completed"}\n')
        return SimpleNamespace(
            returncode=-9,
            stdout="invalid partial",
            stderr="synthetic diagnostic",
            timed_out=True,
            containment_failed=False,
            output_limit_exceeded=False,
        )

    monkeypatch.setattr(codex_hook_launch_runtime, "run_isolated_hook_process", run)
    value = collector.run(
        wheel=Path("fixture.whl"), source_sha=SHA, private=private, output=tmp_path / "public", count=1
    )
    assert (
        not value["collection_complete"] and value["completed"] is None and value["worker_summary_available"] is False
    )
    assert (private / "attempts.jsonl").exists()
    capture = json.loads((private / "worker-capture.json").read_text())
    assert capture["stdout"]["length"] == len("invalid partial")
    assert "invalid partial" not in json.dumps(value)
    assert value["worker_timed_out"] is True


def test_cli_filesystem_failure_emits_only_finite_status(monkeypatch, capsys):
    monkeypatch.setattr(
        collector.sys,
        "argv",
        [
            "collector",
            "--wheel",
            "nonexistent-fixture.whl",
            "--source-sha",
            SHA,
            "--private",
            "unused-private",
            "--output",
            "unused-public",
        ],
    )
    assert collector.main() == 1
    encoded = capsys.readouterr().out
    report = json.loads(encoded)
    assert report["stage"] == "preparation" and report["completed"] is None
    assert "nonexistent-fixture" not in encoded and "unused-private" not in encoded
