"""The small installed entry must keep the existing semantic oracles intact."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts.ci import verify_installed_route_controls as entry


@pytest.mark.parametrize("scope", ["priority-controls", "priority-approval", "registered-aliases"])
def test_entry_forwards_admitted_native_runtime_once_and_retains_remaining_scope(tmp_path, monkeypatch, scope):
    distribution = object()
    native_runtime = tmp_path / "wheel-native-runtime"
    monkeypatch.setattr(
        entry,
        "admit_installed",
        lambda *_: ({"installed_package_sha256": "digest"}, distribution, SimpleNamespace(path=native_runtime)),
    )
    monkeypatch.setattr(entry, "assert_installed_import_origin", lambda value: None)
    monkeypatch.setattr(entry, "installed_package_digest", lambda value: "digest")
    called = []
    original_result = {
        "implemented_scope_passed": True,
        "remaining": ["unimplemented"],
        "qualification_complete": False,
        "validated_cases": 1,
    }

    def original(runtime, *, evidence_file):
        called.append((runtime, evidence_file))
        evidence_file.write_text('{"offered":true}\n')
        return original_result

    if scope == "registered-aliases":

        class Fixture:
            def __init__(self, runtime, *, setup):
                assert runtime is native_runtime and setup == "normal"

            def __enter__(self):
                return native_runtime

            def __exit__(self, *args):
                return False

        monkeypatch.setattr(entry, "DaemonFixture", Fixture)
        monkeypatch.setattr(entry, "run_registered_surface_corpus", original)
    else:
        target = (
            "run_registered_contract_corpus"
            if scope == "priority-controls"
            else "run_current_registered_approval_corpus"
        )
        monkeypatch.setattr(entry, target, original)
    evidence = tmp_path / "ledger.jsonl"
    report = entry.verify(scope, tmp_path / "candidate.whl", "a" * 40, evidence)
    assert called == [(native_runtime, evidence)]
    assert report["result"] is original_result and report["passed"] is True
    assert report["qualification_complete"] is False
    assert report["performance_qualified"] is report["native_approval_consume_qualified"] is False
    assert report["case_ledger_bytes"] == evidence.stat().st_size


def test_original_corpus_failure_does_not_discard_partial_offered_ledger(tmp_path, monkeypatch):
    monkeypatch.setattr(entry, "admit_installed", lambda *_: ({}, object(), SimpleNamespace(path=tmp_path / "native")))

    def original(runtime, *, evidence_file):
        evidence_file.write_text('{"offered":true}\n')
        raise RuntimeError("synthetic private material")

    monkeypatch.setattr(entry, "run_registered_contract_corpus", original)
    evidence = tmp_path / "ledger.jsonl"
    result = entry.verify("priority-controls", tmp_path / "candidate.whl", "a" * 40, evidence)
    assert result["passed"] is False
    assert result["failure"]["category"] == "RuntimeError"
    assert result["case_ledger_bytes"] == evidence.stat().st_size
    assert evidence.read_text() == '{"offered":true}\n'
