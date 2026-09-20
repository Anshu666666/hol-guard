"""The explanatory24 admission is distinct from the original88 reader."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.ci.priority_launcher_child.reader import join_subset
from tests.priority_child_fixtures import _reports


@pytest.fixture(autouse=True)
def private_import_root(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts/ci"))


def test_exact24_admission_preserves_original88_refusal():
    result = join_subset(*_reports())
    assert result["observation_complete"] is True and len(result["rows"]) == 24
    assert result["original_88_population_complete"] is False
    assert result["qualification_eligible"] is False


@pytest.mark.parametrize("changed", ["missing", "duplicate", "receipt", "mutation", "semantic", "incomplete_tail"])
def test_native_and_coordinate_joins_remain_required(changed):
    parent, daemon = _reports()
    if changed == "missing":
        for report in (parent, daemon):
            report["rows"].pop()
            report["started"] -= 1
            report["completed"] -= 1
    elif changed == "duplicate":
        daemon["rows"][1]["coordinate"] = daemon["rows"][0]["coordinate"]
    elif changed == "receipt":
        daemon["rows"][0]["facts"]["receipt_submissions"][0]["identity"]["request_id"] = "other"
    elif changed == "mutation":
        daemon["rows"][0]["facts"]["only_transport_hint_removed"] = False
    elif changed == "semantic":
        daemon["rows"][0]["facts"]["semantic_sha256"] = "0" * 64
    else:
        parent.update(original_success=False, tail_complete=False, observation_complete=False)
    assert join_subset(parent, daemon)["observation_complete"] is False


def test_first_original_failure_and_reader_failure_still_cleanup(monkeypatch, tmp_path):
    import importlib

    run = importlib.import_module("priority_launcher_child.run")
    calls = []
    original = RuntimeError("original failure")

    class Context:
        redirected = 1

        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            calls.append("context_exit")

    class Installed(Context):
        def __init__(self, *_args, **_kwargs):
            super().__init__()
            self.manifest = {"configuration_sha256": "a" * 64}
            self.created = {}
            self.cleanup_faults = []

        def close(self):
            calls.append("observer_close")

    class Fixture:
        runtime = Path("native")
        process = SimpleNamespace(poll=lambda: 0)
        _readers = [SimpleNamespace(is_alive=lambda: False)] * 2

        def __enter__(self):
            return SimpleNamespace(startup_ms=1.0, readiness_ms=1.0)

        def close(self):
            calls.append("fixture_close")

    def failed_subset(*_args):
        calls.append("subset_once")
        raise original

    def failed_reader(*_args, **_kwargs):
        raise ValueError("reader failure")

    monkeypatch.setattr(run, "FixtureRedirect", Context)
    monkeypatch.setattr(run, "ParentCapture", Context)
    monkeypatch.setattr(run, "Installation", Installed)
    monkeypatch.setattr(run, "current_site", lambda: tmp_path)
    monkeypatch.setattr(run, "preflight", lambda *_args: ("python", {"scope": "synthetic"}))
    monkeypatch.setattr(run, "build", lambda *_args: ({"modules": {}}, {}))
    monkeypatch.setattr(run, "measure_selected", failed_subset)
    monkeypatch.setattr(run, "read_profiles", failed_reader)
    monkeypatch.setattr(run, "read_report_document", lambda *_args: ({}, {}))
    monkeypatch.setattr(run, "join_subset", lambda *_args: {})
    report = run.execute_block(
        Fixture(),
        SimpleNamespace(install_priority_launchers=lambda *_args: []),
        object(),
        object(),
        source_root=tmp_path,
        child_script=tmp_path / "child.py",
        daemon_report_path=tmp_path / "daemon.json",
        package_root=tmp_path,
        wheel=tmp_path / "wheel",
    )
    assert calls.count("subset_once") == 1 and calls.index("fixture_close") < calls.index("observer_close")
    assert report["original_failure"]["kind"] == "runtime_error"
    assert report["child_evidence_failure"]["kind"] == "value_error"
    assert report["observer_cleanup_complete"] is True and report["private_sidecars_removed"] is True
    assert report["observation_complete"] is False
    assert "original failure" not in json.dumps(report)


@pytest.mark.parametrize("change", ["in_flight", "missing_child", "unknown_returncode", "containment_failed"])
def test_incomplete_process_retirement_refuses_observer_cleanup(change):
    import importlib

    run = importlib.import_module("priority_launcher_child.run")
    parent: dict[str, Any] = {
        "in_flight": 0,
        "rows": [
            {
                "facts": {
                    "children": [{"pid": 1}],
                    "process_calls": [{"exception": False, "returncode": 0, "containment_failed": False}],
                }
            }
        ],
    }
    assert run.children_reaped(parent) is True
    if change == "in_flight":
        parent["in_flight"] = 1
    elif change == "missing_child":
        parent["rows"][0]["facts"]["children"] = []
    elif change == "unknown_returncode":
        parent["rows"][0]["facts"]["process_calls"][0]["returncode"] = None
    else:
        parent["rows"][0]["facts"]["process_calls"][0]["containment_failed"] = True
    assert run.children_reaped(parent) is False
