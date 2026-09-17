from __future__ import annotations

import json
import sys

import pytest

from scripts import bench_claude_native_launcher_pilot as probe
from scripts.native_slo_contract import assert_privacy_safe


def test_installed_setup_failure_retains_json_and_never_counts_measurements(tmp_path, monkeypatch):
    target = tmp_path / "failure.json"
    monkeypatch.setattr(sys, "argv", ["probe", "--wheel", str(tmp_path / "candidate.whl"), "--json", str(target)])

    def fail(*_args, **kwargs):
        kwargs["report"]["phase"] = "daemon_setup"
        raise RuntimeError("daemon fixture failed native startup")

    monkeypatch.setattr(probe, "run_probe", fail)
    assert probe.main() == 1
    result = json.loads(target.read_text())
    assert result["phase"] == "daemon_setup"
    assert result["cells"] == [] and result["completed_blocks"] == 0
    assert result["scope_complete"] is False and result["qualification_complete"] is False
    assert result["failure"]["reason"] == "daemon_fixture_failed_native_startup"
    assert result["missing_scopes"] and "comparison" not in result


def test_incomplete_or_missing_cpu_cannot_supply_improvement_gate():
    one = {
        "event": "PreToolUse",
        "arm": "python",
        "latency_ms": [100.0],
        "combined_cpu_complete": True,
        "cpu_ms_per_attempt": 10.0,
    }
    assert probe._comparison([one], blocks=1)["PreToolUse"] == {"complete": False}
    candidate = {
        **one,
        "arm": "native",
        "latency_ms": [10.0],
        "combined_cpu_complete": False,
        "cpu_ms_per_attempt": None,
    }
    result = probe._comparison([one, candidate], blocks=1)["PreToolUse"]
    assert result["latency_p95_ratio"] == 0.1
    assert result["cpu_mean_ratio"] is None and result["point_improvement_gate"] is False
    assert result["activation_qualified"] is False


def test_persisted_diagnostics_keep_missing_scopes_and_measured_numbers():
    report = {
        "missing_scopes": ["reference_review_faults", "watch_availability_faults"],
        "cells": [
            {
                "arm": "native",
                "event": "PreToolUse",
                "latency_ms": [3.0, 4.0],
                "combined_cpu_complete": True,
                "cpu_ms_per_attempt": 2.0,
            }
        ],
        "qualification_complete": False,
    }
    assert json.loads(json.dumps(assert_privacy_safe(report))) == report


def test_native_route_mismatch_never_returns_a_successful_series(monkeypatch):
    monkeypatch.setattr(probe, "_route_snapshot", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(probe, "_children_cpu", lambda: 0.0)

    class Sampler:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def report(self, **_kwargs):
            pytest.fail("route refusal cannot be measured as native execution")

    monkeypatch.setattr(probe, "ResourceSampler", Sampler)
    monkeypatch.setattr(
        probe, "observe_priority_launcher", lambda *_args, **_kwargs: type("Observation", (), {"latency_ms": 1.0})()
    )
    with pytest.raises(RuntimeError, match="native_route_mismatch"):
        probe._series(type("Session", (), {"pid": 123})(), object(), 1)
