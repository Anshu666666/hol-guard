from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import native_slo_qualification_run as module
from scripts.native_slo_adapter import Observation
from scripts.native_slo_numeric_journal import recover_numeric_journal

PLAN = {
    "priority_per_run": 2,
    "other_per_run": 1,
    "cold_per_run": 2,
    "recovery_per_run": 2,
    "resource_samples_per_run": 1,
}


@pytest.fixture
def collection(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    class Fixture:
        entered = 0

        def __init__(self, *_args, **_kwargs):
            self.pid = 123
            self.observed = 0
            self.readiness_ms = 0.0
            self.startup_ms = 0.0

        def __enter__(self):
            type(self).entered += 1
            self.readiness_ms = float(type(self).entered)
            self.startup_ms = self.readiness_ms * 10
            return self

        def __exit__(self, *_args):
            pass

        def cpu_accounting_reader(self):
            return None

        def observe(self, harness, event, _size):
            self.observed += 1
            return Observation(harness, event, "1k", float(self.observed), "native_resident", True)

        def control(self, operation, *, count):
            assert operation == "native_samples"
            return {"benign_and_block_validated": True, "values": [10.0 + i for i in range(count)]}

    class Resources:
        samples = 100

        def __init__(self, *, pid, cpu_reader):
            assert pid == 123
            assert cpu_reader is None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def report(self, **_kwargs):
            return {}

    def launchers(_session, _plan, *, journal):
        raw = {"INSTALLED_LAUNCHER.claude-code.PreToolUse": [7.0, 8.0]}
        for name, values in raw.items():
            journal.record(name, values)
        return {}, raw

    def cold(_runtime, _session, count, *, journal):
        values = [20.0 + i for i in range(count)]
        journal.record("NATIVE_CLIENT.cold_oneshot", values)
        return values

    def recovery(_session, count, *, journal):
        values = [30.0] * count
        journal.record("DAEMON_INGRESS.recovery", values)
        return values

    monkeypatch.setattr(module, "_clear_proof_overrides", lambda: None)
    monkeypatch.setattr(
        module, "native_runtime_status", lambda: SimpleNamespace(identity=SimpleNamespace(path=tmp_path))
    )
    monkeypatch.setattr(module, "_runtime_summary", lambda _: {"build_sha": "a" * 40})
    monkeypatch.setattr(module, "route_matrix", lambda: (("claude-code", "PreToolUse"), ("pi", "PostToolUse")))
    monkeypatch.setattr(
        module,
        "run_contract_corpus",
        lambda *_args, **_kw: {
            "manifest_digest": "b" * 64,
            "oracle_digest": "c" * 64,
            "validated_digest": "d" * 64,
        },
    )
    monkeypatch.setattr(module, "run_registered_contract_corpus", lambda *_args, **_kw: {"validated_digest": "e" * 64})
    monkeypatch.setattr(module, "workload_matrix", lambda *_args: {"missing_reference_scopes": []})
    monkeypatch.setattr(module, "run_attribution_scenarios", lambda *_args, **_kw: {"python_phases": {}})
    monkeypatch.setattr(module, "run_additional_scenarios", lambda *_args, **_kw: {"python_phases": {}})
    monkeypatch.setattr(module, "hardware_summary", lambda: {"platform": "linux-x64"})
    monkeypatch.setattr(module, "DaemonFixture", Fixture)
    monkeypatch.setattr(module, "ResourceSampler", Resources)
    monkeypatch.setattr(module, "measure_priority_launchers", launchers)
    monkeypatch.setattr(module, "measure_load_profiles", lambda *_args: ({}, {}, {}))
    monkeypatch.setattr(module, "_run_cold", cold)
    monkeypatch.setattr(module, "_run_recovery", recovery)
    return tmp_path / "block.json"


def test_block_aggregate_is_exactly_conserved_by_private_journal(collection: Path) -> None:
    report = module.run_block(plan=PLAN, raw_file=collection)
    raw = json.loads(collection.read_bytes())
    recovered = recover_numeric_journal(collection.with_name("block-numeric.jsonl"))
    assert recovered["series"] == raw
    assert list(recovered["series"]) == list(raw)
    assert raw["DAEMON_INGRESS.claude-code.PreToolUse"] == [3.0, 4.0]
    assert raw["DAEMON_PROCESS.startup"] == [10.0, 20.0, 30.0, 40.0]
    assert raw["NATIVE_CLIENT.policy_readiness"] == [1.0, 2.0, 3.0, 4.0]
    assert raw["DAEMON_INGRESS.recovery"] == [30.0, 30.0]
    assert recovered["collection_complete"] is True
    assert report["qualification_complete"] is recovered["qualification_complete"] is False
    assert "series" not in report and "numeric_journal" not in report
    measurements = cast(dict[str, dict[str, object]], report["measurements"])
    assert {name: value["count"] for name, value in measurements.items()} == {
        name: len(values) for name, values in raw.items()
    }


@pytest.mark.parametrize("phase", ["launcher", "cold", "recovery"])
def test_later_interruption_preserves_earlier_numeric_series(
    collection: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
) -> None:
    names = {
        "launcher": ("measure_priority_launchers", "INSTALLED_LAUNCHER.claude-code.PreToolUse"),
        "cold": ("_run_cold", "NATIVE_CLIENT.cold_oneshot"),
        "recovery": ("_run_recovery", "DAEMON_INGRESS.recovery"),
    }
    function, series = names[phase]

    def interrupted(*_args, journal, **_kwargs):
        with journal.batch(series, 2) as batch:
            batch.record([99.0])
            raise TimeoutError("PRIVATE stopped worker stderr /home/customer")

    monkeypatch.setattr(module, function, interrupted)
    with pytest.raises(TimeoutError):
        module.run_block(plan=PLAN, raw_file=collection)
    assert not collection.exists()
    path = collection.with_name("block-numeric.jsonl")
    recovered = recover_numeric_journal(path)
    assert recovered["series"]["DAEMON_INGRESS.claude-code.PreToolUse"] == [3.0, 4.0]
    assert recovered["series"]["NATIVE_CLIENT.claude-code.PostToolUse"] == [10.0, 11.0]
    assert recovered["series"][series] == [99.0]
    assert recovered["batches"][-1]["status"] == "failed"
    assert recovered["collection_complete"] is False
    assert b"PRIVATE" not in path.read_bytes() and b"customer" not in path.read_bytes()


def test_native_batch_interruption_keeps_the_previous_hundred_observations(
    collection: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = module.DaemonFixture
    original = fixture.control
    calls = 0

    def control(self, operation, *, count):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise TimeoutError("child stopped")
        assert count == 100
        return original(self, operation, count=count)

    monkeypatch.setattr(fixture, "control", control)
    with pytest.raises(TimeoutError):
        module.run_block(plan={**PLAN, "priority_per_run": 101}, raw_file=collection)
    recovered = recover_numeric_journal(collection.with_name("block-numeric.jsonl"))
    assert len(recovered["series"]["NATIVE_CLIENT.claude-code.PostToolUse"]) == 100
    assert recovered["batches"][-1] == {
        "series": "NATIVE_CLIENT.claude-code.PostToolUse",
        "offered": 1,
        "observed": 0,
        "status": "failed",
    }
    assert recovered["collection_complete"] is False


def test_rejected_warm_observation_is_retained_without_qualification(
    collection: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = module.DaemonFixture
    original = fixture.observe

    def observe(self, harness, event, size):
        value = original(self, harness, event, size)
        if self.observed == 3:
            return Observation(harness, event, size, value.latency_ms, "native_fail_safe", False)
        return value

    monkeypatch.setattr(fixture, "observe", observe)
    with pytest.raises(RuntimeError, match="warm sample changed semantic route"):
        module.run_block(plan=PLAN, raw_file=collection)
    recovered = recover_numeric_journal(collection.with_name("block-numeric.jsonl"))
    assert recovered["series"]["DAEMON_INGRESS.claude-code.PreToolUse"] == [3.0]
    assert recovered["batches"][-1]["status"] == "failed"
    assert recovered["collection_complete"] is recovered["qualification_complete"] is False
    assert not collection.exists()


def test_attribution_precedes_gates_and_same_mapping_reaches_additional(collection, monkeypatch):
    from scripts import native_slo_qualification_scenarios as scenarios

    from .test_native_slo_qualification_scenarios import _install_collectors

    collectors, _ = _install_collectors(monkeypatch, collection)
    events, captured = [], []
    original_corpus, original_launchers = module.run_contract_corpus, module.measure_priority_launchers

    def attribution(*args, **kwargs):
        events.append("attribution")
        value = scenarios.run_attribution_scenarios(*args, **kwargs)
        captured.append(value)
        return value

    def corpus(*args, **kwargs):
        assert collectors == ["phases", "identity", "cold"]
        events.append("corpus")
        return original_corpus(*args, **kwargs)

    def launchers(*args, **kwargs):
        events.append("headline")
        return original_launchers(*args, **kwargs)

    def additional(*args, precollected_attribution, **kwargs):
        assert precollected_attribution is captured[0]
        scenarios._validate_attribution(precollected_attribution, receipt_profile="candidate")
        events.append("additional")
        return {"python_phases": precollected_attribution["python_phases"]}

    monkeypatch.setattr(module, "run_attribution_scenarios", attribution)
    monkeypatch.setattr(module, "run_contract_corpus", corpus)
    monkeypatch.setattr(module, "measure_priority_launchers", launchers)
    monkeypatch.setattr(module, "run_additional_scenarios", additional)
    report = module.run_block(plan=PLAN, raw_file=collection)
    assert events == ["attribution", "corpus", "headline", "additional"]
    assert collectors == ["phases", "identity", "cold"]
    # The unchanged final privacy projection copies containers after handoff.
    assert report["phases"] == captured[0]["python_phases"]


@pytest.mark.parametrize("failure_stage", ["corpus", "c16"])
def test_downstream_failure_preserves_attribution_and_partial_archive(collection, monkeypatch, failure_stage):
    import hashlib
    import traceback

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from scripts import native_slo_qualification_scenarios as scenarios
    from scripts.native_slo_evidence_archive import open_archive, seal
    from scripts.native_slo_evidence_files import read_samples

    from .test_native_slo_qualification_scenarios import _install_collectors

    calls, _ = _install_collectors(monkeypatch, collection, fail_phases=True)
    monkeypatch.setattr(module, "run_attribution_scenarios", scenarios.run_attribution_scenarios)
    original = RuntimeError("qualification c16 route mismatch")

    def fail(*_args, **kwargs):
        assert calls == ["phases", "identity", "cold"]
        if failure_stage == "c16":
            with kwargs["journal"].batch("INSTALLED_LAUNCHER.c16.claude-code.PreToolUse", 16) as batch:
                batch.record([7.0] * 16)
                raise original
        raise original

    monkeypatch.setattr(
        module, "run_contract_corpus" if failure_stage == "corpus" else "measure_priority_launchers", fail
    )
    monkeypatch.setattr(module, "run_additional_scenarios", lambda *_a, **_k: pytest.fail("past original failed gate"))
    with pytest.raises(RuntimeError) as caught:
        module.run_block(plan=PLAN, raw_file=collection)
    assert caught.value is original and traceback.extract_tb(original.__traceback__)[-1].name == "fail"
    assert calls == ["phases", "identity", "cold"] and not collection.exists()
    partial = dict(read_samples(collection.parent))
    expected = {
        "block-phase-cases.jsonl",
        "block-phase-summary.json",
        "block-identity-cases.jsonl",
        "block-identity-summary.json",
        "block-identity-cold-cases.jsonl",
        "block-identity-cold-observer.jsonl",
        "block-identity-cold-summary.json",
        "block-numeric.jsonl",
    }
    assert set(partial) == expected
    assert partial["block-phase-cases.jsonl"].endswith(b"{")
    assert json.loads(partial["block-phase-summary.json"])["passed"] is False
    for name in ("block-identity-summary.json", "block-identity-cold-summary.json"):
        assert json.loads(partial[name])["passed"] is True
    assert b"PRIVATE" not in partial["block-phase-summary.json"]
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    key_id = hashlib.sha256(
        key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()
    encoded = seal(list(partial.items()), public, key_id, context={"source_sha": "a" * 40})
    recovered, _ = open_archive(encoded, private)
    assert dict(recovered) == partial
    journal = recover_numeric_journal(collection.with_name("block-numeric.jsonl"))
    assert journal["collection_complete"] is False
