"""Real coordinator/store controls with modeled edges; no native execution."""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import codex_native_live_decision as completion
from scripts.ci import codex_continuation_observer as observe
from scripts.ci import codex_continuation_schema as schema
from scripts.ci import verify_codex_continuation_guard as entry

from .test_native_codex_live_continuation import _complete, _fixture, _resolve, _Worker
from .test_native_review_policy_binding import _bind_receipt


@pytest.mark.parametrize("mutation", ["none", "request", "policy", "native_absent"])
def test_original_store_completion_records_executed_refusal_without_extra_calls(tmp_path, monkeypatch, mutation):
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    store, workspace, edge, hook, row = _fixture(tmp_path)
    _resolve(store, row)
    worker = _Worker(store, edge)
    if mutation == "request":
        edge["receipt"]["request_digest"] = "e" * 64
        _bind_receipt(edge)
    elif mutation == "policy":
        edge["receipt"]["policy_digest"] = "e" * 64
        worker.snapshot["policy_digest"] = "e" * 64
        _bind_receipt(edge)
    elif mutation == "native_absent":
        worker.edge = None
    observer = observe.production_observer(completion)
    assert observer.source_bound
    monkeypatch.setattr(completion, "complete_native_codex_live_decision", observer)
    previous = sys.gettrace()
    native = observe.NativeReturns()
    monkeypatch.setattr(worker, "_review_raw_hook_native", native.wrap(worker._review_raw_hook_native))
    result = _complete(store, workspace, edge, hook, row, worker=worker)
    assert sys.gettrace() is previous
    assert worker.calls == 1
    assert result["completed"] is (mutation == "none")
    report = observer.report()
    proof = {"guards": report, "native_returns": native.report()}
    assert schema.validated_export(proof) is proof
    assert report["complete"] and report["active_calls"] == 0 and len(report["calls"]) == 1
    captured = report["calls"][0]
    expected = {
        "none": "completed_forwarding",
        "request": "stored_request_digest_mismatch",
        "policy": "policy_binding_mismatch",
        "native_absent": "native_edge_absent",
    }[mutation]
    assert captured["return_group"] == expected
    assert captured["returned"] is True
    assert len(captured["events"]) <= observe.MAX_EVENTS
    if mutation == "request":
        assert captured["projection"]["request_matches_stored"] is False
        assert captured["projection"]["fresh_request_digest"] == "e" * 64
    assert str(tmp_path) not in json.dumps(report)
    assert "ollama push test" not in json.dumps(report)


@pytest.mark.parametrize("failure", [False, True])
def test_native_return_observer_forwards_once_and_freezes_only_scalar_identity(failure):
    native = observe.NativeReturns()
    edge = {"receipt": {"request_digest": "e" * 64, "policy_generation": 4}, "result": {"decision": "deny"}}
    error = RuntimeError("original native wrapper failure")
    calls = []

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        if failure:
            raise error
        return edge

    wrapped = native.wrap(original)
    payload = {"private": "not retained"}
    if failure:
        with pytest.raises(RuntimeError) as raised:
            wrapped(payload=payload, deadline=1.5, policy_snapshot={"generation": 4})
        assert raised.value is error
    else:
        assert wrapped(payload=payload, deadline=1.5, policy_snapshot={"generation": 4}) is edge
        edge["receipt"]["request_digest"] = "a" * 64
    assert len(calls) == 1 and calls[0][1]["payload"] is payload and calls[0][1]["deadline"] == 1.5
    proof = native.report()
    assert proof["active_calls"] == 0 and proof["complete"] is (not failure)
    if not failure:
        assert proof["rows"][0]["receipt_identity"]["fresh_request_digest"] == "e" * 64
    assert "not retained" not in json.dumps(proof)


@pytest.mark.parametrize("mutation", ["raw", "event", "missing", "duplicate", "count"])
def test_closed_export_refuses_unreviewed_or_incomplete_shapes(mutation):
    proof = {"guards": observe.CallObserver(lambda: None).report(), "native_returns": observe.NativeReturns().report()}
    if mutation == "raw":
        proof["private_path"] = "/private/canary"
    elif mutation == "event":
        proof["guards"]["calls"] = [
            {"events": [{"event": "arbitrary", "line": 1}], "complete": False, "returned": False, "projection": {}}
        ]
    elif mutation == "missing":
        proof["guards"]["complete"] = True
    elif mutation == "count":
        proof["guards"]["active_calls"] = True
    else:
        with pytest.raises(ValueError):
            json.loads('{"guards":{},"guards":{}}', object_pairs_hook=schema.pairs)
        return
    with pytest.raises(ValueError):
        schema.validated_export(proof)


@pytest.mark.parametrize(
    "mode", ["result", "original_exception", "capture_failure", "existing_trace", "source_changed"]
)
def test_same_original_result_or_exception_survives_observer_refusal_and_errors(monkeypatch, mode):
    value = object()
    failure = RuntimeError("original-private-error")
    offered = []

    def original(arg, *, deadline):
        offered.append((arg, deadline))
        if mode == "original_exception":
            raise failure
        return value

    observer = observe.CallObserver(original, source_bound=mode != "source_changed")
    if mode == "capture_failure":
        monkeypatch.setattr(observe, "projected_locals", lambda _: (_ for _ in ()).throw(ValueError("capture")))
    previous = sys.gettrace()

    def sentinel(*_):
        return None

    try:
        if mode == "existing_trace":
            sys.settrace(sentinel)
        if mode == "original_exception":
            with pytest.raises(RuntimeError) as raised:
                observer(value, deadline=123.5)
            assert raised.value is failure
        else:
            assert observer(value, deadline=123.5) is value
        assert sys.gettrace() is (sentinel if mode == "existing_trace" else previous)
    finally:
        sys.settrace(previous)
    assert offered == [(value, 123.5)]
    report = observer.report()
    assert report["active_calls"] == 0
    if mode in {"capture_failure", "existing_trace", "source_changed"}:
        assert report["complete"] is False
    assert "original-private-error" not in json.dumps(report)


def test_mutable_mapping_or_scalar_subclasses_are_not_observed():
    class Forbidden(dict):
        def get(self, *args):
            raise AssertionError("opaque mapping accessed")

    class Text(str):
        def __eq__(self, value):
            raise AssertionError("opaque equality invoked")

    report = observe.projected_locals(
        {
            "request": Forbidden(),
            "receipt": {"request_digest": Text("a" * 64)},
            "snapshot": Forbidden(),
            "result": {"decision": Text("allow")},
        }
    )
    assert report["fresh_request_digest"] is None and report["request_matches_stored"] is None
    assert report["native_decision"] is None


def test_event_and_call_limits_do_not_stop_original_work():
    calls = []

    def original():
        for index in range(observe.MAX_EVENTS * 2):
            calls.append(index)
        return calls

    observer = observe.CallObserver(original)
    for _ in range(observe.MAX_CALLS + 1):
        assert observer() is calls
    report = observer.report()
    assert report["overflow"] and not report["complete"]
    assert len(report["calls"]) == observe.MAX_CALLS
    assert all(len(row["events"]) <= observe.MAX_EVENTS for row in report["calls"])
    assert len(calls) == (observe.MAX_CALLS + 1) * observe.MAX_EVENTS * 2


def test_child_forwarding_preserves_original_spawn_arguments_and_identity(tmp_path, monkeypatch):
    from scripts import native_slo_daemon_fixture as fixture

    sentinel = object()
    received = []
    monkeypatch.setattr(fixture, "_spawn_hook_process", lambda *a, **kw: (received.append((a, kw)), sentinel)[1])
    original = fixture._spawn_hook_process
    args = (sys.executable, "-u", str(entry.Path(fixture.__file__).resolve()), "--serve", "runtime", "normal", "none")
    environment = {"unchanged": "value"}
    with entry.child_forwarding(tmp_path / "proof.json") as offered:
        assert fixture._spawn_hook_process(args, cwd=tmp_path, environment=environment, ownership=True) is sentinel
        with pytest.raises(ValueError, match="unexpected_fixture_spawn"):
            fixture._spawn_hook_process(args, cwd=tmp_path, environment=environment)
    assert fixture._spawn_hook_process is original and offered == [True]
    forwarded, kwargs = received[0]
    assert forwarded[0][:2] == args[:2] and forwarded[0][3:] == args[3:]
    assert kwargs["cwd"] is tmp_path and kwargs["ownership"] is True
    assert kwargs["environment"] == {**environment, "RSP136_CODEX_OBSERVER_FILE": str(tmp_path / "proof.json")}
    assert environment == {"unchanged": "value"}


def test_original_case_failure_remains_separate_from_cleanup_failure(tmp_path, monkeypatch):
    original = RuntimeError("original fixed fixture failure")
    cleanup = RuntimeError("cleanup fixed fixture failure")

    class Fixture:
        def __init__(self, *a, **kw):
            self._closed = False
            self.process = SimpleNamespace(poll=lambda: 0)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self._closed = True
            raise cleanup

    from contextlib import nullcontext

    monkeypatch.setattr(entry, "child_forwarding", lambda _: nullcontext([True]))
    monkeypatch.setattr(entry, "DaemonFixture", Fixture)
    monkeypatch.setattr(entry, "_one_case", lambda *_: (_ for _ in ()).throw(original))
    result = entry.run_attempt(tmp_path, tmp_path / "rows.jsonl", tmp_path / "trace.json")
    assert result["original_failure"]["diagnostic_digest"] != result["cleanup_failure"]["diagnostic_digest"]
    assert result["fixture_closed"] and result["original_passed"] is False
