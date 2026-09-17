from __future__ import annotations

import copy
import json
import os
import time
from types import SimpleNamespace

import pytest

from scripts import mcp_rebaseline_resources as resources


def _report():
    return {
        "sample_minimum_met": True,
        "samples": 30,
        "unavailable_samples": 0,
        "metric_samples": dict.fromkeys(resources._REQUIRED, 30),
        "unavailable_metrics": {"handles": {"platform_unsupported": 30}},
        "baseline": {"processes": 2, "rss_bytes": 8192},
        "peak": {"processes": 2, "rss_bytes": 16384},
        "cpu_seconds": 0.02,
        "short_exited_descendants_cpu_complete": True,
    }


@pytest.fixture
def fixture(monkeypatch, request):
    pipes = resources.ResourcePipes.create()
    state = SimpleNamespace(report=_report(), events=[], identity=frozenset({(4242, 10.0), (4343, 11.0)}))
    monkeypatch.setattr(
        resources, "_psutil", lambda: SimpleNamespace(Process=lambda _pid: SimpleNamespace(create_time=lambda: 10.0))
    )
    monkeypatch.setattr(resources, "_membership", lambda _pid: state.identity)

    class Sampler:
        def __init__(self, **kwargs):
            assert kwargs == {"interval_seconds": 0.01, "pid": 4242}

        def __enter__(self):
            state.events.append("start_and_initial_sample")
            return self

        def __exit__(self, *_args):
            state.events.append("stop_and_final_sample")

        def report(self, *, attempted):
            assert attempted in (0, 99)
            value = copy.deepcopy(state.report)
            if not attempted:
                value["cpu_ms_per_attempt"] = None
            return value

    monkeypatch.setattr(resources, "ResourceSampler", Sampler)
    observer = resources.ParentResourceObserver(
        4242, pipes.parent_request_fd, pipes.parent_ack_fd, trace_count=getattr(request, "param", 1)
    )
    worker = resources.WorkerResourceHandshake(*pipes.worker_fds)
    observer.start()
    try:
        yield pipes, state, observer, worker
    finally:
        observer.abort()
        observer.finish()
        pipes.close()


def test_barriers_bracket_measurement_before_worker_can_teardown(fixture):
    _pipes, state, observer, worker = fixture
    worker.begin(0)
    assert state.events == ["start_and_initial_sample"]
    state.events.append("warm_calls")
    worker.end(0)
    assert state.events == ["start_and_initial_sample", "warm_calls", "stop_and_final_sample"]
    rows = observer.finish()
    assert observer.failure is None
    assert rows[0]["status"] == "complete"
    assert rows[0]["identity_verified"] is True
    assert "4242" not in json.dumps(rows) and "4343" not in json.dumps(rows)


@pytest.mark.parametrize("fixture", [2], indirect=True)
def test_fixed_trace_sequence_preserves_incomplete_earlier_window(fixture):
    _pipes, state, observer, worker = fixture
    worker.begin(0)
    state.report["unavailable_samples"] = 1
    worker.end(0)
    worker.begin(1)
    state.report["unavailable_samples"] = 0
    worker.end(1)
    rows = observer.finish()
    assert [row["trace_index"] for row in rows] == [0, 1]
    assert [row["status"] for row in rows] == ["incomplete", "complete"]
    assert rows[0]["resources"]["unavailable_samples"] == 1


def test_observer_owns_duplicates_until_after_final_ack(fixture):
    pipes, _state, observer, worker = fixture
    worker.begin(0)
    pipes._close("parent_request_fd", "parent_ack_fd")
    worker.end(0)
    assert observer.finish()[0]["status"] == "complete"
    for descriptor in (observer.request_fd, observer.ack_fd):
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_report_failure_is_retained_instead_of_losing_window(fixture, monkeypatch):
    _pipes, _state, observer, worker = fixture

    def failed_report(*_args, **_kwargs):
        raise ValueError("private exception detail must not escape")

    monkeypatch.setattr(resources.ResourceSampler, "report", failed_report)
    worker.begin(0)
    worker.end(0)
    row = observer.finish()[0]
    assert row["status"] == "incomplete"
    assert row["failure"] == "observer_report_failed"
    assert row["resources"] is None
    assert "private exception" not in json.dumps(row)


@pytest.mark.parametrize("fault", ["too_few", "missing", "denied", "extra_process", "cpu_incomplete"])
def test_real_incomplete_readings_are_retained_and_never_repaired(fixture, fault):
    _pipes, state, observer, worker = fixture
    if fault == "too_few":
        state.report["metric_samples"]["private_bytes"] = 29
    elif fault == "missing":
        state.report["unavailable_samples"] = 1
    elif fault == "denied":
        state.report["unavailable_metrics"]["descriptors"] = {"permission_denied": 1}
    elif fault == "extra_process":
        state.report["peak"]["processes"] = 3
    else:
        state.report["short_exited_descendants_cpu_complete"] = False
    worker.begin(0)
    worker.end(0)
    row = observer.finish()[0]
    assert row["status"] == "incomplete"
    assert row["failure"] == "resource_samples_incomplete"
    assert row["resources"] == {**state.report, "scope": "mcp_proxy_worker_and_descendants"}
    assert state.events == ["start_and_initial_sample", "stop_and_final_sample"]


def test_explicit_workload_failure_stops_sampling_and_keeps_observations(fixture):
    _pipes, state, observer, worker = fixture
    worker.begin(0)
    worker.end(0, failed=True)
    row = observer.finish()[0]
    assert row["failure"] == "worker_trace_failed"
    assert row["resources"]["samples"] == 30
    assert row["warm_attempts"] is None and row["expected_warm_attempts"] == 99
    assert row["resources"]["cpu_ms_per_attempt"] is None
    assert state.events[-1] == "stop_and_final_sample"


def test_changed_child_identity_cannot_pass(fixture):
    _pipes, state, observer, worker = fixture
    worker.begin(0)
    state.identity = frozenset({(4242, 10.0), (4343, 99.0)})
    worker.end(0)
    row = observer.finish()[0]
    assert row["failure"] == "process_identity_changed"
    assert row["identity_verified"] is False
    assert row["resources"]["samples"] == 30


def test_root_pid_reuse_after_begin_retains_final_report_and_rejects_ack(fixture):
    _pipes, state, observer, worker = fixture
    worker.begin(0)
    state.identity = frozenset({(4242, 99.0), (4343, 11.0)})
    with pytest.raises(resources.ResourceHandshakeError, match="ack_invalid"):
        worker.end(0)
    row = observer.finish()[0]
    assert row["failure"] == "root_identity_changed"
    assert row["resources"]["samples"] == 30
    assert state.events.count("stop_and_final_sample") == 1


def test_abort_preserves_active_window(fixture):
    _pipes, state, observer, worker = fixture
    worker.begin(0)
    observer.abort()
    row = observer.finish()[0]
    assert row["status"] == "incomplete"
    assert row["failure"] == "observer_aborted"
    assert row["resources"]["samples"] == 30
    assert state.events[-1] == "stop_and_final_sample"


@pytest.mark.parametrize("frame", [b"1:begin\n", b"0:end\n", b"0:begin\n0:end\n", b"x" * 1025])
def test_invalid_or_oversized_frames_do_not_start_a_window(fixture, frame):
    pipes, state, observer, _worker = fixture
    os.write(pipes.worker_request_fd, frame)
    rows = observer.finish()
    assert observer.failure is not None
    assert rows[0]["status"] == "incomplete"
    assert rows[0]["resources"] is None
    assert state.events == []


def test_worker_refuses_duplicate_and_out_of_order_begin(fixture):
    _pipes, _state, _observer, worker = fixture
    with pytest.raises(resources.ResourceHandshakeError, match="worker_sequence_invalid"):
        worker.begin(1)
    worker.begin(0)
    with pytest.raises(resources.ResourceHandshakeError, match="worker_sequence_invalid"):
        worker.begin(0)
    worker.end(0)


def test_ack_timeout_poisoning_is_bounded(monkeypatch):
    pipes = resources.ResourcePipes.create()
    monkeypatch.setattr(resources, "_ACK_SECONDS", 0.01)
    worker = resources.WorkerResourceHandshake(*pipes.worker_fds)
    try:
        with pytest.raises(resources.ResourceHandshakeError, match="protocol_deadline"):
            worker.begin(0)
        with pytest.raises(resources.ResourceHandshakeError, match="worker_protocol_poisoned"):
            worker.begin(0)
    finally:
        pipes.close()


def test_pipe_eof_is_explicit(fixture):
    pipes, _state, observer, _worker = fixture
    pipes.close_worker_ends()
    row = observer.finish()[0]
    assert row["failure"] == "protocol_eof"
    assert row["resources"] is None


def test_pipe_cleanup_is_idempotent():
    pipes = resources.ResourcePipes.create()
    descriptors = (*pipes.worker_fds, pipes.parent_request_fd, pipes.parent_ack_fd)
    pipes.close_worker_ends()
    pipes.close()
    pipes.close()
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("children", [[], [4343, 4444]])
def test_membership_requires_exact_worker_and_one_child(monkeypatch, children):
    def process(pid):
        return SimpleNamespace(
            pid=pid, create_time=lambda: 10.0, children=lambda **_kwargs: [process(p) for p in children]
        )

    monkeypatch.setattr(resources, "_psutil", lambda: SimpleNamespace(Process=process))
    with pytest.raises(resources.ResourceHandshakeError, match="process_membership_invalid"):
        resources._membership(4242)


def test_partial_frame_deadline_is_not_an_accepted_message():
    pipes = resources.ResourcePipes.create()
    try:
        os.write(pipes.worker_request_fd, b"0:begin")
        with pytest.raises(resources.ResourceHandshakeError, match="protocol_deadline"):
            resources._read_frame(pipes.parent_request_fd, time.monotonic() + 0.01)
    finally:
        pipes.close()
