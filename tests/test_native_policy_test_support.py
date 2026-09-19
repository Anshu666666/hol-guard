"""Finite readiness diagnostics preserve transport and test budgets."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_test_support as support
from codex_plugin_scanner.guard.native_resident_client import record_native_resident_client_failure_code


@pytest.mark.parametrize("result", [None, b"synthetic response"])
def test_transport_arguments_result_and_worker_failure_are_preserved(result: bytes | None) -> None:
    diagnostic = support._PublicationDiagnostics()
    sentinel = object()
    calls = []
    responses = []

    def client(**kwargs):
        calls.append(kwargs)
        record_native_resident_client_failure_code("native_client_timed_out")
        return result

    worker = threading.Thread(target=lambda: responses.append(diagnostic.call(client, payload=sentinel, deadline=7)))
    worker.start()
    worker.join()
    assert calls == [{"payload": sentinel, "deadline": 7}]
    assert responses == [result]
    assert diagnostic.describe(None) == "publisher=missing; transport=native_client_timed_out; started=1; completed=1"
    record_native_resident_client_failure_code("native_client_exit_nonzero")
    assert "native_client_timed_out" in diagnostic.describe(None)


def test_transport_exception_is_not_replaced_and_untrusted_text_is_not_rendered() -> None:
    diagnostic = support._PublicationDiagnostics()
    failure = RuntimeError("private-message-canary")

    def client(**_kwargs):
        record_native_resident_client_failure_code("private-transport-canary")
        raise failure

    with pytest.raises(RuntimeError) as caught:
        diagnostic.call(client, payload=b"private-payload-canary")
    assert caught.value is failure
    assert diagnostic.describe("private-publisher-canary") == "publisher=other; transport=other; started=1; completed=1"


def test_completed_failure_survives_a_later_success_and_counters_are_bounded() -> None:
    diagnostic = support._PublicationDiagnostics()

    def client(**_kwargs):
        if diagnostic._started == 1:
            record_native_resident_client_failure_code("native_client_timed_out")
        return b"synthetic"

    for _ in range(1001):
        diagnostic.call(client)
    assert diagnostic.describe(None) == (
        "publisher=missing; transport=native_client_timed_out; started=999; completed=999"
    )


class _Publisher:
    def __init__(self, *, ready: bool, snapshot: object, injected: bool = False) -> None:
        self.ready = ready
        self.snapshot = snapshot
        self._client_request = (lambda **_kwargs: b"injected") if injected else None
        self.last_error = "private-publisher-canary"
        self.started = False
        self.closed = False
        self.deadlines = []

    def start(self):
        self.started = True

    def wait_until_ready(self, deadline):
        self.deadlines.append(deadline)
        return self.ready

    def current_snapshot(self):
        return self.snapshot

    def close(self):
        self.closed = True


@pytest.mark.parametrize("platform,budget", [("linux", 3.0), ("win32", 25.0)])
@pytest.mark.parametrize("injected", [False, True])
def test_readiness_failure_keeps_original_budget_and_restores_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, budget: float, injected: bool
) -> None:
    publisher = _Publisher(ready=False, snapshot=None, injected=injected)
    previous = publisher._client_request
    monkeypatch.setattr(support, "get_native_policy_snapshot_publisher", lambda _store: publisher)
    monkeypatch.setattr(support.sys, "platform", platform)
    monkeypatch.setattr(support.time, "monotonic", lambda: 100.0)
    with (
        pytest.raises(AssertionError, match="native policy publisher was not ready: publisher=other") as caught,
        support.native_policy_snapshot(tmp_path),
    ):
        pytest.fail("Unavailable publication cannot yield authority")
    assert "private-publisher-canary" not in str(caught.value)
    assert publisher.started and publisher.closed
    assert publisher.deadlines == [100.0 + budget]
    assert publisher._client_request is previous


@pytest.mark.parametrize("snapshot", [None, {"generation": 4}])
def test_ready_snapshot_predicate_and_cleanup_are_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, snapshot: object
) -> None:
    publisher = _Publisher(ready=True, snapshot=snapshot)
    monkeypatch.setattr(support, "get_native_policy_snapshot_publisher", lambda _store: publisher)
    if snapshot is None:
        with (
            pytest.raises(AssertionError, match="native policy publisher returned no ACKed snapshot"),
            support.native_policy_snapshot(tmp_path),
        ):
            pytest.fail("Missing snapshot cannot yield authority")
    else:
        with support.native_policy_snapshot(tmp_path) as actual:
            assert actual is snapshot
    assert publisher.closed and publisher._client_request is None


def test_original_client_is_restored_when_close_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    publisher = _Publisher(ready=True, snapshot={"generation": 4})
    failure = RuntimeError("synthetic close failure")

    def close():
        publisher.closed = True
        raise failure

    monkeypatch.setattr(publisher, "close", close)
    monkeypatch.setattr(support, "get_native_policy_snapshot_publisher", lambda _store: publisher)
    with pytest.raises(RuntimeError) as caught, support.native_policy_snapshot(tmp_path):
        pass
    assert caught.value is failure
    assert publisher.closed and publisher._client_request is None
