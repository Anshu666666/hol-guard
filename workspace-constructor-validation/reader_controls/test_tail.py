"""Actual post-worker source calls, eager thread cleanup, and finite-tail refusals."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from codex_plugin_scanner.guard.daemon import hook_worker, request_executor, server, server_http
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_command_fixture import prepare_empty_command_authority

from constructor.capture import PARENTS, TAIL_ARGUMENTS, TAIL_STAGES, Capture
from constructor.hooks import CALLERS, OwnedHooks
from constructor.reader import admit_phases
from constructor.tail_hooks import TAIL_SITES, install_tail
from reader_controls.test_capture import capture, nested
from reader_controls.test_hooks import registry


def fixture_prefix(value: Capture, body: Any) -> Any:
    """Model the existing five boundaries; body retains actual request-services code."""

    def at(index: int) -> Any:
        stage = list(PARENTS)[index]

        def original() -> Any:
            if index == 4:
                return True
            if index == 3:
                value.adopt(object(), value.store)
                value.acceptance(value.clock())
            at(index + 1)
            if index == 2:
                body()
            return None

        return value.call(stage, CALLERS[stage], original, (), {})

    return value.replacement(at, (0,), {})


@pytest.mark.parametrize("fail_thread", [None, 34])
def test_actual_authority_and_both_eager_executor_calls_are_source_bound_and_retired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_thread: int | None
) -> None:
    sites = registry()
    store = GuardStore(tmp_path / "home")
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"k" * 32, "test"))
    prepare_empty_command_authority(store)
    http: Any = server_http._GuardDaemonHTTPServer.__new__(server_http._GuardDaemonHTTPServer)
    http.store = store
    cleanup: list[str] = []
    http.runtime_hook_evidence_writer = SimpleNamespace(stop=lambda **_kw: cleanup.append("writer"))
    http.hook_config_reader = None
    http.hook_config_scope = None
    http.runtime = object()
    http.hook_process_runner = SimpleNamespace(close_contained=lambda: cleanup.append("runner"))
    monkeypatch.setattr(hook_worker, "HookWorker", lambda **_kw: object())
    for name in (
        "ExtensionControlRuntime",
        "ExtensionControlApiService",
        "LocalCliApiService",
        "ApprovalAttentionCoordinator",
    ):
        monkeypatch.setattr(server, name, lambda *_args, **_kwargs: object())
    value = Capture(object())
    value.store, value.http = store, http
    hooks = OwnedHooks(value, sites)
    thread_calls: list[Any] = []
    original_start = request_executor.threading.Thread.start
    failure = RuntimeError("PRIVATE_PARTIAL_CONTROL_START")

    def start(thread: Any) -> None:
        thread_calls.append(thread)
        if len(thread_calls) == fail_thread:
            raise failure
        original_start(thread)

    monkeypatch.setattr(request_executor.threading.Thread, "start", start)
    try:
        install_tail(hooks)
        if fail_thread is None:
            fixture_prefix(value, http._initialize_request_services)
        else:
            with pytest.raises(RuntimeError) as caught:
                fixture_prefix(value, http._initialize_request_services)
            assert caught.value is failure
            # These calls and retirement happen in the original request-services
            # failure arm, before this test's fallback cleanup.
            assert cleanup == ["writer", "runner"]
            assert all(not thread.is_alive() for thread in thread_calls)
            assert all(not thread.is_alive() for thread in http.general_request_executor.threads)
    finally:
        hooks.close()
        for name in ("control_request_executor", "general_request_executor"):
            executor = getattr(http, name, None)
            if executor is not None:
                assert executor.shutdown(timeout_seconds=2)
                assert all(not thread.is_alive() for thread in executor.threads)
    report = value.freeze()
    assert hooks.restored and report["observation_complete"]
    assert [row["site"] for row in report["tail_rows"]] == list(TAIL_SITES.values())
    assert [(row["workers"], row["queue_limit"]) for row in report["tail_rows"]] == list(TAIL_ARGUMENTS)
    summary = admit_phases(report)
    assert summary["all_three_tail_returned"] is (fail_thread is None)
    assert len(http.general_request_executor.threads) == 32
    if fail_thread is None:
        assert len(http.control_request_executor.threads) == 8 and cleanup == []
    else:
        assert not hasattr(http, "control_request_executor") and report["tail_rows"][-1]["outcome"] == "exception"


def test_actual_executor_partial_thread_start_failure_cleans_started_thread_and_preserves_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value, error, calls, started = capture(), RuntimeError("PRIVATE_THREAD_FAILURE"), [], []
    original_start = request_executor.threading.Thread.start

    def start(thread: Any) -> None:
        calls.append(thread)
        if len(calls) == 2:
            raise error
        original_start(thread)
        started.append(thread)

    monkeypatch.setattr(request_executor.threading.Thread, "start", start)
    executor = request_executor.BoundedRequestExecutor.__new__(request_executor.BoundedRequestExecutor)

    def body() -> None:
        value.tail_call("authority_read", TAIL_SITES["authority_read"], lambda: object(), (), {})
        value.tail_call(
            "general_executor",
            TAIL_SITES["general_executor"],
            request_executor.BoundedRequestExecutor.__init__,
            (executor,),
            {
                "name": "general",
                "workers": 32,
                "queue_limit": 128,
                "run": lambda *_a: None,
                "discard": lambda *_a: None,
            },
            workers=32,
            queue_limit=128,
        )

    value.store = object()
    with pytest.raises(RuntimeError) as caught:
        fixture_prefix(value, body)
    assert caught.value is error and len(calls) == 2 and len(started) == 1
    assert not started[0].is_alive() and executor.shutdown(timeout_seconds=1)
    report = value.freeze()
    assert report["observation_complete"] is True and "PRIVATE_THREAD_FAILURE" not in json.dumps(report)
    assert report["tail_rows"][-1]["outcome"] == "exception"
    assert admit_phases(report)["observed_tail_phases"] == 2


def test_unselected_executor_exception_is_forwarded_once(monkeypatch: pytest.MonkeyPatch) -> None:
    sites, value, calls = registry(), capture(), []
    error = RuntimeError("PRIVATE_UNSELECTED")

    def original(*args: Any, **kwargs: Any) -> None:
        calls.append((args, kwargs))
        raise error

    monkeypatch.setattr(request_executor.BoundedRequestExecutor, "__init__", original)
    hooks = OwnedHooks(value, sites)
    try:
        install_tail(hooks)
        with pytest.raises(RuntimeError) as caught:
            value.replacement(
                lambda: request_executor.BoundedRequestExecutor(
                    name="outside", workers=0, queue_limit=1, run=lambda *_a: None, discard=lambda *_a: None
                ),
                (),
                {},
            )
        assert caught.value is error and len(calls) == 1 and value.tail_rows == []
    finally:
        hooks.close()
    assert hooks.restored


def test_authority_result_is_opaque_and_argument_identity_preserved() -> None:
    value, calls = capture(), []

    class Private:
        def __getattribute__(self, _name: str) -> Any:
            raise AssertionError("must not inspect")

        def __repr__(self) -> str:
            raise AssertionError("must not render")

    result, argument = Private(), object()

    def original(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        return result

    def body() -> None:
        assert (
            value.tail_call("authority_read", TAIL_SITES["authority_read"], original, (argument,), {"key": argument})
            is result
        )
        for index in (1, 2):
            workers, limit = TAIL_ARGUMENTS[index]
            value.tail_call(
                TAIL_STAGES[index],
                TAIL_SITES[TAIL_STAGES[index]],
                lambda: None,
                (),
                {},
                workers=workers,
                queue_limit=limit,
            )

    value.store = object()
    fixture_prefix(value, body)
    assert calls == [((argument,), {"key": argument})]
    assert admit_phases(value.freeze())["all_three_tail_returned"]
    assert "Private" not in json.dumps(value.freeze())


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "reversed",
        "parent",
        "before_worker",
        "after_services",
        "overlap",
        "bool_workers",
        "counts",
        "private",
        "returned",
        "exception",
        "site",
    ],
)
def test_impossible_tail_images_refuse(mutation: str) -> None:
    value = capture()
    nested(value)
    report = copy.deepcopy(value.freeze())
    rows = report["tail_rows"]
    if mutation == "missing":
        rows.pop()
    elif mutation == "extra":
        rows.append(dict(rows[-1]))
    elif mutation == "reversed":
        rows.reverse()
    elif mutation == "parent":
        rows[0]["parent"] = 3
    elif mutation == "before_worker":
        rows[0]["entry_seconds"] = report["rows"][3]["exit_seconds"] - 1
    elif mutation == "after_services":
        rows[-1]["exit_seconds"] = report["rows"][2]["exit_seconds"] + 1
    elif mutation == "overlap":
        rows[1]["entry_seconds"] = rows[0]["exit_seconds"] - 1
    elif mutation == "bool_workers":
        rows[1]["workers"] = True
    elif mutation == "counts":
        rows[1]["queue_limit"] = 1
    elif mutation == "private":
        rows[0]["value"] = "private"
    elif mutation == "returned":
        rows[0]["returned"] = "private"
    elif mutation == "exception":
        rows[0].update(outcome="exception", returned=None, error="runtime_error")
    elif mutation == "site":
        rows[1]["site"] = TAIL_SITES["control_executor"]
    with pytest.raises((ValueError, TypeError)):
        admit_phases(report)


def test_tail_overflow_and_failed_clock_never_retry_original(monkeypatch: pytest.MonkeyPatch) -> None:
    from constructor import capture as module

    value, calls = capture(), []
    monkeypatch.setattr(module, "MAX_TAIL_ROWS", 0)
    value.store = object()
    fixture_prefix(
        value, lambda: value.tail_call("authority_read", TAIL_SITES["authority_read"], lambda: calls.append(1), (), {})
    )
    assert calls == [1] and value.overflow and value.lost and not value.active_tail

    def broken() -> float:
        raise ValueError("PRIVATE_CLOCK")

    monkeypatch.setattr(module, "MAX_TAIL_ROWS", 3)
    value = capture()
    value.store = object()
    error = OSError("PRIVATE_ERROR")

    def original() -> None:
        calls.append(2)
        raise error

    def fail_clock() -> None:
        value.clock = broken
        value.tail_call("authority_read", TAIL_SITES["authority_read"], original, (), {})

    with pytest.raises(OSError) as caught:
        fixture_prefix(value, fail_clock)
    assert caught.value is error and calls == [1, 2]


@pytest.mark.parametrize("failure", ["store", "registry", "flags", "exception"])
def test_selected_authority_owner_refusals_forward_exactly_once(failure: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.store_extension_control_authority import StoreExtensionControlAuthorityMixin

    value, calls, result, original_error = capture(), [], object(), RuntimeError("PRIVATE_AUTHORITY")
    owner = object()
    value.store = owner

    class Sites:
        def site(self, _frame: Any) -> str:
            return TAIL_SITES["authority_read"]

    def original(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        if failure == "exception":
            raise original_error
        return result

    monkeypatch.setattr(StoreExtensionControlAuthorityMixin, "read_extension_control_authority_for_registry", original)
    hooks = OwnedHooks(value, Sites())
    arg_owner = object() if failure == "store" else owner
    arg_registry = object() if failure == "registry" else server.BUILT_IN_COMMAND_EXTENSION_REGISTRY
    kwargs = {"read_only": True} if failure == "flags" else {}

    def body() -> None:
        call: Any = StoreExtensionControlAuthorityMixin.read_extension_control_authority_for_registry
        actual = call(arg_owner, arg_registry, **kwargs)
        assert actual is result

    try:
        install_tail(hooks)
        if failure == "exception":
            with pytest.raises(RuntimeError) as caught:
                fixture_prefix(value, body)
            assert caught.value is original_error
            assert value.tail_rows[0]["outcome"] == "exception"
        else:
            fixture_prefix(value, body)
            assert value.lost and value.tail_rows == []
    finally:
        hooks.close()
    assert calls == [((arg_owner, arg_registry), kwargs)] and hooks.restored


@pytest.mark.parametrize("failure", ["run_owner", "run_function", "workers", "name", "site"])
def test_selected_executor_owner_refusals_preserve_original_call(failure: str, monkeypatch: pytest.MonkeyPatch) -> None:
    import types

    value, calls = capture(), []
    value.store, value.http = object(), object()

    class Sites:
        def site(self, _frame: Any) -> str:
            return TAIL_SITES["general_executor"] if failure != "site" else TAIL_SITES["general_executor"] + "0"

    def original(*args: Any, **kwargs: Any) -> None:
        calls.append((args, kwargs))

    monkeypatch.setattr(request_executor.BoundedRequestExecutor, "__init__", original)
    hooks = OwnedHooks(value, Sites())
    arguments: dict[str, Any] = {
        "name": "general",
        "workers": 32,
        "queue_limit": 128,
        "run": types.MethodType(server_http._GuardDaemonHTTPServer._process_request_worker, value.http),
        "discard": types.MethodType(server_http._GuardDaemonHTTPServer._discard_request, value.http),
    }
    if failure == "run_owner":
        arguments["run"] = types.MethodType(server_http._GuardDaemonHTTPServer._process_request_worker, object())
    elif failure == "run_function":
        arguments["run"] = lambda *_a: None
    elif failure == "workers":
        arguments["workers"] = True
    elif failure == "name":
        arguments["name"] = "PRIVATE_NAME"
    instance = request_executor.BoundedRequestExecutor.__new__(request_executor.BoundedRequestExecutor)

    def body() -> None:
        value.tail_call("authority_read", TAIL_SITES["authority_read"], lambda: object(), (), {})
        assert request_executor.BoundedRequestExecutor.__init__(instance, **arguments) is None

    try:
        install_tail(hooks)
        fixture_prefix(value, body)
    finally:
        hooks.close()
    assert len(calls) == 1 and calls[0] == ((instance,), arguments)
    assert value.lost and len(value.tail_rows) == 1 and hooks.restored
    assert "PRIVATE_NAME" not in json.dumps(value.freeze())
