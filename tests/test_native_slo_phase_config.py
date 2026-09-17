from __future__ import annotations

import importlib
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from scripts import native_slo_phases as phases
from scripts.native_slo_phases import PhaseProfiler


def _routed(profiler: PhaseProfiler, function: Any) -> Any:
    def hook(_self: object, payload: object, *, default_harness: str) -> Any:
        del payload, default_harness
        return function()

    return profiler._wrap(hook, "daemon_hook_inclusive", root=True)(
        None, {"hook_event_name": "PostToolUse"}, default_harness="claude-code"
    )


def _binding(profiler: PhaseProfiler, name: str) -> dict[str, Any]:
    return profiler.report()["config_lookup_coverage"]["bindings"][name]


@pytest.mark.parametrize(("binding", "module_name"), phases._CONFIG_BINDINGS)
@pytest.mark.parametrize("raises", [False, True])
def test_actual_config_bindings_preserve_exact_call_and_outcome(
    monkeypatch: pytest.MonkeyPatch, binding: str, module_name: str, raises: bool
) -> None:
    owner = importlib.import_module(module_name)
    home, workspace = Path("private-home"), Path("private-workspace")
    result, failure = object(), ValueError("private failure not exported")
    calls: list[tuple[object, object]] = []

    def load(guard_home: object, *, workspace: object) -> object:
        calls.append((guard_home, workspace))
        if raises:
            raise failure
        return result

    monkeypatch.setattr(owner, "load_guard_config", load)
    with PhaseProfiler() as profiler:

        def invoke() -> Any:
            if binding == "hook_worker":
                return owner.HookWorker._load_config(None, home, workspace)
            return owner.load_guard_config(home, workspace=workspace)

        if raises:
            with pytest.raises(ValueError) as caught:
                _routed(profiler, invoke)
            assert caught.value is failure
        else:
            assert _routed(profiler, invoke) is result
        assert _binding(profiler, binding)["zero_calls_observed"] is False
    assert owner.load_guard_config is load
    assert calls == [(home, workspace)]
    assert _binding(profiler, binding) == {
        "status": "complete",
        "entries": 1,
        "outermost_calls": 1,
        "zero_calls_observed": False,
    }
    span = profiler.report()["by_route"]["claude-code.PostToolUse"]["config_lookup"]
    assert span["count"] == 1
    assert span["outcomes"] == {"raised" if raises else "returned_value": 1}
    assert "private-" not in str(profiler.report())
    assert "private failure" not in str(profiler.report())


def test_dynamic_availability_import_is_observed_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import config, protection_posture
    from codex_plugin_scanner.guard.daemon.hook_availability_policy import hook_review_is_recording_only

    calls: list[object] = []
    value = config.GuardConfig(guard_home=Path("private-home"), workspace=None)
    monkeypatch.setattr(config, "load_guard_config", lambda *args, **kwargs: (calls.append(args), value)[1])
    monkeypatch.setattr(protection_posture, "protection_is_off", lambda **kwargs: True)
    with PhaseProfiler() as profiler:
        assert _routed(profiler, lambda: hook_review_is_recording_only(guard_home=Path("private-home"))) is True
    assert len(calls) == 1
    assert _binding(profiler, "config_module")["entries"] == 1


def test_forwarding_alias_records_entries_without_double_counting_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import config
    from codex_plugin_scanner.guard.daemon import hook_worker

    value = object()
    monkeypatch.setattr(config, "load_guard_config", lambda *args, **kwargs: value)
    monkeypatch.setattr(
        hook_worker, "load_guard_config", lambda *args, **kwargs: config.load_guard_config(*args, **kwargs)
    )
    with PhaseProfiler() as profiler:
        assert _routed(profiler, lambda: hook_worker.HookWorker._load_config(None, Path("home"), None)) is value
    assert _binding(profiler, "hook_worker")["entries"] == 1
    assert _binding(profiler, "hook_worker")["outermost_calls"] == 1
    assert _binding(profiler, "config_module")["entries"] == 1
    assert _binding(profiler, "config_module")["outermost_calls"] == 0
    assert _binding(profiler, "config_module")["zero_calls_observed"] is False
    assert profiler.report()["by_route"]["claude-code.PostToolUse"]["config_lookup"]["count"] == 1


def test_verified_zero_requires_completed_foreground_window(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import config

    calls: list[bool] = []
    monkeypatch.setattr(config, "load_guard_config", lambda *args, **kwargs: calls.append(True))
    profiler = PhaseProfiler()
    assert _binding(profiler, "config_module")["entries"] is None
    with profiler:
        config.load_guard_config(Path("outside-route"))
        assert _binding(profiler, "config_module")["zero_calls_observed"] is False
        assert _routed(profiler, lambda: 17) == 17
        assert _binding(profiler, "config_module")["zero_calls_observed"] is False
    assert calls == [True]
    assert all(row["zero_calls_observed"] for row in profiler.report()["config_lookup_coverage"]["bindings"].values())
    with PhaseProfiler() as idle:
        pass
    assert _binding(idle, "config_module")["zero_calls_observed"] is False
    _routed(idle, lambda: None)  # A late retained wrapper cannot complete the old window.
    assert _binding(idle, "config_module")["zero_calls_observed"] is False


def test_missing_historical_binding_is_unsupported_not_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    original = importlib.import_module
    missing = phases._CONFIG_BINDINGS[-1][1]

    def load(name: str) -> Any:
        if name == missing:
            raise ModuleNotFoundError(name=missing)
        return original(name)

    monkeypatch.setattr(phases.importlib, "import_module", load)
    with PhaseProfiler() as profiler:
        _routed(profiler, lambda: None)
    assert _binding(profiler, "native_review_continuation") == {
        "status": "unsupported",
        "entries": None,
        "outermost_calls": None,
        "zero_calls_observed": False,
    }


def test_reader_context_is_not_foreground_config_work(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import config

    result = object()
    monkeypatch.setattr(config, "load_guard_config", lambda *args, **kwargs: result)
    with PhaseProfiler() as profiler:
        assert profiler.reader_call(config.load_guard_config, "reader_config", Path("home")) is result
        _routed(profiler, lambda: None)
    assert _binding(profiler, "config_module")["entries"] == 0
    assert _binding(profiler, "config_module")["zero_calls_observed"] is True


def test_unavailable_alias_callable_is_not_a_measured_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker

    monkeypatch.setattr(hook_worker, "load_guard_config", None)
    with PhaseProfiler() as profiler:
        _routed(profiler, lambda: None)
    assert _binding(profiler, "hook_worker") == {
        "status": "unsupported",
        "entries": None,
        "outermost_calls": None,
        "zero_calls_observed": False,
    }


def test_zero_is_not_certified_until_restoration_finishes(monkeypatch: pytest.MonkeyPatch) -> None:
    with PhaseProfiler() as profiler:
        _routed(profiler, lambda: None)
        original_close = profiler._stack.close

        def close() -> None:
            assert _binding(profiler, "config_module")["zero_calls_observed"] is False
            original_close()

        monkeypatch.setattr(profiler._stack, "close", close)
    assert _binding(profiler, "config_module")["zero_calls_observed"] is True


def test_foreground_already_running_at_installation_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    entered, release = threading.Event(), threading.Event()
    profiler = PhaseProfiler()
    original_install = profiler._install_config_probes

    def operation() -> None:
        entered.set()
        assert release.wait(2)

    with ThreadPoolExecutor(max_workers=1) as executor:

        def install() -> None:
            future = executor.submit(_routed, profiler, operation)
            try:
                assert entered.wait(2)
                original_install()
            finally:
                release.set()
            future.result(timeout=2)

        monkeypatch.setattr(profiler, "_install_config_probes", install)
        with profiler:
            _routed(profiler, lambda: None)
    assert _binding(profiler, "config_module")["status"] == "foreground_at_installation"
    assert _binding(profiler, "config_module")["zero_calls_observed"] is False


def test_binding_replacement_is_explicit_and_original_restored(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.daemon import hook_worker

    original = hook_worker.load_guard_config
    with PhaseProfiler() as profiler:
        _routed(profiler, lambda: None)
        monkeypatch.setattr(hook_worker, "load_guard_config", lambda *args, **kwargs: None)
    assert hook_worker.load_guard_config is original
    assert _binding(profiler, "hook_worker")["status"] == "binding_changed"
    assert _binding(profiler, "hook_worker")["zero_calls_observed"] is False


def test_partial_setup_failure_restores_all_original_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    originals = [
        (importlib.import_module(module), importlib.import_module(module).load_guard_config)
        for _name, module in phases._CONFIG_BINDINGS
    ]
    failure = RuntimeError("synthetic setup failure")

    def fail(*args: object) -> None:
        raise failure

    monkeypatch.setattr(phases, "install_io_probes", fail)
    profiler = PhaseProfiler()
    with pytest.raises(RuntimeError) as caught:
        profiler.__enter__()
    assert caught.value is failure
    assert all(owner.load_guard_config is original for owner, original in originals)
    assert all(
        row["status"] == "setup_failed" for row in profiler.report()["config_lookup_coverage"]["bindings"].values()
    )
    assert all(
        not row["zero_calls_observed"] for row in profiler.report()["config_lookup_coverage"]["bindings"].values()
    )


def test_missing_dependency_is_not_mislabeled_as_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    original_import = importlib.import_module
    original_validate = native_runtime._validate_binary
    failure = ModuleNotFoundError(name="private_missing_dependency")

    def load(name: str) -> Any:
        if name == phases._CONFIG_BINDINGS[-1][1]:
            raise failure
        return original_import(name)

    monkeypatch.setattr(phases.importlib, "import_module", load)
    profiler = PhaseProfiler()
    with pytest.raises(ModuleNotFoundError) as caught:
        profiler.__enter__()
    assert caught.value is failure
    assert native_runtime._validate_binary is original_validate
    assert all(
        not row["zero_calls_observed"] for row in profiler.report()["config_lookup_coverage"]["bindings"].values()
    )


def test_failed_lookup_resets_nesting_for_next_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import config

    calls: list[bool] = []
    failure = RuntimeError("private original")

    def load(*args: object) -> None:
        calls.append(True)
        if len(calls) == 1:
            raise failure

    monkeypatch.setattr(config, "load_guard_config", load)
    with PhaseProfiler() as profiler:
        with pytest.raises(RuntimeError) as caught:
            _routed(profiler, lambda: config.load_guard_config(Path("home")))
        assert caught.value is failure
        _routed(profiler, lambda: config.load_guard_config(Path("home")))
    assert _binding(profiler, "config_module")["outermost_calls"] == 2
    assert profiler.report()["by_route"]["claude-code.PostToolUse"]["config_lookup"]["outcomes"] == {
        "raised": 1,
        "returned_none": 1,
    }


@pytest.mark.parametrize("in_config", [False, True])
@pytest.mark.parametrize("raises", [False, True])
def test_teardown_during_foreground_work_never_certifies_zero(
    monkeypatch: pytest.MonkeyPatch, in_config: bool, raises: bool
) -> None:
    from codex_plugin_scanner.guard import config
    from codex_plugin_scanner.guard.daemon import hook_worker

    entered, release = threading.Event(), threading.Event()
    value, failure = object(), ValueError("original delayed failure")
    calls: list[bool] = []

    def canonical(*args: object, **kwargs: object) -> object:
        calls.append(True)
        if raises:
            raise failure
        return value

    def block() -> None:
        entered.set()
        assert release.wait(2)

    def alias(*args: object, **kwargs: object) -> object:
        if in_config:
            block()
        return config.load_guard_config(*args, **kwargs)

    def operation() -> object:
        if not in_config:
            block()
        return hook_worker.load_guard_config(Path("home"))

    monkeypatch.setattr(config, "load_guard_config", canonical)
    monkeypatch.setattr(hook_worker, "load_guard_config", alias)
    profiler = PhaseProfiler()
    profiler.__enter__()
    _routed(profiler, lambda: None)  # An earlier completed root must not hide overlap.
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_routed, profiler, operation)
        try:
            assert entered.wait(2)
            profiler.__exit__()
            assert _binding(profiler, "config_module")["status"] == "in_flight_at_teardown"
            assert not any(
                row["zero_calls_observed"] for row in profiler.report()["config_lookup_coverage"]["bindings"].values()
            )
        finally:
            release.set()
            profiler.__exit__()
        if raises:
            with pytest.raises(ValueError) as caught:
                future.result(timeout=2)
            assert caught.value is failure
        else:
            assert future.result(timeout=2) is value
    assert calls == [True]
    assert config.load_guard_config is canonical
    assert hook_worker.load_guard_config is alias
    assert _binding(profiler, "config_module")["entries"] == 0
    assert _binding(profiler, "config_module")["zero_calls_observed"] is False
