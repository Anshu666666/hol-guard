from __future__ import annotations

import functools
import hashlib
import json
import sys
import threading
from types import ModuleType

import pytest

from scripts.native_slo_identity_phases import IdentityObserver, validate_identity_report


def fixture_runtime(tmp_path, *, live=False, legacy=False):
    path = tmp_path / "private-executable-name"
    path.write_bytes(b"synthetic executable bytes" * 700)
    runtime = ModuleType("codex_plugin_scanner.guard.identity_fixture")
    runtime.hashlib = hashlib
    runtime.lookups = 0
    runtime.fail = None
    runtime._run_native_process = lambda *_a, **_k: object()

    @functools.lru_cache(maxsize=16)
    def capabilities(*key):
        return runtime._run_native_process(path, ("capabilities", "--json"), input_text="", timeout_seconds=1.0)

    def validate(candidate):
        digest = runtime.hashlib.sha256()
        with candidate.open("rb") as stream:
            while chunk := stream.read(113):
                digest.update(chunk)
        assert digest.hexdigest() == hashlib.sha256(path.read_bytes()).hexdigest()
        return "identity"

    def status(**_kwargs):
        runtime.lookups += 1
        identity = runtime.live_native_identity(path) if live else None
        if identity is None:
            identity = runtime._validate_binary(path)
        if runtime.fail is not None:
            raise runtime.fail
        result = runtime._capabilities_for_identity("fixed-identity")
        return (identity, result)

    runtime._validate_binary = validate
    runtime._capabilities_for_identity = capabilities
    if live:
        runtime.live_native_identity = lambda _path: "identity" if runtime.lookups > 1 else None
    if legacy:
        runtime.native_runtime_status = status
    else:
        runtime._inspect_native_runtime_status = status
        runtime.native_runtime_status = lambda: runtime._inspect_native_runtime_status(allow_attestation=True)

    class Handler:
        def _handle_runtime_hook(self, payload, query="", *, default_harness):
            return runtime.native_runtime_status()

    return runtime, Handler, path


def hook(handler):
    return handler()._handle_runtime_hook({"hook_event_name": "PostToolUse"}, default_harness="claude-code")


@pytest.mark.parametrize("live", [False, True])
def test_exact_accepted_hash_bytes_and_cache_hits_are_distinct(tmp_path, live):
    runtime, handler, path = fixture_runtime(tmp_path, live=live)
    original_status, original_hash = runtime._inspect_native_runtime_status, runtime.hashlib
    with IdentityObserver(runtime=runtime, handler=handler) as observer:
        results = [hook(handler) for _ in range(3)]
    report = validate_identity_report(observer.report())
    assert report["complete"] and len({id(value[1]) for value in results}) == 1
    assert report["cold_resident_measured"] is False and report["cache_state_modified"] is False
    assert runtime._inspect_native_runtime_status is original_status and runtime.hashlib is original_hash
    rows = report["rows"]
    assert [r["status_calls"] for r in rows] == [1, 1, 1]
    assert [r["capability_cache_misses"] for r in rows] == [1, 0, 0]
    assert [r["capability_cache_hits"] for r in rows] == [0, 1, 1]
    assert [r["executable_hashed_bytes"] for r in rows] == [path.stat().st_size] + (
        [0, 0] if live else [path.stat().st_size] * 2
    )
    assert [r["live_proof_hits"] for r in rows] == ([0, 1, 1] if live else [0, 0, 0])
    assert all(r["status_wall_ns"] > 0 and r["status_thread_cpu_ns"] > 0 for r in rows)
    assert str(path) not in json.dumps(report) and "synthetic executable" not in json.dumps(report)


def test_prepared_capability_cache_is_not_cleared_or_called_cold(tmp_path):
    runtime, handler, _ = fixture_runtime(tmp_path)
    original = runtime._capabilities_for_identity("fixed-identity")
    before = runtime._capabilities_for_identity.cache_info()
    with IdentityObserver(runtime=runtime, handler=handler) as observer:
        assert all(hook(handler)[1] is original for _ in range(3))
    report = validate_identity_report(observer.report())
    assert report["initial_capability_cache_entries"] == 1
    assert all(r["capability_cache_hits"] == 1 and r["capability_cache_misses"] == 0 for r in report["rows"])
    after = runtime._capabilities_for_identity.cache_info()
    assert after.hits - before.hits == 3 and after.misses == before.misses


def test_partial_observer_installation_restores_functions_and_releases_owner(tmp_path):
    runtime, handler, _ = fixture_runtime(tmp_path)
    original = runtime._inspect_native_runtime_status
    validator = runtime._validate_binary
    del runtime._validate_binary
    observer = IdentityObserver(runtime=runtime, handler=handler)
    with pytest.raises(AttributeError):
        observer.__enter__()
    assert runtime._inspect_native_runtime_status is original and not observer._installed
    runtime._validate_binary = validator
    with IdentityObserver(runtime=runtime, handler=handler) as retry:
        assert all(hook(handler) for _ in range(3))
    assert retry.report()["complete"]


def test_real_binary_validator_hashes_exact_bytes_within_observed_status(tmp_path):
    from codex_plugin_scanner.guard import native_runtime

    path = tmp_path / "runtime"
    path.write_bytes(b"x" * (1024 * 1024 + 23))

    class Handler:
        def _handle_runtime_hook(self, payload, *, default_harness):
            return native_runtime._validate_binary(path)

    with IdentityObserver(runtime=native_runtime, handler=Handler) as observer:
        identity = hook(Handler)
    row = observer.report()["rows"][0]
    assert identity.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert row["validation_calls"] == row["validation_returned_identity"] == 1
    assert row["executable_hashed_bytes"] == path.stat().st_size
    assert observer.report()["complete"] is False  # This unit call is not a three-hook route.


def test_same_original_exception_and_partial_work_survive(tmp_path):
    runtime, handler, path = fixture_runtime(tmp_path)
    error = ValueError("private arguments must never escape")
    with IdentityObserver(runtime=runtime, handler=handler) as observer:
        hook(handler)
        runtime.fail = error
        with pytest.raises(ValueError) as caught:
            hook(handler)
    assert caught.value is error
    report = validate_identity_report(observer.report())
    assert not report["complete"] and len(report["rows"]) == 2
    assert report["rows"][1]["status_raised"] == 1
    assert report["rows"][1]["executable_hashed_bytes"] == path.stat().st_size
    assert report["rows"][1]["dispatch_outcome"] == "raised"
    assert "private arguments" not in json.dumps(report)


def test_concurrent_cache_activity_is_ambiguous_not_a_fabricated_hit(tmp_path):
    runtime, handler, _ = fixture_runtime(tmp_path)
    original = runtime._run_native_process
    nested = False

    def process(*args, **kwargs):
        nonlocal nested
        if not nested:
            nested = True
            thread = threading.Thread(target=lambda: runtime._capabilities_for_identity("other-background-identity"))
            thread.start()
            thread.join(1)
            assert not thread.is_alive()
        return original(*args, **kwargs)

    runtime._run_native_process = process
    with IdentityObserver(runtime=runtime, handler=handler) as observer:
        for _ in range(3):
            hook(handler)
    report = validate_identity_report(observer.report())
    assert report["rows"][0]["capability_cache_ambiguous"] == 1
    assert report["rows"][0]["capability_cache_hits"] == report["rows"][0]["capability_cache_misses"] == 0
    assert report["rows"][0]["capability_process_calls"] == 1
    assert not report["complete"]


def test_frozen_public_status_alias_is_observed_and_restored(tmp_path, monkeypatch):
    runtime, _handler, _ = fixture_runtime(tmp_path, legacy=True)
    alias = ModuleType("codex_plugin_scanner.guard.identity_fixture_alias")
    original = runtime.native_runtime_status
    alias.status = original
    monkeypatch.setitem(sys.modules, alias.__name__, alias)

    class AliasHandler:
        def _handle_runtime_hook(self, payload, *, default_harness):
            return alias.status()

    with IdentityObserver(runtime=runtime, handler=AliasHandler) as observer:
        for _ in range(3):
            hook(AliasHandler)
    assert alias.status is original and runtime.native_runtime_status is original
    assert validate_identity_report(observer.report())["complete"]


def test_unexpected_hook_is_called_unchanged_but_diagnostic_fails(tmp_path):
    runtime, handler, _ = fixture_runtime(tmp_path)
    with IdentityObserver(runtime=runtime, handler=handler) as observer:
        for _ in range(4):
            assert hook(handler)[0] == "identity"
    report = validate_identity_report(observer.report())
    assert report["unexpected_hooks"] == 1 and len(report["rows"]) == 3 and not report["complete"]
    assert runtime.lookups == 4


@pytest.mark.parametrize("mutation", ["extra", "bool_metric", "cache_count", "false_complete", "private_phase"])
def test_closed_report_rejects_unknown_or_inconsistent_observations(tmp_path, mutation):
    runtime, handler, _ = fixture_runtime(tmp_path)
    with IdentityObserver(runtime=runtime, handler=handler) as observer:
        for _ in range(3):
            hook(handler)
    report = observer.report()
    if mutation == "extra":
        report["private_path"] = str(tmp_path)
    elif mutation == "bool_metric":
        report["rows"][0]["status_calls"] = True
    elif mutation == "cache_count":
        report["rows"][0]["capability_cache_hits"] += 1
    elif mutation == "false_complete":
        report["complete"] = False
    else:
        report["rows"][0]["phase"] = str(tmp_path)
    with pytest.raises(RuntimeError, match="qualification identity"):
        validate_identity_report(report)
