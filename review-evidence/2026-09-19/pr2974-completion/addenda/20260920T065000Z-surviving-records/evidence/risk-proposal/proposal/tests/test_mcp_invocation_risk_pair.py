"""Unexecuted proposal controls for the bounded RSP-100 authority pair.

These tests use fresh source paths only. They do not install historical adapters,
run benchmark workers, alter campaign plans, or claim full RSP-100 acceptance.
"""

from __future__ import annotations

import contextvars
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard import mcp_request_risk as sharing
from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_authority_binding import proxy_authority_scope
from codex_plugin_scanner.guard.proxy import runtime_mcp
from codex_plugin_scanner.guard.proxy.tool_call_binding import bind_tool_call, use_tool_call_binding

from .test_mcp_owned_preparation_pilot import _session


@contextmanager
def _observed(hook=None):
    # A profile observer leaves the helper implementation identities unchanged.
    codes = {
        calls.tool_call_risk_categories.__code__: "categories",
        calls._tool_call_risk_signals_for_categories.__code__: "signals",
        GuardConfig.resolve_action_override.__code__: "policy",
    }
    seen = Counter()
    previous = sys.getprofile()

    def observe(frame, event, value):
        if event == "call" and frame.f_code in codes:
            seen[codes[frame.f_code]] += 1
        if hook is not None:
            hook(frame, event, value, seen)

    sys.setprofile(observe)
    try:
        yield seen
    finally:
        sys.setprofile(previous)


def _resolve(proxy, message):
    binding = bind_tool_call(message)
    assert binding is not None
    params = binding.owned_message["params"]
    with proxy_authority_scope(), use_tool_call_binding(binding):
        return proxy._resolve_tool_call_authority(
            tool_name=params["name"], arguments=params.get("arguments")
        )


def test_admitted_pair_derives_once_and_each_later_invocation_is_fresh(tmp_path):
    proxy, messages, _marker = _session(tmp_path)
    message = messages[-1]
    with _observed() as direct_counts:
        direct = proxy._resolve_tool_call_authority(
            tool_name=message["params"]["name"], arguments=message["params"]["arguments"]
        )
    assert direct_counts == {"categories": 2, "signals": 1, "policy": 2}
    with _observed() as counts:
        first = _resolve(proxy, message)
        second = _resolve(proxy, message)
    assert counts == {"categories": 2, "signals": 2, "policy": 4}
    assert first.artifact_hash == second.artifact_hash == direct.artifact_hash
    assert first.decision == second.decision == direct.decision
    assert sharing._OWNER.get() is None
    assert not hasattr(first, "risk_facts")


def test_real_stdio_keeps_child_bytes_and_once_only_pair(tmp_path):
    proxy, messages, marker = _session(tmp_path)
    with _observed() as counts:
        result = proxy.run_session(messages)
    assert counts["categories"] == counts["signals"] == 1
    assert counts["policy"] == 2
    assert json.loads(marker.read_text()) == messages[-1]
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"


@pytest.mark.parametrize("name", ["build_tool_call_hash", "evaluate_tool_call"])
def test_replaced_public_alias_receives_original_kwargs_and_runs_uncached(tmp_path, monkeypatch, name):
    proxy, messages, _marker = _session(tmp_path)
    original = getattr(runtime_mcp, name)
    reached = []

    def callback(*args, **kwargs):
        assert "risk_facts" not in kwargs
        reached.append(name)
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime_mcp, name, callback)
    with _observed() as counts:
        _resolve(proxy, messages[-1])
    assert reached == [name]
    assert counts["categories"] == 2


@pytest.mark.parametrize("name", ["_tool_call_risk_category_set", "_schema_risk_categories"])
def test_changed_helper_between_consumers_recomputes_without_public_alias_bypass(
    tmp_path, monkeypatch, name
):
    proxy, messages, _marker = _session(tmp_path)
    original_check = proxy._check_tool_call_preparation
    original = getattr(calls, name)
    preparations = []

    def prepare():
        preparations.append(True)
        if len(preparations) == 2:
            def changed(*args, **kwargs):
                return original(*args, **kwargs) | {"secret_access"}
            monkeypatch.setattr(calls, name, changed)
        return original_check()

    monkeypatch.setattr(proxy, "_check_tool_call_preparation", prepare)
    with _observed() as counts:
        result = _resolve(proxy, messages[-1])
    assert len(preparations) == 3
    assert counts["categories"] == 2
    assert "secret_access" in result.decision.risk_categories


def test_helper_change_after_second_policy_callback_recomputes(tmp_path, monkeypatch):
    proxy, messages, _marker = _session(tmp_path)
    original = calls._tool_call_risk_category_set
    policy_code = GuardConfig.resolve_action_override.__code__
    changed = []

    def observe(frame, event, _value, counts):
        if event == "return" and frame.f_code is policy_code and counts["policy"] == 2:
            if not changed:
                changed.append(True)
                monkeypatch.setattr(
                    calls, "_tool_call_risk_category_set",
                    lambda artifact, arguments: original(artifact, arguments) | {"secret_access"},
                )

    with _observed(observe) as counts:
        result = _resolve(proxy, messages[-1])
    assert changed == [True]
    assert counts["categories"] == 2
    assert "secret_access" in result.decision.risk_categories


@pytest.mark.parametrize("mutation", ["arguments", "catalog", "policy", "artifact"])
def test_bound_input_or_authority_change_never_reuses_prior_facts(tmp_path, mutation):
    proxy, messages, _marker = _session(tmp_path)
    proxy.config = replace(proxy.config, artifact_actions={})
    category_code = calls.tool_call_risk_categories.__code__
    changed = []

    def observe(frame, event, _value, _counts):
        if event != "return" or frame.f_code is not category_code or changed:
            return
        changed.append(True)
        if mutation == "arguments":
            frame.f_locals["arguments"]["text"] = "changed"
        elif mutation == "catalog":
            proxy._tool_catalog_generation += 1
        elif mutation == "policy":
            proxy.config.artifact_actions["changed"] = "block"
        else:
            frame.f_locals["artifact"].runtime_private_metadata["changed"] = True

    with _observed(observe), pytest.raises(runtime_mcp.framing.ProxyIoLimitError):
        _resolve(proxy, messages[-1])
    assert changed == [True]
    assert sharing._OWNER.get() is None


def test_exception_expires_token_and_does_not_poison_next_invocation(tmp_path):
    proxy, messages, _marker = _session(tmp_path)
    target = calls._tool_call_policy_context.__code__
    captured = []

    def observe(frame, event, _value, _counts):
        if event == "call" and frame.f_code is target:
            captured.append(sharing._OWNER.get())
            raise RuntimeError("injected after category derivation")

    with _observed(observe), pytest.raises(RuntimeError, match="injected"):
        _resolve(proxy, messages[-1])
    assert len(captured) == 1 and captured[0] is not None
    assert captured[0]._closed is True
    assert captured[0]._categories is None
    assert sharing._OWNER.get() is None
    with _observed() as counts:
        _resolve(proxy, messages[-1])
    assert counts["categories"] == 1


def test_nested_resolution_disables_parent_and_nested_sharing(tmp_path):
    proxy, messages, _marker = _session(tmp_path)
    target = calls.tool_call_risk_categories.__code__
    nested = []

    def observe(frame, event, _value, _counts):
        if event == "call" and frame.f_code is target and not nested:
            # Profiling callbacks do not recursively profile their own calls.
            nested.append(_resolve(proxy, messages[-1]))

    with _observed(observe) as counts:
        outer = _resolve(proxy, messages[-1])
    assert len(nested) == 1
    assert outer.artifact_hash == nested[0].artifact_hash
    assert counts["categories"] == 2
    assert sharing._OWNER.get() is None


def test_copied_context_in_another_thread_cannot_consume_the_token(tmp_path):
    proxy, messages, _marker = _session(tmp_path)
    target = calls._tool_call_policy_context.__code__
    observed = []

    def observe(frame, event, _value, _counts):
        if event == "call" and frame.f_code is target and not observed:
            facts = sharing._OWNER.get()
            assert facts is not None
            context = contextvars.copy_context()
            with ThreadPoolExecutor(max_workers=1) as executor:
                observed.append(executor.submit(context.run, facts.supported).result())
            assert facts._closed is True

    with _observed(observe) as counts:
        _resolve(proxy, messages[-1])
    assert observed == [False]
    assert counts["categories"] == 2
    assert sharing._OWNER.get() is None
