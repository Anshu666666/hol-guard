"""Unexecuted source-change refusal controls for approval risk projection."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.mcp_authority_binding import proxy_authority_scope
from codex_plugin_scanner.guard.proxy import runtime_mcp
from codex_plugin_scanner.guard.proxy.tool_call_binding import bind_tool_call, use_tool_call_binding

from .test_mcp_approval_risk_projection import _bound_queue, _queue_hooks, _supported
from .test_mcp_invocation_risk_pair import _observed
from .test_mcp_owned_preparation_pilot import _session


@pytest.mark.parametrize("changed", ["concrete_path", "context_descriptor", "config_dispatch"])
def test_observation_refuses_changed_dispatch_before_invoking_it(tmp_path, monkeypatch, changed):
    _supported()
    proxy, messages, _marker = _session(tmp_path, action="review")
    binding = bind_tool_call(messages[-1])
    params = binding.owned_message["params"]
    calls_seen = []

    def forbidden(*_args, **_kwargs):
        calls_seen.append(changed)
        raise AssertionError("changed dispatch must not run merely to enable reuse")

    with proxy_authority_scope(), use_tool_call_binding(binding):
        authority = proxy._resolve_tool_call_authority(tool_name=params["name"], arguments=params["arguments"])
        analysis = authority.risk_analysis
        assert analysis is not None
        expected = calls.tool_call_risk_summary(authority.artifact, params["arguments"])
        if changed == "concrete_path":
            monkeypatch.setattr(type(proxy.context.workspace_dir), "resolve", forbidden)
        elif changed == "context_descriptor":
            monkeypatch.setattr(type(proxy.context), "workspace_dir", property(forbidden))
        else:
            monkeypatch.setattr(type(proxy.config), "__getattribute__", forbidden)
        with _observed() as counts:
            result = runtime_mcp._approval_risk_summary(analysis, authority.artifact, params["arguments"])
    assert result == expected
    assert counts["categories"] == counts["signals"] == 1
    assert calls_seen == []
    assert analysis._phase == "closed"


@pytest.mark.parametrize(
    "interface",
    [
        "runtime_digest",
        "authority_digest",
        "authority_check",
        "request_check",
        "request_matcher",
        "request_parts",
        "request_json_alias",
        "runtime_object_shadow",
    ],
)
def test_changed_authority_interfaces_are_not_invoked_by_optional_probe(tmp_path, monkeypatch, interface):
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import mcp_authority_binding as authority_binding
    from codex_plugin_scanner.guard.proxy import tool_call_binding as request_binding

    _supported()
    proxy, messages, _marker = _session(tmp_path, action="review")
    invoked = []
    locations = {
        "runtime_digest": (runtime_mcp, "exact_authority_digest"),
        "runtime_object_shadow": (runtime_mcp, "object"),
        "authority_digest": (authority_binding, "exact_authority_digest"),
        "authority_check": (authority_binding.ExactAuthorityBinding, "check"),
        "request_check": (request_binding.ToolCallBinding, "check"),
        "request_matcher": (request_binding, "_matches_frame"),
        "request_parts": (request_binding, "_json_parts"),
        "request_json_alias": (request_binding, "json"),
    }

    def forbidden(*_args, **_kwargs):
        invoked.append(interface)
        raise AssertionError("changed authority callback is not an optional observation")

    def mutate(name):
        if name == "daemon":
            owner, member = locations[interface]
            if interface == "request_json_alias":
                replacement = SimpleNamespace(dumps=forbidden)
            elif interface == "runtime_object_shadow":
                replacement = SimpleNamespace(__getattribute__=forbidden)
            else:
                replacement = forbidden
            monkeypatch.setattr(owner, member, replacement, raising=False)

    _trace, payloads, receipts = _queue_hooks(monkeypatch, proxy, mutate=mutate)
    with _observed() as counts:
        _bound_queue(proxy, messages[-1])
    assert invoked == []
    assert counts == {"categories": 3, "signals": 2, "policy": 2}
    assert payloads and receipts


def test_reexported_default_method_does_not_hide_inherited_custom_dispatch(tmp_path):
    _supported()
    proxy, messages, _marker = _session(tmp_path, action="review")
    binding = bind_tool_call(messages[-1])
    params = binding.owned_message["params"]
    invoked = []

    class CustomDispatch(runtime_mcp.RuntimeMcpGuardProxy):
        def __getattribute__(self, name):
            invoked.append(name)
            return super().__getattribute__(name)

    class Reexported(CustomDispatch):
        _capture_tool_call_authority = runtime_mcp.RuntimeMcpGuardProxy._capture_tool_call_authority
        _bind_tool_call_artifact = staticmethod(runtime_mcp.RuntimeMcpGuardProxy._bind_tool_call_artifact)
        _evaluate_tool_call_authority = runtime_mcp.RuntimeMcpGuardProxy._evaluate_tool_call_authority
        _resolve_tool_call_authority = runtime_mcp.RuntimeMcpGuardProxy._resolve_tool_call_authority

    with proxy_authority_scope(), use_tool_call_binding(binding):
        authority = proxy._resolve_tool_call_authority(tool_name=params["name"], arguments=params["arguments"])
        analysis = authority.risk_analysis
        assert analysis is not None
        original_type = type(proxy)
        try:
            object.__setattr__(proxy, "__class__", Reexported)
            assert not runtime_mcp._approval_observation_supported(proxy)
            with _observed() as counts:
                summary = runtime_mcp._approval_risk_summary(analysis, authority.artifact, params["arguments"])
        finally:
            object.__setattr__(proxy, "__class__", original_type)
    assert summary == "No high-risk signal was detected in this tool call."
    assert counts["categories"] == counts["signals"] == 1
    assert invoked == []
    assert analysis._phase == "closed"
