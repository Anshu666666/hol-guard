"""Unrun source recovery of RSP-100 dependency-change counterexamples.

This file is a separate finite witness. It imports no historical pilot or
measurement worker and installs no adapter. The input-only helper below is an
intentionally unsafe negative control, not a proposed implementation.
"""

from __future__ import annotations

import sys
from pathlib import PurePath

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_authority_binding import exact_authority_digest, use_mcp_authority_check
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy
from codex_plugin_scanner.guard.store import GuardStore


def _fixture(tmp_path):
    context = HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / "guard")
    config = GuardConfig(
        guard_home=context.guard_home,
        workspace=tmp_path,
        default_action="allow",
        mode="prompt",
        risk_actions={"mcp_dangerous_tool": "review"},
    )
    proxy = CodexMcpGuardProxy(
        server_name="synthetic",
        command=[sys.executable, "-u", "-c", ""],
        context=context,
        store=GuardStore(context.guard_home),
        config=config,
        source_scope="project",
        config_path=".mcp.json",
    )
    definition = {
        "name": "summarize",
        "description": "Summarize text.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
    }
    proxy._tool_catalog["summarize"] = definition
    proxy._tool_catalog_state = "complete"
    artifact = calls.build_tool_call_artifact(
        harness="codex",
        server_name="synthetic",
        tool_name="summarize",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        tool_schema=definition["inputSchema"],
        tool_description=definition["description"],
        server_fingerprint={"tool_catalog_fingerprint": "synthetic-initial"},
    )
    arguments = {"text": "ordinary text"}
    check = proxy._capture_tool_call_authority(arguments=arguments, config=config)
    check, _ = proxy._bind_tool_call_artifact(artifact, check)
    assert check is not None
    return proxy, config, artifact, arguments, check


def _input_only_negative_control(proxy, config, artifact, arguments, facts):
    """Exercise existing optional APIs with deliberately stale input-only facts."""
    artifact_hash = calls.build_tool_call_hash(
        artifact, arguments, workspace=proxy.context.workspace_dir, config=config, risk_facts=facts
    )
    decision = calls.evaluate_tool_call(
        store=proxy.store,
        config=config,
        artifact=artifact,
        artifact_hash=artifact_hash,
        arguments=arguments,
        claim_saved_approval=False,
        risk_facts=facts,
    )
    return artifact_hash, decision


def _count_categories(monkeypatch):
    original = calls.tool_call_risk_categories
    observations = []

    def counted(artifact, arguments):
        result = original(artifact, arguments)
        observations.append(result)
        return result

    monkeypatch.setattr(calls, "tool_call_risk_categories", counted)
    return observations


def _forbid_selected_preparation(*_args, **_kwargs):
    pytest.fail("Selected B entered the unselected request-facts preparation API")


def test_constructor_replacement_retains_the_purepath_name_counterexample(tmp_path, monkeypatch):
    proxy, config, artifact, arguments, authority_check = _fixture(tmp_path)
    observations = _count_categories(monkeypatch)
    facts = calls.prepare_tool_call_risk_facts(artifact, arguments)
    assert facts is not None and facts.categories == ()
    assert observations == [()]
    original_constructor = calls.ToolCallDecision
    original_name = PurePath.__dict__["name"]
    original_risk_function = calls.tool_call_risk_categories
    original_risk_code = original_risk_function.__code__
    original_category_set = calls._tool_call_risk_category_set
    original_category_code = original_category_set.__code__
    input_digest = exact_authority_digest((config, artifact, arguments))
    trace = []

    def construct_then_change_dependency(*args, **kwargs):
        decision = original_constructor(*args, **kwargs)
        assert decision.action == "allow" and decision.risk_categories == ()
        monkeypatch.setattr(PurePath, "name", property(lambda _path: "run_terminal_command"))
        monkeypatch.setattr(calls, "ToolCallDecision", original_constructor)
        trace.append("PurePath.name replaced; original ToolCallDecision restored")
        return decision

    monkeypatch.setattr(calls, "ToolCallDecision", construct_then_change_dependency)
    with use_mcp_authority_check(authority_check):
        _, initial = _input_only_negative_control(proxy, config, artifact, arguments, facts)
    assert initial.action == "allow" and initial.risk_categories == ()
    assert trace == ["PurePath.name replaced; original ToolCallDecision restored"]
    assert calls.ToolCallDecision is original_constructor
    assert PurePath.__dict__["name"] is not original_name
    assert PurePath("summarize").name == "run_terminal_command"
    assert calls.tool_call_risk_categories is original_risk_function
    assert original_risk_function.__code__ is original_risk_code
    assert calls._tool_call_risk_category_set is original_category_set
    assert original_category_set.__code__ is original_category_code
    assert exact_authority_digest((config, artifact, arguments)) == input_digest
    authority_check()
    assert calls._matching_tool_call_risk_snapshot(artifact, arguments, facts) is not None

    # The callback has restored the constructor. Only its dependency mutation
    # survives into this later invocation of the actual selected B evaluator.
    monkeypatch.setattr(calls, "prepare_tool_call_risk_facts", _forbid_selected_preparation)
    with use_mcp_authority_check(authority_check):
        _, fresh_hash, fresh = proxy._evaluate_tool_call_authority(
            artifact=artifact, arguments=arguments, config=config
        )
    assert observations == [(), ("command_execution",), ("command_execution",)]
    assert fresh.action == "review"
    assert fresh.risk_categories == ("command_execution",)
    authority_check()

    with use_mcp_authority_check(authority_check):
        stale_hash, stale = _input_only_negative_control(proxy, config, artifact, arguments, facts)
    assert stale.action == "allow" and stale.risk_categories == ()
    assert stale_hash != fresh_hash
    assert observations == [(), ("command_execution",), ("command_execution",)]
    assert exact_authority_digest((config, artifact, arguments)) == input_digest
    authority_check()


@pytest.mark.parametrize("mutation", ["function_binding", "function_code", "closure_contents"])
def test_later_risk_changes_are_not_bound_by_input_only_facts(tmp_path, monkeypatch, mutation):
    proxy, config, artifact, arguments, authority_check = _fixture(tmp_path)
    original = calls._tool_call_risk_category_set
    state = {"changed": False}

    def closure_risk(current_artifact, current_arguments):
        if state["changed"]:
            return {"command_execution"}
        return original(current_artifact, current_arguments)

    if mutation == "closure_contents":
        monkeypatch.setattr(calls, "_tool_call_risk_category_set", closure_risk)
    selected = calls._tool_call_risk_category_set
    original_code = selected.__code__
    facts = calls.prepare_tool_call_risk_facts(artifact, arguments)
    assert facts is not None and facts.categories == ()
    original_constructor = calls.ToolCallDecision

    def changed_risk(_artifact, _arguments):
        return {"command_execution"}

    def construct_then_change_risk(*args, **kwargs):
        decision = original_constructor(*args, **kwargs)
        if mutation == "function_binding":
            monkeypatch.setattr(calls, "_tool_call_risk_category_set", changed_risk)
        elif mutation == "function_code":
            monkeypatch.setattr(selected, "__code__", changed_risk.__code__)
        else:
            state["changed"] = True
        monkeypatch.setattr(calls, "ToolCallDecision", original_constructor)
        return decision

    monkeypatch.setattr(calls, "ToolCallDecision", construct_then_change_risk)
    with use_mcp_authority_check(authority_check):
        _, initial = _input_only_negative_control(proxy, config, artifact, arguments, facts)
    assert initial.action == "allow" and initial.risk_categories == ()
    assert calls.ToolCallDecision is original_constructor
    if mutation == "function_binding":
        assert calls._tool_call_risk_category_set is not selected
    else:
        assert calls._tool_call_risk_category_set is selected
        assert (selected.__code__ is original_code) is (mutation == "closure_contents")
    authority_check()
    assert calls._matching_tool_call_risk_snapshot(artifact, arguments, facts) is not None

    monkeypatch.setattr(calls, "prepare_tool_call_risk_facts", _forbid_selected_preparation)
    with use_mcp_authority_check(authority_check):
        _, fresh_hash, fresh = proxy._evaluate_tool_call_authority(
            artifact=artifact, arguments=arguments, config=config
        )
        stale_hash, stale = _input_only_negative_control(proxy, config, artifact, arguments, facts)
    assert fresh.action == "review" and fresh.risk_categories == ("command_execution",)
    assert stale.action == "allow" and stale.risk_categories == ()
    assert fresh_hash != stale_hash
    authority_check()
