"""Finite owned-generation and actual-child-write witnesses for candidate E."""

from __future__ import annotations

import importlib
import io
import json
import sys
from argparse import Namespace
from contextlib import nullcontext
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy, framing, runtime_mcp
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("guard_mcp_owned_preparation_pilot")


@pytest.fixture
def pilot(module):
    candidate = module.OwnedPreparationPilot()
    restore = module.install_adapter(runtime_mcp, candidate)
    try:
        yield candidate
    finally:
        restore()


def _session(tmp_path, *, action="warn"):
    marker = tmp_path / "received.json"
    code = "\n".join(
        [
            "import json,sys",
            "from pathlib import Path",
            f"marker=Path({str(marker)!r})",
            "for line in sys.stdin:",
            " message=json.loads(line)",
            " method=message.get('method')",
            " result={}",
            " if method=='tools/list': result={'tools':[{'name':'safe_echo','inputSchema':{'type':'object'}}]}",
            " if method=='tools/call':",
            "  marker.write_text(json.dumps(message))",
            "  result={'content':[{'type':'text','text':'forwarded'}]}",
            " if 'id' in message: print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':result}),flush=True)",
        ]
    )
    context = HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / "guard")
    proxy = CodexMcpGuardProxy(
        server_name="synthetic",
        command=[sys.executable, "-u", "-c", code],
        context=context,
        store=GuardStore(context.guard_home),
        config=GuardConfig(guard_home=context.guard_home, workspace=tmp_path, default_action=action),
        source_scope="project",
        config_path=".mcp.json",
    )
    message = {
        "jsonrpc": "2.0",
        "id": "exact-id",
        "method": "tools/call",
        "params": {"name": "safe_echo", "arguments": {"nested": [False, 7, -0.0, None], "text": "ordinary"}},
    }
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {"elicitation": {}}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        message,
    ]
    return proxy, messages, marker


@pytest.mark.parametrize(
    ("first", "second"),
    [
        (True, 1),
        (1, 1.0),
        (0.0, -0.0),
        ([], ()),
        ({"a": 1, "b": 2}, {"b": 2, "a": 1}),
        ([[1], 2], [[1, 2]]),
        ("1", 1),
        ({"a": [1, 2]}, {"a": [2, 1]}),
    ],
)
def test_exact_binding_distinguishes_json_material(module, first, second):
    assert module._exact_binding(first) != module._exact_binding(second)


def test_binding_is_alias_independent_private_and_bounded(module, monkeypatch):
    child = {"text": "immutable-private-marker"}
    assert module._exact_binding([child, child]) == module._exact_binding([child, deepcopy(child)])
    request = module.OwnedPreparationPilot().own_request({"params": {"arguments": child}})
    assert request is not None
    assert request.owned_message["params"]["arguments"] is not child
    assert "immutable-private-marker" not in repr(request)
    cycle = []
    cycle.append(cycle)
    with pytest.raises((ValueError, RecursionError)):
        module._exact_binding(cycle)
    monkeypatch.setattr(module, "MAX_BINDING_BYTES", 64)
    with pytest.raises(ValueError, match="binding_limit"):
        module._exact_binding("x" * 100)


def test_custom_callbacks_never_enter_private_binding_or_owner(module):
    callbacks = []

    class Hostile:
        def __reduce_ex__(self, protocol):
            callbacks.append("reduce")
            raise AssertionError

        def __buffer__(self, flags):
            callbacks.append("buffer")
            raise AssertionError

    class CustomList(list, Hostile):
        def __iter__(self):
            callbacks.append("iterator")
            raise AssertionError

    class CustomDict(dict, Hostile):
        def items(self):
            callbacks.append("items")
            raise AssertionError

    for value in [Hostile(), CustomList([1]), CustomDict(a=1), type("S", (str, Hostile), {})("x")]:
        with pytest.raises(TypeError):
            module._exact_binding(value)
        assert module.OwnedPreparationPilot().own_request({"params": value}) is None
    assert callbacks == []
    for value in (float("nan"), float("inf"), {1: "non-string-key"}):
        assert module.OwnedPreparationPilot().own_request({"params": value}) is None


def test_actual_child_receives_the_owned_generation_once(tmp_path, monkeypatch, pilot):
    proxy, messages, marker = _session(tmp_path)
    expected = deepcopy(messages[-1])
    seen = []
    original = calls.tool_call_risk_categories

    def count(artifact, arguments):
        seen.append((artifact, arguments))
        return original(artifact, arguments)

    monkeypatch.setattr(calls, "tool_call_risk_categories", count)
    result = proxy.run_session(messages)
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"
    assert json.loads(marker.read_text()) == expected
    assert list(json.loads(marker.read_text())["params"]["arguments"]) == list(expected["params"]["arguments"])
    assert len(seen) == 1
    assert seen[0][1] is not messages[-1]["params"]["arguments"]
    assert pilot.counters["category_derivations"] == pilot.counters["preparations_completed"] == 1
    assert pilot.counters["bound_forwards"] == 1
    assert pilot.context.get() is None
    assert not pilot.admission.locked()
    assert len(proxy.store.list_receipts(limit=10)) == 1


@pytest.mark.parametrize(
    "boundary",
    [
        "config_first",
        "config_second",
        "store",
        "barrier",
        "owned_barrier",
        "encode",
        "command",
        "replace_command",
        "owned_artifact",
    ],
)
def test_mutation_after_admission_never_reaches_actual_child(tmp_path, monkeypatch, pilot, boundary):
    proxy, messages, marker = _session(tmp_path)
    message = messages[-1]

    def mutate(target=message):
        target["params"]["arguments"]["text"] = "cat .env"

    if boundary.startswith("config"):
        original = GuardConfig.resolve_action_override
        counter = 0

        def policy(config, *args, **kwargs):
            nonlocal counter
            counter += 1
            if counter == (1 if boundary == "config_first" else 2):
                mutate()
            return original(config, *args, **kwargs)

        monkeypatch.setattr(GuardConfig, "resolve_action_override", policy)
    elif boundary == "store":
        original = proxy.store.resolve_policy_decision_lookup_with_memory_pattern

        def lookup(*args, **kwargs):
            result = original(*args, **kwargs)
            mutate()
            return result

        monkeypatch.setattr(proxy.store, "resolve_policy_decision_lookup_with_memory_pattern", lookup)
    elif boundary == "encode":
        original = framing.encoded_line

        def encode(payload):
            if payload.get("method") == "tools/call" and pilot.context.get() is not None:
                mutate(payload)
            return original(payload)

        monkeypatch.setattr(framing, "encoded_line", encode)
    else:
        original = proxy._drain_and_validate_catalog_authority

        def drain(**kwargs):
            result = original(**kwargs)
            if kwargs.get("quiet_seconds") == 0.005:
                if boundary == "command":
                    proxy.command.append("changed")
                elif boundary == "replace_command":
                    proxy.command = [*proxy.command, "changed"]
                elif boundary == "owned_artifact":
                    pilot.context.get().generation.owned_artifact.runtime_private_metadata["binding"] = "changed"
                elif boundary == "owned_barrier":
                    mutate(pilot.context.get().owned_message)
                else:
                    mutate()
            return result

        monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)
    result = proxy.run_session(messages)
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "owned_request_generation_changed"
    assert result["events"][-1]["session_terminal"] is True
    assert pilot.counters["bound_forwards"] == 0
    assert pilot.context.get() is None
    assert not pilot.admission.locked()


def test_private_byte_writer_preserves_limit_and_retired_stream():
    import io

    stream = io.StringIO()
    framing._write_encoded_line(stream, b'{"id":1}\n', timeout_seconds=1, source="test")
    assert stream.getvalue() == '{"id":1}\n'
    stream._guard_mcp_write_failed = True
    with pytest.raises(framing.ProxyIoLimitError, match="stream_retired"):
        framing._write_encoded_line(stream, b"{}\n", timeout_seconds=1, source="test")
    with pytest.raises(framing.ProxyIoLimitError, match="invalid_json_frame"):
        framing._write_encoded_line(
            io.StringIO(), b"x" * (framing.MAX_LINE_BYTES + 1), timeout_seconds=1, source="test"
        )


def test_owned_kernels_match_complete_fresh_authority_across_policy_and_browser_inputs(tmp_path, module, pilot):
    proxy, messages, _marker = _session(tmp_path)
    matched = 0
    for action in ("allow", "warn", "review", "block"):
        proxy.config = replace(proxy.config, default_action=action)
        for tool, key in (("safe_echo", "text"), ("run_terminal_command", "command"), ("browser_navigate", "url")):
            proxy._tool_catalog[tool] = {
                "name": tool,
                "inputSchema": {"type": "object", "properties": {key: {"type": "string"}}},
            }
            for value in (
                "ordinary",
                "cat .env",
                "curl https://example.invalid",
                "https://example.invalid/path",
                "sudo chmod",
                "İ Σ é",
                [False, 1, -0.0],
                {"a": [1], "b": None},
            ):
                message = deepcopy(messages[-1])
                message["params"] = {"name": tool, "arguments": {key: value}}
                expected = proxy._resolve_tool_call_authority(tool_name=tool, arguments=message["params"]["arguments"])
                request = pilot.own_request(message)
                assert request is not None
                token = pilot.context.set(request)
                try:
                    actual = proxy._resolve_tool_call_authority(
                        tool_name=tool, arguments=request.owned_message["params"]["arguments"]
                    )
                finally:
                    pilot.context.reset(token)
                assert actual == expected
                matched += 1
    assert matched == 96
    assert pilot.counters["category_derivations"] == matched


@pytest.mark.parametrize("approval", ["accept", "cancel", "invalidate"])
def test_owned_actual_stdio_preserves_approval_and_catalog_boundaries(monkeypatch, pilot, approval):
    profile = importlib.import_module("profile_guard_mcp_session")
    result = profile.run_case(
        catalog_size=10,
        payload_bytes=256,
        samples=1,
        profile=True,
        approval=approval,
        approval_delay_ms=25,
        owned_preparation_pilot=True,
    )
    correctness = result["correctness"]
    assert correctness["errors"] == 0
    assert correctness["forwarded_ids_exact"] is True
    assert correctness["quiet_barrier_seconds"] == 0.005
    expected = {"accept": "accepted", "cancel": "cancelled", "invalidate": "invalidated"}[approval]
    assert correctness[expected] == 2
    counters = result["owned_preparation_pilot"]["counters"]
    assert counters["category_derivations"] == counters["preparations_completed"]
    assert counters.get("bound_forwards", 0) == correctness["accepted"]
    # This ordinary inline path performs no saved claim/rebuild. Facts are not
    # retained in _Generation; only its exact input binding reaches forwarding.
    assert counters["preparations_completed"] >= counters["requests_admitted"]


def test_owned_actual_stdio_rebuilds_facts_after_catalog_refresh(pilot):
    profile = importlib.import_module("profile_guard_mcp_session")
    result = profile.run_case(
        catalog_size=10, payload_bytes=1024, samples=2, profile=True, refresh_every=1, owned_preparation_pilot=True
    )
    assert result["correctness"]["accepted"] == 3
    assert len(result["correctness"]["catalog_generations"]) == 3
    assert result["exclusive_phases"]["classification"]["calls"] == 2
    assert result["owned_preparation_pilot"]["counters"]["category_derivations"] == 3


@pytest.mark.parametrize("mutate_before_claim", [False, True])
def test_actual_saved_claim_rebuilds_fresh_generation_and_checks_before_consumption(
    tmp_path, monkeypatch, pilot, mutate_before_claim
):
    proxy, messages, marker = _session(tmp_path, action="review")
    original_capture = proxy._capture_tools_catalog

    def capture(*args, **kwargs):
        result = original_capture(*args, **kwargs)
        authority = proxy._resolve_tool_call_authority(
            tool_name="safe_echo", arguments=messages[-1]["params"]["arguments"]
        )
        approval_id = proxy.store.record_local_once_approval(
            request_id="owned-exact-once",
            harness="codex",
            artifact_id=authority.artifact.artifact_id,
            artifact_hash=authority.artifact_hash,
            workspace=str(tmp_path),
            publisher=authority.artifact.publisher,
            action="allow",
            created_at="2026-07-17T00:00:00+00:00",
            expires_at="2027-07-17T00:00:00+00:00",
        )
        assert approval_id is not None
        return result

    monkeypatch.setattr(proxy, "_capture_tools_catalog", capture)
    monkeypatch.setattr(proxy, "_claim_boundary_config", lambda: proxy.config)
    original_claim = proxy.store.claim_approval_reuse_decisions
    claimed = []

    def claim(*args, **kwargs):
        claimed.append(True)
        return original_claim(*args, **kwargs)

    monkeypatch.setattr(proxy.store, "claim_approval_reuse_decisions", claim)
    if mutate_before_claim:
        original_drain = proxy._drain_and_validate_catalog_authority

        def drain(**kwargs):
            result = original_drain(**kwargs)
            if not kwargs.get("quiet_seconds") and pilot.context.get() is not None:
                messages[-1]["params"]["arguments"]["text"] = "cat .env"
            return result

        monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)
    result = proxy.run_session(messages)
    if mutate_before_claim:
        assert not marker.exists()
        assert claimed == []
        assert result["events"][-1]["reason_code"] == "owned_request_generation_changed"
    else:
        assert json.loads(marker.read_text()) == messages[-1]
        assert claimed == [True]
        assert pilot.counters["preparations_completed"] == 2
        assert pilot.counters["category_derivations"] == 2
        assert pilot.counters["bound_forwards"] == 1


@pytest.mark.parametrize("selection", ["owned", "busy", "unsupported", "package"])
def test_original_separate_inline_deadline_and_fallback_scope_are_preserved(tmp_path, monkeypatch, module, selection):
    proxy, messages, _marker = _session(tmp_path)
    clock = [100.0]
    monkeypatch.setattr(framing.time, "monotonic", lambda: clock[0])
    observed = []

    def read(**_kwargs):
        clock[0] += 45.0
        remaining = framing.remaining_timeout(120.0, source="inline_approval")
        assert remaining == 75.0
        return json.dumps({"id": "approval", "result": {"action": "accept"}})

    monkeypatch.setattr(proxy, "_read_client_during_wait", read)

    def serialized(_proxy, **kwargs):
        assert framing._BUDGET.get() is None
        reply = proxy._request_inline_approval(
            {"jsonrpc": "2.0", "id": "approval", "method": "elicitation/create", "params": {}},
            input_stream=io.StringIO(),
            output_stream=io.StringIO(),
            child_stdin=io.StringIO(),
            child_stdout=io.StringIO(),
        )
        assert reply["action"] == "accept"
        assert framing._BUDGET.get() is None
        observed.append(reply)
        return {"id": kwargs["message"]["id"], "result": {}}, {"decision": "fixture"}

    monkeypatch.setattr(runtime_mcp.RuntimeMcpGuardProxy, "_handle_message_serialized", serialized)
    candidate = module.OwnedPreparationPilot()
    restore = module.install_adapter(runtime_mcp, candidate)
    if selection == "busy":
        candidate.admission.acquire()
    elif selection == "unsupported":
        messages[-1]["params"]["arguments"]["text"] = float("nan")
    elif selection == "package":
        monkeypatch.setattr(proxy, "_package_request_artifact", lambda **_kwargs: object())
    try:
        proxy._handle_message_checked(
            message=messages[-1],
            child_stdin=io.StringIO(),
            child_stdout=io.StringIO(),
            client_input=None,
            server_output=None,
            approval_callback=None,
        )
    finally:
        restore()
        if selection == "busy":
            candidate.admission.release()
    assert len(observed) == 1
    assert clock[0] == 145.0


def test_mutation_after_completed_bound_write_does_not_replace_success_with_failure(tmp_path, monkeypatch, pilot):
    proxy, messages, marker = _session(tmp_path)
    expected = deepcopy(messages[-1])
    original = proxy._forward_message

    def forward(*args, **kwargs):
        response = original(*args, **kwargs)
        if marker.exists():
            messages[-1]["params"]["arguments"]["text"] = "changed after completed response"
        return response

    monkeypatch.setattr(proxy, "_forward_message", forward)
    result = proxy.run_session(messages)
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"
    assert json.loads(marker.read_text()) == expected
    assert pilot.counters["bound_forwards"] == 1


def test_legacy_custom_routing_fallback_adds_no_callback_invocations(tmp_path, monkeypatch, module):
    proxy, messages, _marker = _session(tmp_path)
    callbacks = []

    class Message(dict):
        def get(self, *args):
            callbacks.append("get")
            return super().get(*args)

    class Method(str):
        def __eq__(self, value):
            callbacks.append("equality")
            return super().__eq__(value)

    monkeypatch.setattr(
        runtime_mcp.RuntimeMcpGuardProxy, "_handle_message_serialized", lambda _self, **_kwargs: (None, {})
    )
    for message in (Message(messages[-1]), {**messages[-1], "method": Method("tools/call")}):
        kwargs = dict(
            message=message,
            child_stdin=io.StringIO(),
            child_stdout=io.StringIO(),
            client_input=None,
            server_output=None,
            approval_callback=None,
        )
        callbacks.clear()
        proxy._handle_message_checked(**kwargs)
        expected = list(callbacks)
        callbacks.clear()
        candidate = module.OwnedPreparationPilot()
        restore = module.install_adapter(runtime_mcp, candidate)
        try:
            proxy._handle_message_checked(**kwargs)
        finally:
            restore()
        assert callbacks == expected
        assert candidate.counters["requests_admitted"] == 0


@pytest.mark.parametrize("stage", ["during_case", "after_completed_case"])
def test_comparison_preserves_failed_attempts_and_completed_invalid_results(tmp_path, monkeypatch, module, stage):
    comparison = importlib.import_module("compare_guard_mcp_owned_preparation")
    identity = {"mcp_tool_calls.py": "frozen"}
    monkeypatch.setattr(comparison, "source_identity", lambda _root: identity)
    monkeypatch.setattr(comparison, "oracle_identity", lambda: identity)
    monkeypatch.setattr(comparison, "harness_identity", lambda: {"harness": "frozen"})
    monkeypatch.setattr(comparison, "performance_lock", lambda _path: nullcontext())
    monkeypatch.setattr(comparison, "verify_facts", lambda _root: {"cases": 3008})

    def case(**_kwargs):
        if stage == "during_case":
            raise comparison.BenchmarkCaseError(
                {"attempted_tool_requests": 3, "observed_tool_responses": 2, "observed_child_forwarded_count": 2}
            )
        return {"loaded_runtime_sha256": {"mcp_tool_calls.py": "wrong"}, "correctness": {"accepted": 4, "errors": 0}}

    monkeypatch.setattr(comparison, "run_case", case)
    args = Namespace(
        json=tmp_path / "attempts.json",
        baseline_src=tmp_path / "B",
        candidate_src=tmp_path / "E",
        lock_file=tmp_path / "lock",
        samples=3,
    )
    with pytest.raises((comparison.BenchmarkCaseError, RuntimeError)):
        comparison.run_comparison(args)
    report = json.loads(args.json.read_text())
    assert report["cases"] == []
    failed = report["failed_case"]
    if stage == "during_case":
        assert failed["attempted_tool_requests"] == 3
        assert failed["observed_tool_responses"] == 2
        assert failed["observed_child_forwarded_count"] == 2
    else:
        assert failed["completed_case_result"]["correctness"]["accepted"] == 4
        assert failed["measurement_valid"] is False
    with pytest.raises(ValueError, match="refuses_to_overwrite"):
        comparison.run_comparison(args)


def test_comparison_rejects_wrong_parent_oracle_before_credit_or_sampling(tmp_path, monkeypatch, module):
    comparison = importlib.import_module("compare_guard_mcp_owned_preparation")
    monkeypatch.setattr(comparison, "source_identity", lambda _root: {"mcp_tool_calls.py": "expected"})
    monkeypatch.setattr(comparison, "oracle_identity", lambda: {"mcp_tool_calls.py": "wrong-installed-copy"})
    monkeypatch.setattr(comparison, "performance_lock", lambda _path: nullcontext())
    monkeypatch.setattr(comparison, "verify_facts", lambda _root: pytest.fail("wrong oracle must never execute"))
    monkeypatch.setattr(comparison, "run_case", lambda **_kwargs: pytest.fail("wrong oracle must prevent timing"))
    args = Namespace(
        json=tmp_path / "wrong-oracle.json",
        baseline_src=tmp_path,
        candidate_src=tmp_path,
        lock_file=tmp_path / "lock",
        samples=3,
    )
    with pytest.raises(RuntimeError, match="wrong_candidate_source"):
        comparison.run_comparison(args)
    report = json.loads(args.json.read_text())
    assert report["cases"] == []
    assert "public_api_facts_parity" not in report
    assert report["public_oracle_loaded_sources_sha256"] == {"mcp_tool_calls.py": "wrong-installed-copy"}
