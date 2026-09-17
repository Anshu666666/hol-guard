"""Exact stream comparison and retained authority witnesses for inactive F."""

from __future__ import annotations

import importlib
import io
import json
from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.proxy import framing, runtime_mcp
from tests import test_mcp_owned_preparation_pilot as retained

_session = retained._session
test_actual_forward = retained.test_actual_child_receives_the_owned_generation_once
test_saved_claim = retained.test_actual_saved_claim_rebuilds_fresh_generation_and_checks_before_consumption
test_alias_binding = retained.test_binding_is_alias_independent_private_and_bounded
test_custom_callbacks = retained.test_custom_callbacks_never_enter_private_binding_or_owner
test_type_identity = retained.test_exact_binding_distinguishes_json_material
test_custom_routing = retained.test_legacy_custom_routing_fallback_adds_no_callback_invocations
test_admission_mutation = retained.test_mutation_after_admission_never_reaches_actual_child
test_completed_forward_mutation = (
    retained.test_mutation_after_completed_bound_write_does_not_replace_success_with_failure
)
test_original_deadlines = retained.test_original_separate_inline_deadline_and_fallback_scope_are_preserved
test_authority_browser_parity = (
    retained.test_owned_kernels_match_complete_fresh_authority_across_policy_and_browser_inputs
)


# Run the unchanged predicates against F's module and adapter. The old external
# profile worker explicitly installs E, so those profile/campaign tests are not
# re-exported here or credited as F coverage.
@pytest.fixture
def module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("guard_mcp_streaming_preparation_pilot")


@pytest.fixture
def pilot(module):
    candidate = module.OwnedPreparationPilot()
    restore = module.install_adapter(runtime_mcp, candidate)
    try:
        yield candidate
    finally:
        restore()


@pytest.mark.parametrize("width", [1, 2, 3, 7, 16, 64])
def test_comparison_does_not_depend_on_chunk_boundaries(module, width):
    reference = b"finite exact comparison, including \x00 and \xff"
    for candidate in (reference, reference[:-1], reference + b"x", b"x" + reference[1:]):
        output = module._BindingComparator(reference)
        for offset in range(0, len(candidate), width):
            assert output.write(candidate[offset : offset + width]) == len(candidate[offset : offset + width])
            assert output.write(b"") == 0
        assert output.matches() is (candidate == reference)
        assert output.position == len(candidate)
        assert output.reference is reference
        assert not hasattr(output, "__dict__")


def test_streamed_bindings_match_frozen_e_for_strict_values_without_a_new_buffer(module, monkeypatch):
    original = importlib.import_module("guard_mcp_owned_preparation_pilot")
    shared = {"text": "shared"}
    values = [
        None,
        False,
        True,
        0,
        1,
        1.0,
        -0.0,
        0.0,
        "",
        "İ Σ é €",
        "x" * 131072,
        [0] * 65536,
        [shared, shared],
        [shared, deepcopy(shared)],
        {"a": [1], "b": None},
        {"b": None, "a": [1]},
    ]
    references = [original._exact_binding(value) for value in values]

    def forbidden_buffer():
        pytest.fail("freshness comparison must not allocate a complete binding buffer")

    monkeypatch.setattr(module, "_BindingBuffer", forbidden_buffer)
    for value, reference in zip(values, references, strict=True):
        assert module._binding_matches(value, reference)
        assert not module._binding_matches(value, reference[:-1])
        assert not module._binding_matches(value, reference + b"\x00")
    for left, right in ((False, 0), (True, 1), (1, 1.0), (0.0, -0.0), ({"a": 1, "b": 2}, {"b": 2, "a": 1})):
        assert not module._binding_matches(left, original._exact_binding(right))


def test_streamed_comparison_keeps_limits_cycles_and_custom_rejection(module, monkeypatch):
    callbacks = []

    class Hostile:
        def __reduce_ex__(self, _protocol):
            callbacks.append("reduce")
            raise AssertionError

        def __buffer__(self, _flags):
            callbacks.append("buffer")
            raise AssertionError

    class CustomBytes(bytes):
        def __len__(self):
            callbacks.append("length")
            raise AssertionError

    # A prior byte mismatch must not skip rejection of later custom material.
    with pytest.raises(TypeError, match="custom_input"):
        module._binding_matches(["x" * 131072, Hostile()], b"mismatch")
    for target in (
        lambda: module._BindingComparator(CustomBytes(b"x")),
        lambda: module._BindingComparator(b"x").write(CustomBytes(b"x")),
    ):
        with pytest.raises(TypeError, match="custom_binding"):
            target()
    cycle = []
    cycle.append(cycle)
    with pytest.raises((ValueError, RecursionError)):
        module._binding_matches(cycle, b"not a cycle")
    assert callbacks == []
    monkeypatch.setattr(module, "MAX_BINDING_BYTES", 64)
    with pytest.raises(ValueError, match="binding_limit"):
        module._BindingComparator(b"x" * 65)
    output = module._BindingComparator(b"x" * 64)
    assert output.write(b"x" * 64) == 64
    assert output.matches()
    with pytest.raises(ValueError, match="binding_limit"):
        output.write(b"x")
    with pytest.raises(ValueError, match="binding_limit"):
        module._binding_matches("x" * 100, b"mismatch")


def test_only_three_retained_bindings_are_created_for_a_complete_forward(tmp_path, monkeypatch, module, pilot):
    proxy, messages, marker = _session(tmp_path)
    created = []
    compared = []
    original_binding = module._exact_binding
    original_compare = module._binding_matches

    def binding(value):
        created.append(type(value).__name__)
        return original_binding(value)

    def compare(value, reference):
        compared.append(type(value).__name__)
        return original_compare(value, reference)

    monkeypatch.setattr(module, "_exact_binding", binding)
    monkeypatch.setattr(module, "_binding_matches", compare)
    result = proxy.run_session(messages)
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"
    assert json.loads(marker.read_text()) == messages[-1]
    assert created == ["dict", "tuple", "list"]
    assert compared.count("dict") >= 3  # Original, owner and actual decoded wire.
    assert pilot.counters["bound_forwards"] == 1


def test_aba_during_final_encoding_rejects_changed_wire_after_owner_is_restored(tmp_path, monkeypatch, pilot):
    proxy, messages, marker = _session(tmp_path)
    original_encoder = framing.encoded_line
    changed_wires = []

    def encode(payload):
        if payload.get("method") != "tools/call" or pilot.context.get() is None:
            return original_encoder(payload)
        arguments = payload["params"]["arguments"]
        before = arguments["text"]
        try:
            arguments["text"] = "cat .env"
            encoded = original_encoder(payload)
            changed_wires.append(True)
            return encoded
        finally:
            arguments["text"] = before

    monkeypatch.setattr(framing, "encoded_line", encode)
    result = proxy.run_session(messages)
    assert changed_wires == [True]
    assert messages[-1]["params"]["arguments"]["text"] == "ordinary"
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "owned_request_generation_changed"
    assert result["events"][-1]["session_terminal"] is True
    assert pilot.counters["bound_forwards"] == 0


@pytest.mark.parametrize("custom_method", [False, True])
def test_owned_method_change_at_quiet_barrier_cannot_bypass_final_binding(tmp_path, monkeypatch, pilot, custom_method):
    proxy, messages, marker = _session(tmp_path)
    # Record any unexpected request method, not just tools/call, so the fixture
    # can distinguish rejection from forwarding a method it did not recognize.
    proxy.command[-1] = proxy.command[-1].replace(
        "if method=='tools/call':", "if method not in {'initialize', 'tools/list'}:"
    )
    callbacks = []

    class HostileMethod(str):
        def __eq__(self, other):
            callbacks.append("equality")
            raise AssertionError

        def __ne__(self, other):
            callbacks.append("inequality")
            raise AssertionError

        def __reduce_ex__(self, protocol):
            callbacks.append("reduce")
            raise AssertionError

    original_drain = proxy._drain_and_validate_catalog_authority

    def drain(**kwargs):
        result = original_drain(**kwargs)
        if kwargs.get("quiet_seconds") == 0.005:
            request = pilot.context.get()
            request.owned_message["method"] = HostileMethod("roots/list") if custom_method else "roots/list"
        return result

    monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)
    result = proxy.run_session(messages)
    assert callbacks == []
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "owned_request_generation_changed"
    assert result["events"][-1]["session_terminal"] is True
    assert pilot.counters["bound_forwards"] == 0


def test_unrelated_child_replies_and_notifications_preserve_their_existing_writer(tmp_path, pilot):
    proxy, messages, _marker = _session(tmp_path)
    request = pilot.own_request(messages[-1])
    assert request is not None and request.generation is None
    stream = io.StringIO()
    forwarded = [
        {"jsonrpc": "2.0", "id": "nested-response", "result": {"method": "tools/call"}},
        {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}},
    ]
    token = pilot.context.set(request)
    try:
        for message in forwarded:
            proxy._forward_notification(message, stream)
            assert pilot.context.get() is request
    finally:
        pilot.context.reset(token)
    assert [json.loads(line) for line in stream.getvalue().splitlines()] == forwarded
    assert pilot.counters["bound_forwards"] == 0


@pytest.mark.parametrize("inner_raises", [False, True])
def test_nested_handle_uses_b_and_restores_outer_context_and_admission(tmp_path, monkeypatch, module, inner_raises):
    proxy, messages, _marker = _session(tmp_path)
    nested = deepcopy(messages[-1])
    nested["id"] = "nested-call"
    candidate = module.OwnedPreparationPilot()
    observed = []
    original_authority_calls = []
    sentinel = object()

    def original_authority(_proxy, **kwargs):
        assert candidate.context.get() is None
        original_authority_calls.append(True)
        return sentinel

    def serialized(_proxy, *, message, **kwargs):
        if message["id"] == "nested-call":
            assert candidate.context.get() is None
            assert candidate.admission.locked()
            assert proxy._evaluate_tool_call_authority(artifact=None, arguments={}, config=proxy.config) is sentinel
            observed.append("inner_b")
            if inner_raises:
                raise RuntimeError("nested_fixture_failure")
            return {"id": message["id"], "result": {}}, {}
        outer = candidate.context.get()
        assert outer is not None and message is outer.owned_message
        assert candidate.admission.locked()
        observed.append("outer_before")
        if inner_raises:
            with pytest.raises(RuntimeError, match="nested_fixture_failure"):
                proxy._handle_message_checked(message=nested, **kwargs)
        else:
            response, _event = proxy._handle_message_checked(message=nested, **kwargs)
            assert response["id"] == "nested-call"
        assert candidate.context.get() is outer
        assert candidate.admission.locked()
        observed.append("outer_after")
        return {"id": message["id"], "result": {}}, {}

    monkeypatch.setattr(runtime_mcp.RuntimeMcpGuardProxy, "_evaluate_tool_call_authority", original_authority)
    monkeypatch.setattr(runtime_mcp.RuntimeMcpGuardProxy, "_handle_message_serialized", serialized)
    restore = module.install_adapter(runtime_mcp, candidate)
    try:
        response, _event = proxy._handle_message_checked(
            message=messages[-1],
            child_stdin=io.StringIO(),
            child_stdout=io.StringIO(),
            client_input=None,
            server_output=None,
            approval_callback=None,
        )
    finally:
        restore()
    assert response["id"] == messages[-1]["id"]
    assert observed == ["outer_before", "inner_b", "outer_after"]
    assert original_authority_calls == [True]
    assert candidate.counters["requests_admitted"] == 1
    assert candidate.counters["busy_fallback"] == 1
    assert candidate.context.get() is None
    assert not candidate.admission.locked()
