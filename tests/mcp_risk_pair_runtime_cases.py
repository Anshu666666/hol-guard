"""Actual stock authority-pair parity; counters do not replace production providers."""

from __future__ import annotations

import json
import signal
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePath
from types import FrameType

import pytest

from codex_plugin_scanner.guard import mcp_risk_pair_admission as admission_source
from codex_plugin_scanner.guard import mcp_risk_pair_profile as profile
from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy, runtime_mcp
from codex_plugin_scanner.guard.proxy.framing import ProxyIoLimitError
from codex_plugin_scanner.guard.store import GuardStore

_OBSERVATIONS: list[dict[str, int]] = []

def _stock_proxy(tmp_path: Path) -> CodexMcpGuardProxy:
    workspace = tmp_path.resolve()
    context = HarnessContext(
        home_dir=workspace,
        workspace_dir=workspace,
        guard_home=workspace / "guard",
    )
    proxy = CodexMcpGuardProxy(
        server_name="synthetic",
        command=[sys.executable, "-u", "-c", ""],
        context=context,
        store=GuardStore(context.guard_home),
        config=GuardConfig(
            guard_home=context.guard_home,
            workspace=workspace,
            protection_posture_explicit=False,
        ),
        source_scope="project",
        config_path="config",
    )
    proxy._tool_catalog["read_file"] = {
        "name": "read_file",
        "description": "read notes",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    }
    proxy._tool_catalog_state = "complete"
    # A missing/bootstrap-rejected profile on the supported host must fail,
    # rather than silently turn the stock positive into an uncached success.
    assert profile.DECLARATIONS is not None
    return proxy


@contextmanager
def _observations() -> Iterator[dict[str, int]]:
    providers = (
        (calls._tool_call_risk_category_set.__code__, vars(calls), "categories"),
        (calls.tool_call_risk_categories.__code__, vars(calls), "public_categories"),
        (calls._tool_call_risk_signals_for_categories.__code__, vars(calls), "signals"),
        (calls._tool_call_summary_for_signals.__code__, vars(calls), "summary"),
        (
            runtime_mcp.RuntimeMcpGuardProxy._check_tool_call_preparation.__code__,
            vars(runtime_mcp),
            "preparation",
        ),
    )
    factory_code = runtime_mcp.make_risk_pair_admission.__code__
    factory_globals = vars(admission_source)
    counts = dict.fromkeys((*[name for _, _, name in providers], "admitted"), 0)

    def observe(frame: FrameType, event: str, result: object) -> None:
        if event == "call":
            for code, provider_globals, name in providers:
                if frame.f_code is code and frame.f_globals is provider_globals:
                    counts[name] += 1
                    break
        elif (
            event == "return"
            and frame.f_code is factory_code
            and frame.f_globals is factory_globals
            and result is not None
        ):
            counts["admitted"] += 1

    previous = sys.getprofile()
    assert previous is None, "This finite observer must not replace another profiler."
    sys.setprofile(observe)
    try:
        yield counts
    finally:
        sys.setprofile(previous)
        _OBSERVATIONS.append(dict(counts))


def _resolve(proxy: CodexMcpGuardProxy, arguments: dict[str, object]):
    with _observations() as counts:
        result = proxy._resolve_tool_call_authority(tool_name="read_file", arguments=arguments)
    return result, counts


def _baseline(proxy: CodexMcpGuardProxy, monkeypatch: pytest.MonkeyPatch, arguments: dict[str, object]):
    # Run the unchanged consumers, including real policy/hash/store work.
    # This also warms real caches; no cache entries or declarations are forged.
    with monkeypatch.context() as patch:
        patch.setattr(runtime_mcp, "make_risk_pair_admission", lambda *_args: None)
        result, counts = _resolve(proxy, arguments)
    assert counts["categories"] == 2
    assert counts["signals"] == 1
    assert counts["preparation"] == 3
    return result


def _assert_stock_counts(counts: dict[str, int]) -> None:
    assert counts == {
        "categories": 1,
        "public_categories": 1,
        "signals": 1,
        "summary": 1,
        "preparation": 3,
        "admitted": 1,
    }


def case_stock_warm_pair_preserves_hash_complete_decision_and_summary(stock_proxy, monkeypatch):
    arguments = {"path": "notes"}
    expected = _baseline(stock_proxy, monkeypatch, arguments)
    actual, counts = _resolve(stock_proxy, arguments)
    _assert_stock_counts(counts)
    assert actual == expected
    assert actual.artifact_hash == expected.artifact_hash
    assert actual.decision.signals == expected.decision.signals
    assert actual.decision.summary == expected.decision.summary
    assert not hasattr(actual, "risk_facts")


def case_each_stock_invocation_derives_fresh_even_when_inputs_repeat(stock_proxy, monkeypatch):
    arguments = {"path": "notes"}
    expected = _baseline(stock_proxy, monkeypatch, arguments)
    for _ in range(2):
        actual, counts = _resolve(stock_proxy, arguments)
        _assert_stock_counts(counts)
        assert actual == expected
    arguments["path"] = "othernotes"
    changed_expected = _baseline(stock_proxy, monkeypatch, arguments)
    changed, counts = _resolve(stock_proxy, arguments)
    _assert_stock_counts(counts)
    assert changed == changed_expected
    assert changed.artifact_hash != expected.artifact_hash


def case_dotted_path_retains_actual_ip_extraction_fallback(stock_proxy, monkeypatch):
    arguments = {"path": "notes.txt"}
    expected = _baseline(stock_proxy, monkeypatch, arguments)
    actual, counts = _resolve(stock_proxy, arguments)
    assert actual == expected
    assert counts["categories"] == 2
    assert counts["signals"] == 1
    assert counts["preparation"] == 3


def case_opaque_public_wrapper_preserves_two_original_consumers(stock_proxy, monkeypatch, boundary):
    arguments = {"path": "notes"}
    expected = _baseline(stock_proxy, monkeypatch, arguments)
    owners = {
        "hash": (runtime_mcp, "build_tool_call_hash"),
        "evaluator": (runtime_mcp, "evaluate_tool_call"),
        "categories": (calls, "tool_call_risk_categories"),
        "config": (GuardConfig, "resolve_action_override"),
    }
    owner, name = owners[boundary]
    original = getattr(owner, name)
    invoked = []

    def opaque(*args, **kwargs):
        invoked.append(boundary)
        return original(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(owner, name, opaque)
        actual, counts = _resolve(stock_proxy, arguments)
    assert actual == expected
    assert invoked
    assert counts["categories"] == 2
    assert counts["signals"] == 1
    assert counts["preparation"] == 3
    restored, restored_counts = _resolve(stock_proxy, arguments)
    _assert_stock_counts(restored_counts)
    assert restored == expected


def _policy_mutation_scenario(proxy, monkeypatch, *, enabled):
    original = GuardConfig.resolve_action_override
    original_name = PurePath.name
    arguments = {"path": "notes"}
    with monkeypatch.context() as patch:
        if not enabled:
            patch.setattr(runtime_mcp, "make_risk_pair_admission", lambda *_args: None)

        def policy(config, *args, **kwargs):
            result = original(config, *args, **kwargs)
            patch.setattr(PurePath, "name", property(lambda _path: "rm"))
            return result

        patch.setattr(GuardConfig, "resolve_action_override", policy)
        changed, counts = _resolve(proxy, arguments)
        patch.setattr(GuardConfig, "resolve_action_override", original)
        # Restoring the opaque method does not restore its persistent mutation.
        later, later_counts = _resolve(proxy, arguments)
        assert PurePath.name is not original_name
    return changed, counts, later, later_counts


def case_opaque_policy_mutation_and_later_restored_method_match_original(stock_proxy, monkeypatch):
    _baseline(stock_proxy, monkeypatch, {"path": "notes"})
    baseline = _policy_mutation_scenario(stock_proxy, monkeypatch, enabled=False)
    candidate = _policy_mutation_scenario(stock_proxy, monkeypatch, enabled=True)
    for actual, expected in ((candidate[0], baseline[0]), (candidate[2], baseline[2])):
        assert actual == expected
        assert "destructive_mutation" in actual.decision.risk_categories
        assert actual.decision.action != "allow"
    assert [candidate[1]["categories"], candidate[3]["categories"]] == [2, 2]


def _decision_mutation_scenario(proxy, monkeypatch, *, enabled):
    original = calls.ToolCallDecision.__init__
    arguments = {"path": "notes"}
    with monkeypatch.context() as patch:
        if not enabled:
            patch.setattr(runtime_mcp, "make_risk_pair_admission", lambda *_args: None)

        def construct(decision, *args, **kwargs):
            original(decision, *args, **kwargs)
            patch.setattr(PurePath, "name", property(lambda _path: "rm"))

        patch.setattr(calls.ToolCallDecision, "__init__", construct)
        first, first_counts = _resolve(proxy, arguments)
        patch.setattr(calls.ToolCallDecision, "__init__", original)
        later, later_counts = _resolve(proxy, arguments)
    return first, first_counts, later, later_counts


def case_post_consumption_constructor_mutation_cannot_supply_next_call_facts(stock_proxy, monkeypatch):
    _baseline(stock_proxy, monkeypatch, {"path": "notes"})
    baseline = _decision_mutation_scenario(stock_proxy, monkeypatch, enabled=False)
    candidate = _decision_mutation_scenario(stock_proxy, monkeypatch, enabled=True)
    assert candidate[0] == baseline[0]
    assert candidate[2] == baseline[2]
    assert candidate[1]["categories"] == 1
    assert baseline[1]["categories"] == 2
    assert candidate[3]["categories"] == baseline[3]["categories"] == 2
    assert "destructive_mutation" in candidate[2].decision.risk_categories
    assert candidate[2].decision.action != "allow"


def case_constructor_failure_is_original_and_restored_next_call_is_fresh(stock_proxy, monkeypatch, enabled):
    arguments = {"path": "notes"}
    expected = _baseline(stock_proxy, monkeypatch, arguments)
    failure = RuntimeError("original decision-constructor failure")

    def construct(_decision, *_args, **_kwargs):
        raise failure

    with monkeypatch.context() as patch:
        if not enabled:
            patch.setattr(runtime_mcp, "make_risk_pair_admission", lambda *_args: None)
        patch.setattr(calls.ToolCallDecision, "__init__", construct)
        with _observations() as counts, pytest.raises(RuntimeError) as caught:
            stock_proxy._resolve_tool_call_authority(tool_name="read_file", arguments=arguments)
        assert caught.value is failure
        assert counts["categories"] == (1 if enabled else 2)
    actual, restored_counts = _resolve(stock_proxy, arguments)
    _assert_stock_counts(restored_counts)
    assert actual == expected


def case_argument_change_still_hits_original_authority_fence(stock_proxy, monkeypatch, enabled):
    _baseline(stock_proxy, monkeypatch, {"path": "notes"})
    arguments = {"path": "notes"}
    original = GuardConfig.resolve_action_override

    def policy(config, *args, **kwargs):
        result = original(config, *args, **kwargs)
        arguments["path"] = "changed"
        return result

    with monkeypatch.context() as patch:
        if not enabled:
            patch.setattr(runtime_mcp, "make_risk_pair_admission", lambda *_args: None)
        patch.setattr(GuardConfig, "resolve_action_override", policy)
        with _observations() as counts, pytest.raises(ProxyIoLimitError) as caught:
            stock_proxy._resolve_tool_call_authority(tool_name="read_file", arguments=arguments)
    assert caught.value.reason == "tool_call_authority_changed"
    assert counts["categories"] == 1

def run_case(name: str, root: Path) -> None:
    """Run one actual scenario without inheriting pytest's signal handlers."""
    assert __debug__
    assert sys.getprofile() is None
    before_signals = tuple(signal.getsignal(number) for number in signal.valid_signals())
    proxy = _stock_proxy(root)
    patch = pytest.MonkeyPatch()
    cases = {
        "stock": (case_stock_warm_pair_preserves_hash_complete_decision_and_summary, ()),
        "fresh": (case_each_stock_invocation_derives_fresh_even_when_inputs_repeat, ()),
        "dotted-fallback": (case_dotted_path_retains_actual_ip_extraction_fallback, ()),
        "opaque-hash": (case_opaque_public_wrapper_preserves_two_original_consumers, ("hash",)),
        "opaque-evaluator": (case_opaque_public_wrapper_preserves_two_original_consumers, ("evaluator",)),
        "opaque-categories": (case_opaque_public_wrapper_preserves_two_original_consumers, ("categories",)),
        "opaque-config": (case_opaque_public_wrapper_preserves_two_original_consumers, ("config",)),
        "policy-mutation": (case_opaque_policy_mutation_and_later_restored_method_match_original, ()),
        "constructor-mutation": (case_post_consumption_constructor_mutation_cannot_supply_next_call_facts, ()),
        "constructor-failure-baseline": (
            case_constructor_failure_is_original_and_restored_next_call_is_fresh,
            (False,),
        ),
        "constructor-failure-candidate": (
            case_constructor_failure_is_original_and_restored_next_call_is_fresh,
            (True,),
        ),
        "authority-baseline": (case_argument_change_still_hits_original_authority_fence, (False,)),
        "authority-candidate": (case_argument_change_still_hits_original_authority_fence, (True,)),
    }
    scenario, arguments = cases[name]
    try:
        scenario(proxy, patch, *arguments)
    finally:
        patch.undo()
    after_signals = tuple(signal.getsignal(number) for number in signal.valid_signals())
    assert before_signals == after_signals
    assert sys.getprofile() is None
    print(
        json.dumps(
            {
                "case": name,
                "status": "passed",
                "python": list(sys.version_info[:3]),
                "profile_loaded": profile.DECLARATIONS is not None,
                "signal_handlers": [repr(handler) for handler in before_signals],
                "signals_unchanged": True,
                "observations": _OBSERVATIONS,
            },
            sort_keys=True,
        )
    )
