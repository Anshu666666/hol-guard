"""Finite failure diagnostics; no native execution or enrollment is represented."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.native_runtime import probe_installed_consumer_readiness as probe
from codex_plugin_scanner.guard.policy_rule_identity import PolicyRuleIdentity


def test_matching_rule_preserves_success_without_failure_observation() -> None:
    diagnostics: dict[str, object] = {"passed": False}
    selected = PolicyRuleIdentity("synthetic.policy", "synthetic.profile.block.pwd", "1")
    probe._require_profile_rule(
        selected,
        selected.rule_id,
        command_ordinal=1,
        effect="block",
        decision="deny",
        policy_action="block",
        failure_diagnostics=diagnostics,
    )
    assert diagnostics == {"passed": False}


@pytest.mark.parametrize("selected_present", [False, True])
def test_missing_or_wrong_rule_keeps_original_failure_and_only_fixed_fields(selected_present: bool) -> None:
    diagnostics: dict[str, object] = {}
    selected = PolicyRuleIdentity("PRIVATE_POLICY", "PRIVATE_RULE", "8") if selected_present else None
    with pytest.raises(probe.ProbeError, match=r"^profile_rule_not_causal$"):
        probe._require_profile_rule(
            selected,
            "PRIVATE_EXPECTED_RULE",
            command_ordinal=3,
            effect="review",
            decision="deny",
            policy_action="review",
            failure_diagnostics=diagnostics,
        )
    assert diagnostics == {
        "profile_rule_observation": {
            "command_ordinal": 3,
            "expected_effect": "review",
            "observed_decision": "deny",
            "observed_policy_action": "review",
            "selected_rule_present": selected_present,
            "selected_rule_matches": False,
        }
    }
    assert "PRIVATE" not in json.dumps(diagnostics)


@pytest.mark.parametrize("ordinal", [True, 0, 4, "PRIVATE_COMMAND", None])
def test_unknown_values_are_not_coerced_or_serialized(ordinal: object) -> None:
    class Hostile:
        def __str__(self) -> str:
            raise AssertionError("must not stringify")

        def __eq__(self, other: object) -> bool:
            raise AssertionError("must not compare non-string diagnostic values")

    diagnostics: dict[str, object] = {}
    with pytest.raises(probe.ProbeError, match=r"^profile_rule_not_causal$"):
        probe._require_profile_rule(
            None,
            "PRIVATE_EXPECTED_RULE",
            command_ordinal=ordinal,
            effect="PRIVATE_EFFECT",
            decision=Hostile(),
            policy_action={"PRIVATE_PATH": "PRIVATE_TOKEN"},
            failure_diagnostics=diagnostics,
        )
    assert diagnostics == {
        "profile_rule_observation": {
            "command_ordinal": None,
            "expected_effect": None,
            "observed_decision": None,
            "observed_policy_action": None,
            "selected_rule_present": False,
            "selected_rule_matches": False,
        }
    }
    assert "PRIVATE" not in json.dumps(diagnostics)


@pytest.mark.parametrize("matches", [False, True])
def test_main_retains_failure_only_observation_in_json_with_controlled_native_ports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, matches: bool, capsys: pytest.CaptureFixture[str]
) -> None:
    """Run real report serialization with explicit synthetic prerequisite ports."""
    source_sha = "a" * 40
    output = tmp_path / "report.json"
    monkeypatch.setattr(probe.sys, "argv", ["probe", "--json", str(output), "--expected-source-sha", source_sha])
    monkeypatch.setattr(probe.codex_plugin_scanner, "__file__", "/tmp/site-packages/synthetic/__init__.py")
    monkeypatch.setattr(probe, "environment_is_clean", lambda _environment: True)
    monkeypatch.setattr(probe, "native_mode", lambda: "auto")
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    monkeypatch.setattr(
        probe,
        "native_runtime_status",
        lambda: SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(sha256="b" * 64, path=Path("/synthetic/unexecuted-native")),
            capabilities=SimpleNamespace(build_sha=source_sha),
        ),
    )

    def controlled_exercise(
        _root: Path, _runtime: Path, *, failure_diagnostics: dict[str, object]
    ) -> dict[str, object]:
        expected = "PRIVATE_EXPECTED_RULE"
        selected = PolicyRuleIdentity("PRIVATE_POLICY", expected, "1") if matches else None
        probe._require_profile_rule(
            selected,
            expected,
            command_ordinal=1,
            effect="block",
            decision="deny",
            policy_action="block",
            failure_diagnostics=failure_diagnostics,
        )
        return {"controlled_exercise": True}

    monkeypatch.setattr(probe, "exercise", controlled_exercise)
    assert probe.main() == (0 if matches else 1)
    report = json.loads(output.read_text())
    stdout = capsys.readouterr().out
    assert json.loads(stdout) == report
    assert report["passed"] is matches
    assert ("profile_rule_observation" in report) is not matches
    if not matches:
        assert report["failure"] == "profile_rule_not_causal"
        assert report["profile_rule_observation"]["selected_rule_present"] is False
    assert "PRIVATE" not in stdout
    assert "unexecuted-native" not in stdout


def test_exact_original_assertion_exception_and_cleanup_are_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    original = probe.ProbeError("profile_rule_not_causal")
    calls: list[object] = []

    def require(condition: object, code: str) -> None:
        calls.append((condition, code))
        raise original

    def cleanup() -> None:
        calls.append("cleanup")
        raise RuntimeError("PRIVATE_CLEANUP_MESSAGE")

    monkeypatch.setattr(probe, "require", require)
    diagnostics: dict[str, object] = {}
    with pytest.raises(probe.ProbeError) as caught, probe.cleanup_preserving_failure(cleanup):
        probe._require_profile_rule(
            None,
            "PRIVATE_EXPECTED_RULE",
            command_ordinal=2,
            effect="allow",
            decision="allow",
            policy_action="allow",
            failure_diagnostics=diagnostics,
        )
    assert caught.value is original
    assert calls == [(False, "profile_rule_not_causal"), "cleanup"]
    observation = diagnostics["profile_rule_observation"]
    assert isinstance(observation, dict)
    assert observation["command_ordinal"] == 2
    assert observation["observed_decision"] == "allow"
    assert "PRIVATE" not in json.dumps(diagnostics)
