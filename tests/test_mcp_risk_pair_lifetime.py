"""Private-pair lifetime controls; these do not prove callable admission."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.mcp_risk_pair import (
    arm_risk_pair_policy,
    categories_for_current_policy,
    categories_for_hash,
    risk_pair_policy_scope,
    use_risk_pair,
)


class _Admission:
    def __init__(self):
        self.valid = True
        self.error = None

    def check(self):
        if self.error is not None:
            raise self.error
        return self.valid


def _deriver():
    seen = []

    def derive():
        result = ("category-" + str(len(seen)),)
        seen.append(result)
        return result

    return derive, seen


def _policy(artifact, arguments, derive):
    with risk_pair_policy_scope():
        return categories_for_current_policy(artifact, arguments, derive)


def test_supported_pair_consumes_once_then_expires_before_later_callbacks():
    artifact, arguments = object(), {}
    derive, seen = _deriver()
    with use_risk_pair(_Admission(), artifact, arguments):
        first = categories_for_hash(artifact, arguments, derive)
        arm_risk_pair_policy()
        assert _policy(artifact, arguments, derive) is first
        assert seen == [first]
        assert _policy(artifact, arguments, derive) is not first
        assert len(seen) == 2
    assert categories_for_hash(artifact, arguments, derive) is seen[-1]
    assert len(seen) == 3


def test_unsupported_scope_keeps_both_derivations():
    artifact, arguments = object(), {}
    derive, seen = _deriver()
    with use_risk_pair(None, artifact, arguments):
        categories_for_hash(artifact, arguments, derive)
        arm_risk_pair_policy()
        _policy(artifact, arguments, derive)
    assert len(seen) == 2


@pytest.mark.parametrize("changed", ["admission", "artifact", "arguments"])
def test_changed_pair_uses_live_second_derivation(changed):
    artifact, arguments = object(), {}
    admission = _Admission()
    derive, seen = _deriver()
    with use_risk_pair(admission, artifact, arguments):
        categories_for_hash(artifact, arguments, derive)
        arm_risk_pair_policy()
        if changed == "admission":
            admission.valid = False
        elif changed == "artifact":
            artifact = object()
        else:
            arguments = {}
        assert _policy(artifact, arguments, derive) == ("category-1",)
    assert len(seen) == 2


def test_same_input_direct_policy_during_hashing_does_not_consume_outer_pair():
    artifact, arguments = object(), {}
    derive, seen = _deriver()
    with use_risk_pair(_Admission(), artifact, arguments):
        first = categories_for_hash(artifact, arguments, derive)
        # A callback inside hashing can re-enter a public/private evaluator
        # before the intended runtime caller arms its policy phase.
        assert _policy(artifact, arguments, derive) != first
        arm_risk_pair_policy()
        assert _policy(artifact, arguments, derive) is first
    assert len(seen) == 2


def test_same_input_nested_policy_cannot_consume_outer_pair():
    artifact, arguments = object(), {}
    derive, seen = _deriver()
    with use_risk_pair(_Admission(), artifact, arguments):
        first = categories_for_hash(artifact, arguments, derive)
        arm_risk_pair_policy()
        with risk_pair_policy_scope():
            assert _policy(artifact, arguments, derive) != first
            assert categories_for_current_policy(artifact, arguments, derive) is first
    assert len(seen) == 2


@pytest.mark.parametrize("nested_admitted", [False, True])
def test_nested_runtime_scope_restores_outer_after_exception(nested_admitted):
    artifact, arguments = object(), {}
    derive, seen = _deriver()
    with use_risk_pair(_Admission(), artifact, arguments):
        outer = categories_for_hash(artifact, arguments, derive)
        with pytest.raises(LookupError, match="nested"):
            with use_risk_pair(_Admission() if nested_admitted else None, artifact, arguments):
                categories_for_hash(artifact, arguments, derive)
                raise LookupError("nested")
        arm_risk_pair_policy()
        assert _policy(artifact, arguments, derive) is outer
    assert len(seen) == 2


def test_repeated_first_consumer_invalidates_the_pair():
    artifact, arguments = object(), {}
    derive, seen = _deriver()
    with use_risk_pair(_Admission(), artifact, arguments):
        categories_for_hash(artifact, arguments, derive)
        categories_for_hash(artifact, arguments, derive)
        arm_risk_pair_policy()
        _policy(artifact, arguments, derive)
    assert len(seen) == 3


@pytest.mark.parametrize("stage", ["first", "second"])
def test_admission_exception_propagates_and_scope_is_retired(stage):
    artifact, arguments = object(), {}
    admission = _Admission()
    derive, seen = _deriver()
    with pytest.raises(LookupError, match="authority changed"):
        with use_risk_pair(admission, artifact, arguments):
            if stage == "first":
                admission.error = LookupError("authority changed")
            categories_for_hash(artifact, arguments, derive)
            arm_risk_pair_policy()
            admission.error = LookupError("authority changed")
            _policy(artifact, arguments, derive)
    previous = len(seen)
    categories_for_hash(artifact, arguments, derive)
    assert len(seen) == previous + 1


def test_derivation_exception_cannot_leave_a_reusable_result():
    artifact, arguments = object(), {}
    derive, seen = _deriver()

    def fail():
        raise LookupError("derivation")

    with use_risk_pair(_Admission(), artifact, arguments):
        with pytest.raises(LookupError, match="derivation"):
            categories_for_hash(artifact, arguments, fail)
        arm_risk_pair_policy()
        assert _policy(artifact, arguments, derive) == ("category-0",)
    assert len(seen) == 1


@pytest.mark.parametrize("reentry", ["hash", "arm"])
def test_second_admission_reentry_cannot_resurrect_a_retired_pair(reentry):
    artifact, arguments = object(), {}
    derive, seen = _deriver()

    class ReentrantAdmission:
        def __init__(self):
            self.calls = 0

        def check(self):
            self.calls += 1
            if self.calls == 2:
                if reentry == "hash":
                    categories_for_hash(artifact, arguments, derive)
                else:
                    arm_risk_pair_policy()
            return True

    with use_risk_pair(ReentrantAdmission(), artifact, arguments):
        first = categories_for_hash(artifact, arguments, derive)
        assert len(seen) == (2 if reentry == "hash" else 1)
        arm_risk_pair_policy()
        current = _policy(artifact, arguments, derive)
        assert current is not first
        assert len(seen) == (3 if reentry == "hash" else 2)


def test_initial_refusal_retires_observation_before_fallback_derivation():
    artifact, arguments = object(), {}
    events = []
    admission = _Admission()
    admission.valid = False

    def derive():
        events.append("derive")
        assert events[0] == "retire"
        return ("live",)

    with use_risk_pair(admission, artifact, arguments, on_retire=lambda: events.append("retire")):
        assert categories_for_hash(artifact, arguments, derive) == ("live",)
        arm_risk_pair_policy()
        assert _policy(artifact, arguments, derive) == ("live",)
    assert events == ["retire", "derive", "derive"]


@pytest.mark.parametrize("supported", [False, True])
def test_observation_stops_before_second_result_or_fallback(supported):
    artifact, arguments = object(), {}
    events = []
    admission = _Admission()

    def derive():
        events.append("derive")
        return ("live",)

    with use_risk_pair(admission, artifact, arguments, on_retire=lambda: events.append("retire")):
        first = categories_for_hash(artifact, arguments, derive)
        arm_risk_pair_policy()
        admission.valid = supported
        result = _policy(artifact, arguments, derive)
        assert events == (["derive", "retire"] if supported else ["derive", "retire", "derive"])
        if supported:
            assert result is first
    assert events.count("retire") == 1


def test_nested_pair_cleanup_retires_its_own_observer_only():
    artifact, arguments = object(), {}
    events = []
    derive, _ = _deriver()
    with use_risk_pair(_Admission(), artifact, arguments, on_retire=lambda: events.append("outer")):
        outer = categories_for_hash(artifact, arguments, derive)
        with use_risk_pair(_Admission(), artifact, arguments, on_retire=lambda: events.append("inner")):
            categories_for_hash(artifact, arguments, derive)
        assert events == ["inner"]
        arm_risk_pair_policy()
        assert _policy(artifact, arguments, derive) is outer
        assert events == ["inner", "outer"]
    assert events == ["inner", "outer"]


@pytest.mark.parametrize("entry", ["hash", "policy"])
def test_final_admission_reentry_cannot_reuse_cleared_pair_or_observer(entry):
    artifact, arguments = object(), {}
    events = []
    derive, seen = _deriver()

    class Admission:
        def __init__(self):
            self.calls = 0

        def check(self):
            self.calls += 1
            if self.calls == 3:
                if entry == "hash":
                    categories_for_hash(artifact, arguments, derive)
                else:
                    _policy(artifact, arguments, derive)
            return True

    with use_risk_pair(Admission(), artifact, arguments, on_retire=lambda: events.append("retire")):
        first = categories_for_hash(artifact, arguments, derive)
        arm_risk_pair_policy()
        second = _policy(artifact, arguments, derive)
        assert second is not first
        assert len(seen) == 3
        assert events == ["retire"]
    assert events == ["retire"]
