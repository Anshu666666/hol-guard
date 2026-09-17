"""Contracts for required release collection, installed canaries, and negative outcomes."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci.release_required_evidence import REQUIRED_RELEASE_NODE_FRAGMENTS, build_report
from scripts.ci.verify_release_negative_outcomes import (
    NegativeOutcomeError,
    validate_negative_outcomes,
)

ROOT = Path(__file__).resolve().parents[1]


def _cases() -> list[dict[str, object]]:
    return [
        {"name": "draft", "result": "fail-closed", "passed": False, "evidence": "pytest-draft"},
        {"name": "wrong-workspace", "result": "refused", "passed": False, "evidence": "pytest-workspace"},
        {"name": "stale", "result": "fail-closed", "passed": False, "evidence": "pytest-stale"},
        {
            "name": "unavailable-runtime",
            "result": "unsupported",
            "passed": False,
            "evidence": "installed-matrix",
        },
        {"name": "immutable-block", "result": "refused", "passed": False, "evidence": "review-contract"},
    ]


def test_release_required_tests_are_collected_and_not_silently_deselected() -> None:
    report = build_report(ROOT)

    assert report.missing_required == ()
    assert report.deselected_required == ()
    assert report.collected_release_cases >= len(REQUIRED_RELEASE_NODE_FRAGMENTS)
    assert report.installed_canary_oses == ("ubuntu-latest", "macos-latest", "windows-latest")
    assert "publish-alpha-testpypi" in report.installed_wheel_jobs
    assert report.named_ci_deselects


def test_negative_outcomes_reject_happy_path_passes() -> None:
    payload = {"schema": "hol-guard-release-negative-outcomes.v1", "cases": _cases()}
    normalized = validate_negative_outcomes(payload)
    assert [case["name"] for case in normalized["cases"]] == [
        "draft",
        "wrong-workspace",
        "stale",
        "unavailable-runtime",
        "immutable-block",
    ]

    payload["cases"][0]["passed"] = True
    with pytest.raises(NegativeOutcomeError, match="cannot record a pass"):
        validate_negative_outcomes(payload)


def test_negative_outcomes_require_every_named_fail_closed_case() -> None:
    cases = _cases()[:-1]
    with pytest.raises(NegativeOutcomeError, match="incomplete"):
        validate_negative_outcomes({"schema": "hol-guard-release-negative-outcomes.v1", "cases": cases})
