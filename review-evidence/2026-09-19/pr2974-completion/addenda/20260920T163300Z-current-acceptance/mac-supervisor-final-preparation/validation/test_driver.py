"""Data-only negative admissions for the isolated recovery driver."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

spec = importlib.util.spec_from_file_location("mac_recovery_driver", Path(__file__).with_name("run.py"))
assert spec is not None and spec.loader is not None
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def fixture(tmp_path: Path, passed: bool = False) -> tuple[Path, Path]:
    rows = []
    for ordinal, role in enumerate(("rule_contract", "policy_push", "hook", "policy_push", "original_stop")):
        rows.append({"index": len(rows), "kind": "call_offered", "ordinal": ordinal, "role": role})
        rows.append(
            {
                "index": len(rows),
                "kind": "call_returned",
                "ordinal": ordinal,
                "role": role,
                "returncode": 2 if ordinal == 3 else 0,
            }
        )
    value = {
        "schema": "hol-guard-macos-supervisor-observation.v1",
        "observation_complete": True,
        "capture_faults": 0,
        "overflow": False,
        "native_observation_lost": False,
        "aliases_restored": True,
        "original_test_outcome": "passed" if passed else "failed",
        "rows": rows,
    }
    path, xml = tmp_path / "observation.json", tmp_path / "original.xml"
    path.write_text(json.dumps(value))
    xml.write_text(
        '<testsuites><testsuite><testcase classname="ci.native_runtime.test_native_hook_client" '
        'name="test_native_hook_client_recovers_after_supervisor_exit">'
        + ("" if passed else '<failure message="original"/>')
        + "</testcase></testsuite></testsuites>"
    )
    return path, xml


def test_original_failure_is_diagnostically_admitted_without_becoming_pass(tmp_path: Path) -> None:
    path, xml = fixture(tmp_path)
    result = driver.observation_gate(path, 1, xml)
    assert result["diagnostic_admission_passed"] is True
    assert result["original_selector_exit"] == 1 and result["original_outcome"] == "failed"
    assert result["historical_cause_established"] is False


@pytest.mark.parametrize(
    "fault",
    [
        "native_loss",
        "capture_fault",
        "overflow",
        "restoration",
        "index",
        "duplicate_offer",
        "missing_return",
        "role",
        "stop_failed",
        "outcome",
    ],
)
def test_observation_admission_rejects_missing_or_ambiguous_evidence(tmp_path: Path, fault: str) -> None:
    path, xml = fixture(tmp_path)
    value = json.loads(path.read_text())
    if fault == "native_loss":
        value["native_observation_lost"] = True
    elif fault == "capture_fault":
        value["capture_faults"] = 1
    elif fault == "overflow":
        value["overflow"] = True
    elif fault == "restoration":
        value["aliases_restored"] = False
    elif fault == "index":
        value["rows"][0]["index"] = 1
    elif fault == "duplicate_offer":
        value["rows"][2]["ordinal"] = 0
    elif fault == "missing_return":
        value["rows"][-1]["kind"] = "unobserved"
    elif fault == "role":
        value["rows"][1]["role"] = "hook"
    elif fault == "stop_failed":
        value["rows"][-1]["returncode"] = 1
    else:
        value["original_test_outcome"] = "passed"
    path.write_text(json.dumps(value))
    with pytest.raises(RuntimeError):
        driver.observation_gate(path, 1, xml)


@pytest.mark.parametrize("feature", [False, True])
def test_native_roster_refuses_fewer_tests_before_any_control_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, feature: bool
) -> None:
    calls = []

    def incomplete(*args: Any, **kwargs: Any) -> tuple[int, str]:
        calls.append(args[0])
        return 0, driver.NAMESPACE + "enabled::tests::missing_observations_are_unobserved: test\n"

    monkeypatch.setattr(driver, "command", incomplete)
    with pytest.raises(RuntimeError, match="native_control_roster"):
        driver.native_controls(tmp_path, tmp_path, {}, feature)
    assert len(calls) == 1 and calls[0][-1] == "--list"


def test_python_control_xml_requires_exact_unique_identities(tmp_path: Path) -> None:
    path = tmp_path / "controls.xml"
    path.write_text(
        '<testsuites><testsuite><testcase classname="tests.test_fixture" name="test_one"/>'
        '<testcase classname="tests.test_fixture" name="test_one"/></testsuite></testsuites>'
    )
    with pytest.raises(RuntimeError, match="python_control_identity_join"):
        driver.control_xml(path, ["tests/test_fixture.py::test_one", "tests/test_fixture.py::test_two"])


def test_original_selector_refuses_same_name_from_other_module(tmp_path: Path) -> None:
    path, xml = fixture(tmp_path)
    xml.write_text(xml.read_text().replace("ci.native_runtime.test_native_hook_client", "unrelated.module"))
    with pytest.raises(RuntimeError, match="original_selector_identity"):
        driver.observation_gate(path, 1, xml)


def test_observation_refuses_non_mapping_row(tmp_path: Path) -> None:
    path, xml = fixture(tmp_path)
    value = json.loads(path.read_text())
    value["rows"][0] = "not-a-row"
    path.write_text(json.dumps(value))
    with pytest.raises(RuntimeError, match="observation_rows"):
        driver.observation_gate(path, 1, xml)
