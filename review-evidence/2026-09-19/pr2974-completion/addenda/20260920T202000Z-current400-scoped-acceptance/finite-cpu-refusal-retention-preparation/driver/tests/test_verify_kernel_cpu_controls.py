from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts/ci/verify_kernel_cpu_controls.py"
_SPEC = importlib.util.spec_from_file_location("cpu_finite_driver_under_test", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
driver = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(driver)


def complete() -> dict[str, Any]:
    return {
        "schema": "hol-guard.kernel-cpu-host-controller.v1",
        "passed": True,
        "worker_launched": True,
        "cleanup_complete": True,
        "stream_capture_complete": True,
        "original_workload_executed": False,
        "worker_exit": 0,
        "fault": None,
        "collection_failure": None,
        "stderr_retained_bytes": 0,
        "worker_report": {
            "admitted": True,
            "passed": True,
            "controls": [{"name": "finite", "passed": True, "error": None}],
        },
    }


def test_original_finite_result_admits_without_modification() -> None:
    value = complete()
    before = json.dumps(value)
    driver.admit_result(value, ["finite"])
    assert json.dumps(value) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("passed", False),
        ("cleanup_complete", False),
        ("stream_capture_complete", False),
        ("worker_exit", False),
        ("worker_exit", -9),
        ("original_workload_executed", True),
        ("fault", "os"),
        ("stderr_retained_bytes", 1),
    ],
)
def test_incomplete_or_failed_original_result_is_not_promoted(field: str, value: Any) -> None:
    report = complete()
    report[field] = value
    with pytest.raises(ValueError):
        driver.admit_result(report, ["finite"])


@pytest.mark.parametrize("change", ["missing", "duplicate", "failed", "not_admitted"])
def test_actual_control_population_and_admission_are_required(change: str) -> None:
    report = complete()
    row = report["worker_report"]
    if change == "missing":
        row["controls"] = []
    elif change == "duplicate":
        row["controls"] *= 2
    elif change == "failed":
        row["controls"][0]["error"] = "assertion"
    else:
        row["admitted"] = False
    with pytest.raises(ValueError):
        driver.admit_result(report, ["finite"])


@pytest.mark.parametrize("tail", ["", "<skipped/>", "<failure/>"])
def test_ordered_original_junit_does_not_count_skips_as_passes(tmp_path: Path, tail: str) -> None:
    xml = tmp_path / "actual.xml"
    xml.write_text(
        '<testsuites><testsuite><testcase classname="actual" name="finite">'
        + tail
        + "</testcase></testsuite></testsuites>"
    )
    if tail:
        with pytest.raises(ValueError):
            driver.verify_junit(xml, ["actual::finite"])
    else:
        driver.verify_junit(xml, ["actual::finite"])
        with pytest.raises(ValueError):
            driver.verify_junit(xml, ["actual::other"])


def test_duplicate_json_refused_and_frozen_receipt_cannot_be_replaced(tmp_path: Path) -> None:
    path = tmp_path / "original.json"
    path.write_text('{"passed":true,"passed":false}')
    with pytest.raises(ValueError, match="duplicate"):
        driver.read_json(path)
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        driver.write(path, {"passed": True})
    assert path.read_bytes() == before


def test_preparation_timeout_preserves_original_failure_and_declared_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = TimeoutError("source-control-only")

    def refuse(*_args: Any, **_kwargs: Any) -> None:
        raise original

    monkeypatch.setattr(driver.subprocess, "run", refuse)
    with pytest.raises(TimeoutError) as captured:
        driver.command(["finite-source-command"], tmp_path, tmp_path, "finite", 2)
    assert captured.value is original
    assert json.loads((tmp_path / "finite.command.json").read_text()) == {
        "argv": ["finite-source-command"],
        "timeout_seconds": 2,
    }
    assert json.loads((tmp_path / "finite.status.json").read_text()) == {
        "returncode": None,
        "failure_kind": "TimeoutError",
    }
