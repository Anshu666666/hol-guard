"""Own exactly eight new cells and retain every failed observation or retirement."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from scripts.ci import native_macos_dnssd_sigpipe_final as final
from scripts.ci import native_macos_dnssd_sigpipe_path as driver


@pytest.fixture
def prepared(monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "999")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setattr(driver.original, "_eligible", lambda: True)
    values = {
        "source": {"head": "a" * 40},
        "tools": {"machine": "arm64", "loader_flags": {"effective": 6}},
        "runtime": {"source": "b" * 64},
        "historical": {"historical_only": True},
    }
    for name, key in (
        ("source_identity", "source"),
        ("tool_identity", "tools"),
        ("runtime_identity", "runtime"),
        ("historical_admission", "historical"),
    ):
        monkeypatch.setattr(driver, name, lambda key=key: copy.deepcopy(values[key]))
    images = {
        name: {"sha256": letter * 64, "uuid": letter * 32, "cpu_type": 16777228, "filetype": kind}
        for name, letter, kind in (("native_dlopen", "d", 2), ("bridge", "e", 6))
    }
    monkeypatch.setattr(driver, "identities", lambda *_: copy.deepcopy(images))
    monkeypatch.setattr(driver, "parse_signal", metadata)
    return driver.base() | values | {"status": "prepared"}


def metadata(*arguments):
    context = arguments[4]
    return {
        "valid": True,
        "complete": True,
        "loopback_label": True,
        "partial_line": False,
        "trace_overflow": False,
        "endpoint": {"observation_complete": True},
        "last_observed_boundary": "query_result",
        "records": [],
        "condition": {
            "admitted": True,
            "states": [
                {
                    "handler_kind": int(context == "python"),
                    "flags": 0,
                    "action_mask": "0",
                    "blocked_mask": "0",
                }
            ],
        },
    }


def capture():
    return {
        "pid": 123,
        "return_code": 0,
        "status": "completed",
        "direct_child_reaped": True,
        "termination_attempted": False,
        "stderr_bytes": 0,
        "deadline_seconds": 5.0,
    }


def invoke(prepared):
    saved = []
    report = driver.collect(
        prepared,
        Path("/owned/host"),
        Path("/owned/bridge"),
        lambda value: saved.append(copy.deepcopy(value)),
    )
    return report, saved


def test_exact_eight_cells_arguments_and_same_host_initial_action_join(prepared, monkeypatch):
    calls = []
    monkeypatch.setattr(driver, "run_lookup", lambda arguments: (calls.append(arguments) or capture(), b""))
    report, saved = invoke(prepared)
    assert report["diagnostic_passed"] and report["observation_complete"] and len(calls) == 8
    assert [(row["context"], row["condition"], row["mode"]) for row in report["rows"]] == list(driver.CONTROLS)
    expected = [
        ("/owned/host", "/owned/bridge", mode, condition)
        for condition in ("default", "ignore")
        for mode in ("dns_simple", "dns_shared")
    ]
    assert calls[:4] == expected
    for arguments, (_, condition, mode) in zip(calls[4:], driver.CONTROLS[4:], strict=True):
        assert arguments == (
            driver.sys.executable,
            "-I",
            "-B",
            str(driver.CHILD),
            "--mode",
            mode,
            "--condition",
            condition,
            "--bridge",
            "/owned/bridge",
            "--bridge-sha256",
            "e" * 64,
        )
    assert len(saved) == 9 and saved[0]["rows"] == []
    assert len(report["same_host_condition_pairs"]) == 4
    assert all(row["initial_condition_comparable"] for row in report["same_host_condition_pairs"])
    assert all(
        report[key + "_before"] == report[key + "_after"]
        for key in ("source", "tools", "runtime", "historical", "images")
    )
    assert report["cause_proved"] is report["prior_children_replayed"] is report["qualification_pass"] is False


@pytest.mark.parametrize("at", (0, 3, 7))
def test_unretired_owned_child_stops_every_later_cell(prepared, monkeypatch, at):
    calls = []

    def lookup(arguments):
        row = capture()
        if len(calls) == at:
            row.update(direct_child_reaped=False, cleanup_error="TimeoutExpired")
        calls.append(arguments)
        return row, b""

    monkeypatch.setattr(driver, "run_lookup", lookup)
    report, _ = invoke(prepared)
    assert len(calls) == at + 1 and report["status"] == "direct_child_cleanup_unproved"
    assert not report["observation_complete"] and not report["diagnostic_passed"]


def test_censored_capture_is_retained_without_condition_comparison_credit(prepared, monkeypatch):
    def lookup(_):
        return capture() | {"output_limit": 16384}, b""

    monkeypatch.setattr(driver, "run_lookup", lookup)
    report, _ = invoke(prepared)
    assert len(report["rows"]) == 8 and all("output_limit" in row["capture"] for row in report["rows"])
    assert not report["observation_complete"] and not report["diagnostic_passed"]


def test_changed_initial_mask_refuses_same_host_condition_comparison(prepared, monkeypatch):
    def changed(*arguments):
        value = metadata(*arguments)
        if arguments[-1] == "ignore":
            value["condition"]["states"][0]["action_mask"] = "1"
        return value

    monkeypatch.setattr(driver, "parse_signal", changed)
    monkeypatch.setattr(driver, "run_lookup", lambda _: (capture(), b""))
    report, _ = invoke(prepared)
    assert len(report["rows"]) == 8
    assert not any(row["initial_condition_comparable"] for row in report["same_host_condition_pairs"])
    assert not report["observation_complete"]


def test_changed_phase_image_stops_before_the_next_query(prepared, monkeypatch):
    calls = []
    original = driver.identities

    def identities(*arguments):
        value = original(*arguments)
        if len(calls) == 2:
            value["bridge"]["sha256"] = "f" * 64
        return value

    monkeypatch.setattr(driver, "identities", identities)
    monkeypatch.setattr(driver, "run_lookup", lambda arguments: (calls.append(arguments) or capture(), b""))
    report, _ = invoke(prepared)
    assert len(calls) == 2 and len(report["rows"]) == 2
    assert report["status"] == "diagnostic_failed" and not report["diagnostic_passed"]


def test_always_final_witness_retains_missing_images_and_failed_prepare_baseline(tmp_path, monkeypatch):
    for name in ("source_identity", "tool_identity", "runtime_identity", "historical_admission"):
        monkeypatch.setattr(final, name, lambda: {"fresh": True})
    saved = []
    report = final.collect(tmp_path, tmp_path / "unbuilt", lambda value: saved.append(copy.deepcopy(value)))
    assert report["status"] == "witness_incomplete" and report["all_unchanged"] is False
    assert set(report["images"]) == {"native_dlopen", "bridge"}
    assert all(
        row["file"]["observed"] is False and row["macho"]["observed"] is False for row in report["images"].values()
    )
    assert all(row["comparison"]["unchanged"] is None for row in report["bindings"].values())
    assert report["original_diagnostic_passed"] is None and report["prepared_report_unchanged"] is None
    assert saved[-1] == report
