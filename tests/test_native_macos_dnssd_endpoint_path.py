"""Own exactly six controls and preserve every censoring or retirement refusal."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.ci import native_macos_dnssd_endpoint_binding as binding
from scripts.ci import native_macos_dnssd_endpoint_path as driver
from scripts.ci import native_macos_dnssd_endpoint_final as final


@pytest.fixture
def prepared(monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "999")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setattr(driver.original, "_eligible", lambda: True)
    values = {"source": {"head": "a" * 40}, "tools": {"machine": "arm64", "loader_flags": {"effective": 6}},
              "runtime": {"witness": "b" * 64}, "historical": {"historical_only": True}}
    for name, key in (("source_identity", "source"), ("tool_identity", "tools"), ("runtime_identity", "runtime"), ("historical_admission", "historical")):
        monkeypatch.setattr(driver, name, lambda key=key: copy.deepcopy(values[key]))
    images = {name: {"sha256": letter * 64, "uuid": letter * 32, "cpu_type": 16777228, "filetype": 6 if name == "bridge" else 2}
              for name, letter in (("standalone", "c"), ("native_dlopen", "d"), ("bridge", "e"))}
    monkeypatch.setattr(driver, "identities", lambda *_: copy.deepcopy(images))
    monkeypatch.setattr(driver, "parse_context", lambda *_: {
        "valid": True, "complete": True, "loopback_label": True, "partial_line": False,
        "trace_overflow": False, "endpoint": {"observation_complete": True},
        "last_observed_boundary": "query_result", "records": [],
    })
    return driver.base() | values | {"status": "prepared"}


def capture():
    return {
        "pid": 123, "return_code": 0, "status": "completed", "direct_child_reaped": True,
        "termination_attempted": False, "stderr_bytes": 0, "deadline_seconds": 5.0,
    }


def invoke(prepared):
    saved = []
    result = driver.collect(prepared, Path("/owned/probe"), Path("/owned/host"), Path("/owned/bridge"), lambda value: saved.append(copy.deepcopy(value)))
    return result, saved


def test_exact_six_arguments_contexts_before_after_and_no_historical_replay(prepared, monkeypatch):
    calls = []
    monkeypatch.setattr(driver, "run_lookup", lambda args: (calls.append(args) or capture(), b""))
    result, saved = invoke(prepared)
    assert result["diagnostic_passed"] and result["observation_complete"] and len(calls) == 6
    assert [(row["context"], row["mode"]) for row in result["rows"]] == list(driver.CONTROLS)
    assert calls[:2] == [("/owned/probe", "dns_simple"), ("/owned/probe", "dns_shared")]
    assert calls[2:4] == [("/owned/host", "/owned/bridge", "dns_simple"), ("/owned/host", "/owned/bridge", "dns_shared")]
    for arguments, mode in zip(calls[4:], ("dns_simple", "dns_shared"), strict=True):
        assert arguments == (driver.sys.executable, "-I", "-B", str(driver.CHILD), "--mode", mode, "--bridge", "/owned/bridge", "--bridge-sha256", "e" * 64)
    assert len(saved) == 7 and saved[0]["rows"] == []
    assert all(result[key + "_before"] == result[key + "_after"] for key in ("source", "tools", "runtime", "historical", "images"))
    assert result["prior_children_replayed"] is result["cause_proved"] is result["qualification_pass"] is False


@pytest.mark.parametrize("at", (0, 2, 5))
def test_unretired_direct_child_prevents_every_later_control(prepared, monkeypatch, at):
    calls = []
    def run(arguments):
        row = capture()
        if len(calls) == at:
            row.update(direct_child_reaped=False, cleanup_error="TimeoutExpired")
        calls.append(arguments)
        return row, b""
    monkeypatch.setattr(driver, "run_lookup", run)
    result, _ = invoke(prepared)
    assert len(calls) == at + 1 and result["status"] == "direct_child_cleanup_unproved"
    assert not result["diagnostic_passed"] and not result["observation_complete"]


@pytest.mark.parametrize("extra", [
    {"output_limit": True}, {"error_type": "OSError"}, {"kill_errno": 1}, {"cleanup_error": "TimeoutExpired"},
    {"stderr_bytes": 1}, {"status": "unavailable"},
])
def test_capture_censoring_never_becomes_a_complete_observation(prepared, monkeypatch, extra):
    monkeypatch.setattr(driver, "run_lookup", lambda _: (capture() | extra, b""))
    result, _ = invoke(prepared)
    assert result["status"] == "experiment_finished" and len(result["rows"]) == 6
    assert not result["observation_complete"] and not result["diagnostic_passed"]


def test_observed_pending_poll_remains_failed_lookup(prepared, monkeypatch):
    monkeypatch.setattr(driver, "run_lookup", lambda _: (
        capture() | {"status": "deadline_exceeded", "return_code": -9, "termination_attempted": True}, b"",
    ))
    monkeypatch.setattr(driver, "parse_context", lambda *_: {
        "valid": True, "complete": False, "loopback_label": False, "partial_line": False, "trace_overflow": False,
        "endpoint": {"observation_complete": True}, "last_observed_boundary": "poll_enter", "records": [],
    })
    result, _ = invoke(prepared)
    assert result["observation_complete"] and not result["diagnostic_passed"] and len(result["rows"]) == 6
    assert all(not row["lookup_passed"] for row in result["rows"])
    assert all(row["causal_conclusion"] == "unproved" for row in result["comparison"])


def test_historical_evidence_is_actual_fixed_failed_campaign_data():
    result = binding.historical_admission()
    assert result["source"] == "c5e2c8eb722d577dcb36b2ce7e3db0eac88dcb6c"
    assert result["run"] == 35438429333 and len(result["files"]) == 18
    assert result["original_failures_preserved"] and result["historical_only"] and not result["same_current_run_claimed"]


def test_historical_payload_mutation_refuses_admission(tmp_path, monkeypatch):
    altered = tmp_path / "altered.json"
    altered.write_bytes(binding.HISTORY.read_bytes() + b"\n")
    monkeypatch.setattr(binding, "HISTORY", altered)
    with pytest.raises(ValueError, match="historical payload"):
        binding.historical_admission()


def test_completed_child_without_its_complete_protocol_cannot_earn_observation(prepared, monkeypatch):
    monkeypatch.setattr(driver, "run_lookup", lambda _: (capture(), b""))
    monkeypatch.setattr(driver, "parse_context", lambda *_: {
        "valid": True, "complete": False, "loopback_label": False, "partial_line": False, "trace_overflow": False,
        "endpoint": {"observation_complete": True}, "last_observed_boundary": "query_result", "records": [],
    })
    result, _ = invoke(prepared)
    assert not result["observation_complete"] and not result["diagnostic_passed"]


@pytest.fixture
def final_setup(monkeypatch):
    values = {"source": {"head": "a" * 40}, "tools": {"machine": "arm64"},
              "runtime": {"python_sha256": "b" * 64}, "historical": {"historical_only": True}}
    images = {name: {"sha256": letter * 64, "uuid": letter * 32, "cpu_type": 16777228, "filetype": kind}
              for name, letter, kind in (("standalone", "c", 2), ("native_dlopen", "d", 2), ("bridge", "e", 6))}
    prepared_report = final.original._base() | values | {"status": "prepared"}
    lookup_report = final.original._base() | {key + "_before": value for key, value in values.items()} | {
        "images_before": images, "status": "diagnostic_failed", "diagnostic_passed": False, "prepared_report_sha256": "f" * 64,
    }
    for name, key in (("source_identity", "source"), ("tool_identity", "tools"), ("runtime_identity", "runtime"), ("historical_admission", "historical")):
        monkeypatch.setattr(final, name, lambda key=key: copy.deepcopy(values[key]))
    monkeypatch.setattr(final, "read_input", lambda path: {
        "sha256": "f" * 64, "current_run": True,
        "report": copy.deepcopy(prepared_report if path.name == "prepared.json" else lookup_report),
    })
    by_name = {name: images[key] for key, name, _ in final.IMAGES}
    monkeypatch.setattr(final, "file_identity", lambda path: {"bytes": 1024, "sha256": by_name[path.name]["sha256"]})
    monkeypatch.setattr(final, "binary_identity", lambda path, kind: copy.deepcopy(by_name[path.name]))
    return values, images


def final_invoke():
    saved = []
    result = final.collect(Path("/owned/report"), Path("/owned/build"), lambda row: saved.append(copy.deepcopy(row)))
    return result, saved


def test_final_witness_retains_failed_lookup_and_observes_all_bindings(final_setup):
    result, saved = final_invoke()
    assert result["status"] == "witness_complete" and result["all_unchanged"]
    assert result["original_status"]["lookups"] == "diagnostic_failed"
    assert result["original_diagnostic_passed"] is False
    assert result["diagnostic_outcome_replaced"] is result["qualification_pass"] is result["cause_proved"] is False
    assert set(result["images"]) == {"standalone", "native_dlopen", "bridge"}
    assert set(result["bindings"]) == {"source", "tools", "runtime", "historical"}
    assert saved[0]["stage"] == "inputs" and saved[-1] == result


@pytest.mark.parametrize("failing", ("source_identity", "runtime_identity", "historical_admission", "tool_identity"))
def test_final_witness_keeps_other_observations_when_one_binding_fails(final_setup, monkeypatch, failing):
    def fail():
        raise ValueError("controlled final binding failure")
    monkeypatch.setattr(final, failing, fail)
    result, saved = final_invoke()
    assert result["status"] == "witness_incomplete" and not result["all_unchanged"]
    assert len(result["bindings"]) == 4 and sum(row["after"]["observed"] for row in result["bindings"].values()) == 3
    assert all(row["macho"]["observed"] for row in result["images"].values())
    assert saved[-1]["stage"] == "complete"


def test_final_witness_records_changed_source_without_replacing_earlier_failure(final_setup, monkeypatch):
    monkeypatch.setattr(final, "source_identity", lambda: {"head": "changed"})
    result, _ = final_invoke()
    assert result["bindings"]["source"]["after"]["value"] == {"head": "changed"}
    assert result["bindings"]["source"]["comparison"]["status"] == "changed"
    assert not result["all_unchanged"] and result["original_diagnostic_passed"] is False


def test_final_witness_retains_partial_build_file_and_missing_other_images(monkeypatch, tmp_path):
    build = tmp_path / "build"
    build.mkdir()
    partial = b"not a complete Mach-O image"
    (build / "endpoint-probe").write_bytes(partial)
    for name in ("source_identity", "runtime_identity", "historical_admission", "tool_identity"):
        monkeypatch.setattr(final, name, lambda: {})
    saved = []
    result = final.collect(tmp_path / "missing-report", build, lambda row: saved.append(copy.deepcopy(row)))
    observed = result["images"]["standalone"]
    assert observed["file"]["value"] == {"bytes": len(partial), "sha256": hashlib.sha256(partial).hexdigest()}
    assert observed["macho"]["observed"] is False
    assert result["images"]["bridge"]["file"]["error_type"] == "FileNotFoundError"
    assert result["images"]["native_dlopen"]["file"]["error_type"] == "FileNotFoundError"
    assert all(row["observed"] is False for row in result["inputs"].values())
    assert len(result["bindings"]) == 4 and not result["all_unchanged"]


def test_final_witness_lacks_unchanged_credit_without_a_bound_prior_image(final_setup, monkeypatch):
    old = final.read_input
    def missing_lookup(path):
        if path.name == "endpoint-context.json":
            raise FileNotFoundError(path)
        return old(path)
    monkeypatch.setattr(final, "read_input", missing_lookup)
    result, _ = final_invoke()
    assert all(row["macho"]["observed"] for row in result["images"].values())
    assert all(row["comparison"]["unchanged"] is None for row in result["images"].values())
    assert result["original_diagnostic_passed"] is None and not result["all_unchanged"]


def test_final_witness_refuses_a_report_from_another_workflow(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    path = tmp_path / "prepared.json"
    report = final.original._base() | {"workflow_commit": "b" * 40, "source": {"head": "b" * 40}}
    path.write_text(json.dumps(report), encoding="utf-8")
    record = final.observe(lambda: final.read_input(path))
    assert record["observed"] and record["value"]["current_run"] is False
    assert final.input_value(record) == {}


def test_final_witness_keeps_raw_and_macho_hash_mismatch_incomplete(final_setup, monkeypatch):
    monkeypatch.setattr(final, "file_identity", lambda _: {"bytes": 1024, "sha256": "9" * 64})
    result, _ = final_invoke()
    assert all(row["comparison"]["unchanged"] for row in result["images"].values())
    assert not any(row["file_and_macho_hashes_match"] for row in result["images"].values())
    assert not result["all_unchanged"]


def test_final_witness_rejects_changed_prepared_report_digest(final_setup, monkeypatch):
    old = final.read_input
    def changed(path):
        row = old(path)
        if path.name == "prepared.json":
            row["sha256"] = "8" * 64
        return row
    monkeypatch.setattr(final, "read_input", changed)
    result, _ = final_invoke()
    assert result["prepared_report_unchanged"] is False and not result["all_unchanged"]
    assert result["original_status"]["lookups"] == "diagnostic_failed"
