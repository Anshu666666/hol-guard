"""A native-cache experiment preserves immutable-arm results and original failures."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.ci import native_loopback_cache as cache
from scripts.ci import native_loopback_lookup as lookup
from scripts.ci import native_loopback_resolver as wrapper


def _hosts():
    return {
        "status": "read",
        "file_trusted": True,
        "expected_directory_trusted": True,
        "content_sha256": "a" * 64,
        "inode": 123,
        "mapping": {
            "exact_ipv4_localhost_present": True,
            "exact_ipv6_localhost_present": True,
            "duplicate_ipv4_localhost_records": 0,
            "duplicate_ipv6_localhost_records": 0,
            "localhost_conflicts": 0,
            "malformed": 0,
        },
    }


def _ci(monkeypatch):
    monkeypatch.setattr(cache.sys, "platform", "darwin")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_OS", "macOS")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")


@pytest.mark.parametrize("mutation", [None, "signal", "hosts", "dns", "lookup", "already_completed"])
def test_one_native_signal_requires_unchanged_configuration_and_actual_libc_completion(monkeypatch, mutation):
    _ci(monkeypatch)
    hosts = [_hosts(), _hosts()]
    if mutation == "hosts":
        hosts[1]["content_sha256"] = "b" * 64
    monkeypatch.setattr(cache, "hosts_mapping_witness", lambda: hosts.pop(0))
    calls = []

    def fixed(arguments, *, limit):
        calls.append(arguments)
        assert limit in {4096, 256 * 1024}
        if arguments == cache._SIGNAL:
            assert arguments == (
                "/usr/bin/sudo",
                "-n",
                "/bin/launchctl",
                "kill",
                "SIGHUP",
                "system/com.apple.mDNSResponder",
            )
            return {
                "status": "failed" if mutation == "signal" else "completed",
                "return_code": 1 if mutation == "signal" else 0,
            }, b""
        assert arguments == cache._DNS
        digest = "b" if mutation == "dns" and len(calls) > 1 else "a"
        return {"status": "completed", "stdout_sha256": digest * 64}, b""

    probes = []

    def libc(operation):
        probes.append(operation)
        completed = mutation == "already_completed" or (len(probes) > 3 and mutation != "lookup")
        return {"status": "completed" if completed else "deadline_exceeded", "loopback_label": completed}

    monkeypatch.setattr(cache, "_fixed_command", fixed)
    monkeypatch.setattr(cache, "libc_probe", libc)
    original = {"status": "deadline_exceeded", "loopback_label": False, "elapsed_ms": 5001.0}
    saved = copy.deepcopy(original)
    report = cache.refresh_native_cache(original)
    assert original == saved and report["original_probe"] == saved
    assert report["qualification_pass"] is False and report["qualification_sample"] is False
    assert report["baseline_artifact_modified"] is False and report["fixture_deadline_changed"] is False
    assert calls.count(cache._SIGNAL) == (0 if mutation == "already_completed" else 1)
    assert report["signal_attempts"] == calls.count(cache._SIGNAL)
    assert report["libc_recovered"] is (mutation is None)
    assert probes == list(cache._LOOKUPS) * (1 if mutation == "already_completed" else 2)


@pytest.mark.parametrize("reason", ["not_ci", "untrusted_hosts", "no_ipv4", "conflicting_hosts"])
def test_cache_refresh_refuses_unsupported_environment_and_untrusted_configuration(monkeypatch, reason):
    _ci(monkeypatch)
    hosts = _hosts()
    if reason == "not_ci":
        monkeypatch.delenv("GITHUB_RUN_ID")
    elif reason == "untrusted_hosts":
        hosts["file_trusted"] = False
    elif reason == "no_ipv4":
        hosts["mapping"]["exact_ipv4_localhost_present"] = False
    else:
        hosts["mapping"]["localhost_conflicts"] = 1
    monkeypatch.setattr(cache, "hosts_mapping_witness", lambda: hosts)

    def fixed(arguments, *, limit):
        assert arguments == cache._DNS
        return {"status": "completed", "stdout_sha256": "a" * 64}, b""

    monkeypatch.setattr(cache, "_fixed_command", fixed)
    monkeypatch.setattr(cache, "libc_probe", lambda _op: pytest.fail("ineligible cache experiment ran a lookup"))
    report = cache.refresh_native_cache({"status": "deadline_exceeded"})
    assert report["signal_attempts"] == 0 and report["libc_recovered"] is False


@pytest.mark.parametrize("returncode", [0, 1, 17])
def test_recovered_environment_runs_original_command_once_and_preserves_its_exit(monkeypatch, tmp_path, returncode):
    monkeypatch.setattr(wrapper.sys, "platform", "darwin")
    before = {"status": "deadline_exceeded", "loopback_label": False}
    after = {"status": "completed", "loopback_label": True}
    observations = [before, after]
    monkeypatch.setattr(wrapper, "resolver_probe", lambda: observations.pop(0))
    monkeypatch.setattr(
        wrapper,
        "refresh_native_cache",
        lambda value, **_kwargs: {"status": "experiment_finished", "libc_recovered": value is before},
    )
    calls = []

    def command(arguments):
        calls.append(arguments)
        return returncode

    monkeypatch.setattr(wrapper, "_run_command", command)
    monkeypatch.setattr(
        wrapper, "LoopbackPTRResponder", lambda: pytest.fail("recovered native lookup installed another resolver")
    )
    output = tmp_path / "resolver.json"
    assert wrapper.run_wrapped(["original", "paired", "command"], output, refresh_cache=True) == returncode
    report = json.loads(output.read_text())
    assert report["before"] == before and report["after"] == after
    assert report["command_returncode"] == returncode
    assert report["qualification_pass"] is False
    assert calls == [["original", "paired", "command"]]


def test_fixed_native_failure_retains_only_bounded_metadata(monkeypatch):
    def run(arguments, **kwargs):
        assert arguments == cache._SIGNAL
        assert kwargs["timeout"] == 5 and kwargs["stdin"] == subprocess.DEVNULL
        raise subprocess.TimeoutExpired(arguments, 5, output=b"private-output", stderr=b"private-diagnostic")

    monkeypatch.setattr(cache.subprocess, "run", run)
    report, stdout = cache._fixed_command(cache._SIGNAL, limit=4096)
    assert report["status"] == "deadline_exceeded" and stdout == b""
    assert "private" not in json.dumps(report)


def test_wrapper_standalone_cli_retains_the_explicit_experiment_option():
    script = Path(__file__).resolve().parents[1] / "scripts/ci/native_loopback_resolver.py"
    result = subprocess.run(
        [sys.executable, "-I", str(script), "--help"], capture_output=True, text=True, timeout=10, check=True
    )
    assert "--refresh-native-cache" in result.stdout


def test_native_signal_is_checkpointed_before_its_outcome_is_known(monkeypatch):
    _ci(monkeypatch)
    monkeypatch.setattr(cache, "hosts_mapping_witness", _hosts)
    monkeypatch.setattr(
        cache, "libc_probe", lambda _operation: {"status": "deadline_exceeded", "loopback_label": False}
    )
    checkpoints = []

    def fixed(arguments, *, limit):
        if arguments == cache._SIGNAL:
            assert checkpoints[-1]["status"] == "native_signal_pending"
            assert checkpoints[-1]["signal_attempts"] == 1
            assert "signal" not in checkpoints[-1]
            raise SystemExit(143)
        assert arguments == cache._DNS
        return {"status": "completed", "stdout_sha256": "a" * 64}, b""

    monkeypatch.setattr(cache, "_fixed_command", fixed)
    with pytest.raises(SystemExit):
        cache.refresh_native_cache(
            {"status": "deadline_exceeded"}, progress=lambda report: checkpoints.append(copy.deepcopy(report))
        )
    assert checkpoints[-1]["original_probe"]["status"] == "deadline_exceeded"
    assert checkpoints[-1]["libc_recovered"] is False


@pytest.mark.parametrize("index", [-1, -2, 0, 5])
def test_signed_interface_index_does_not_turn_a_positive_ptr_into_a_negative_answer(index):
    data = f"12:01:01.001 Add 2 {index} 1.0.0.127.in-addr.arpa. PTR IN localhost.\n".encode()
    report = lookup.dns_service_summary(data, b"")
    assert report["counts"]["positive"] == report["counts"]["loopback_label"] == 1
    assert report["counts"]["negative"] == 0
    assert report["unparsed_fixed_question_rows"]["rows"] == 0


def test_negative_localonly_ptr_and_invalid_interface_stay_separate():
    data = b"""12:01:01.001 Add 2 -1 1.0.0.127.in-addr.arpa. PTR IN 0.0.0.0    No Such Record
12:01:01.002 Add 2 -2147483649 1.0.0.127.in-addr.arpa. PTR IN localhost.
"""
    report = lookup.dns_service_summary(data, b"")
    assert report["counts"]["negative"] == 1 and report["counts"]["positive"] == 0
    assert report["unparsed_fixed_question_rows"]["rows"] == 1
