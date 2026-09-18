from __future__ import annotations

import hashlib
import json
import os
import plistlib
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.ci import native_macos_service_identity as diagnostic


def _plist(label="com.apple.mDNSResponder.reloaded", **changes):
    return plistlib.dumps({"Label": label, "ProgramArguments": [str(diagnostic._EXECUTABLE)], **changes})


@pytest.mark.parametrize("label", ["com.apple.mDNSResponder", "com.apple.mDNSResponder.reloaded"])
def test_service_target_comes_from_the_actual_validated_plist(label):
    result = diagnostic._service(_plist(label))
    assert result["valid"] and result["service_target"] == "system/" + label
    assert result["program_arguments"] == ["/usr/sbin/mDNSResponder"]


@pytest.mark.parametrize(
    "data",
    [
        b"not a plist",
        b'<?xml version="1.0"?><plist><dict>',
        plistlib.dumps([]),
        _plist("../other"),
        _plist("com.apple.mDNSResponder\nother"),
        _plist("com.apple.mDNSResponderHelper.reloaded"),
        _plist(Program="/bin/other"),
        _plist(Program=b"unexpected bytes"),
        _plist(ProgramArguments=["/bin/other"]),
        _plist(ProgramArguments=[]),
        _plist(ProgramArguments=[False]),
        _plist(ProgramArguments=["/usr/sbin/mDNSResponder"] * 65),
    ],
)
def test_untrusted_or_ambiguous_selection_never_becomes_a_service_target(data):
    result = diagnostic._service(data)
    assert result["valid"] is False and "service_target" not in result


@pytest.mark.skipif(os.name != "posix", reason="fixed trusted POSIX executable")
def test_trusted_descriptor_read_hashes_actual_root_owned_executable():
    path = Path("/usr/bin/true")
    result, data = diagnostic._trusted_file(path, diagnostic._EXECUTABLE_LIMIT)
    assert result["trusted"] and result["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["uid"] == 0 and not result["mode"] & 0o022 and data == b""
    oversized, _ = diagnostic._trusted_file(path, 1)
    assert not oversized["trusted"] and oversized["status"] == "untrusted_file"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file ownership validation")
def test_writable_or_untrusted_ancestor_is_rejected_before_file_contents(tmp_path):
    directory = tmp_path / "writable"
    directory.mkdir(mode=0o777)
    directory.chmod(0o777)
    path = directory / "plist"
    path.write_bytes(_plist())
    result, data = diagnostic._trusted_file(path, 1024, keep_bytes=True)
    assert result["status"] == "untrusted_ancestor" and data == b""


def _completed(arguments, *, output="", code=0):
    return {
        "argv": list(arguments),
        "status": "completed",
        "return_code": code,
        "completed_without_intervention": True,
        "stdout": output,
        "stderr": "",
    }


def _host(monkeypatch, *, label="com.apple.mDNSResponder.reloaded", signature=0, printed=0, changed=False):
    monkeypatch.setattr(diagnostic.sys, "platform", "darwin")
    monkeypatch.setattr(diagnostic.platform, "platform", lambda: "controlled macOS fixture")
    for key, value in {"GITHUB_ACTIONS": "true", "RUNNER_OS": "macOS", "GITHUB_RUN_ID": "123"}.items():
        monkeypatch.setenv(key, value)
    calls = []
    reads = []

    def read(path, _maximum, *, keep_bytes=False):
        reads.append((path, keep_bytes))
        result = {"path": str(path), "trusted": True, "status": "read", "sha256": "1" * 64}
        if changed and path == diagnostic._PLIST and not keep_bytes:
            result["sha256"] = "2" * 64
        return result, _plist(label) if keep_bytes else b""

    def capture(arguments):
        calls.append(arguments)
        if arguments == diagnostic._ANCHOR:
            return _completed(arguments, code=signature)
        assert arguments == ("/usr/bin/sudo", "-n", "/bin/launchctl", "print", "system/" + label)
        return _completed(
            arguments,
            code=printed,
            output=f"system/{label} = {{\n\tprogram = /usr/sbin/mDNSResponder\n\tpid = 321\n}}\n",
        )

    monkeypatch.setattr(diagnostic, "_trusted_file", read)
    monkeypatch.setattr(diagnostic, "_capture", capture)
    return calls, reads


def test_readonly_host_probe_binds_actual_label_signature_program_and_unchanged_files(monkeypatch):
    calls, reads = _host(monkeypatch)
    report = diagnostic.collect()
    assert report["service_identity_verified"] and report["printed_identity"]["pid"] == 321
    assert len(calls) == 2 and len(reads) == 4
    assert report["service"]["label"] == "com.apple.mDNSResponder.reloaded"
    for field in (
        "qualification_pass",
        "cache_effect_verified",
        "ownership_verified",
        "running_process_identity_verified",
        "service_intervention_attempted",
        "security_configuration_modified",
    ):
        assert report[field] is False


@pytest.mark.parametrize("options", [{"signature": 1}, {"printed": 113}, {"changed": True}])
def test_rejection_or_changed_file_never_earns_identity_credit(monkeypatch, options):
    calls, _ = _host(monkeypatch, **options)
    report = diagnostic.collect()
    assert report["service_identity_verified"] is False and len(calls) == 2
    assert report["status"] == "identity_unverified"


def test_unvalidated_label_never_reaches_launchctl(monkeypatch):
    calls, _ = _host(monkeypatch, label="com.apple.other")
    report = diagnostic.collect()
    assert report["status"] == "service_selection_failed" and calls == []


def test_non_ci_or_non_macos_host_does_not_read_or_run_system_commands(monkeypatch):
    calls, reads = _host(monkeypatch)
    monkeypatch.delenv("GITHUB_ACTIONS")
    report = diagnostic.collect()
    assert report["status"] == "not_disposable_macos_ci" and calls == reads == []


@pytest.mark.parametrize(
    "output",
    [
        "system/com.apple.other = {\n\tprogram = /usr/sbin/mDNSResponder\n}",
        "system/com.apple.mDNSResponder = {\n\tprogram = /bin/other\n}",
        "system/com.apple.mDNSResponder = {\n\tprogram = /usr/sbin/mDNSResponder\n\tprogram = /bin/other\n}",
    ],
)
def test_printed_service_mismatch_does_not_validate(output):
    result = diagnostic._printed_identity(
        _completed((), output=output), diagnostic._service(_plist("com.apple.mDNSResponder"))
    )
    assert not (result["service_label_matches"] and result["program_matches"])


@pytest.mark.skipif(os.name != "posix", reason="POSIX finite output capture")
def test_actual_command_status_and_bounded_failure_are_retained():
    result = diagnostic._capture((sys.executable, "-c", "print('actual output'); raise SystemExit(7)"))
    assert result["status"] == "completed" and result["return_code"] == 7
    assert result["stdout"] == "actual output\n" and result["completed_without_intervention"]
    timed = diagnostic._capture((sys.executable, "-c", "import time; time.sleep(10)"), timeout=0.03)
    assert timed["status"] == "deadline_exceeded" and timed["termination_attempted"]
    assert timed["return_code"] is not None and not timed["completed_without_intervention"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX kernel output limit")
def test_kernel_file_limit_bounds_unexpected_command_output(monkeypatch):
    monkeypatch.setattr(diagnostic, "_OUTPUT_LIMIT", 1024)
    result = diagnostic._capture((sys.executable, "-c", "import os; os.write(1, b'x' * 2048)"))
    assert result["status"] == "output_limit" and result["stdout_bytes"] <= 1024
    assert result["stderr_bytes"] <= 1024 and not result["completed_without_intervention"]


def test_standalone_cli_needs_no_import_path_and_preserves_ineligible_host_failure(tmp_path):
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("GITHUB_ACTIONS", None)
    output = tmp_path / "identity.json"
    process = subprocess.run(
        [sys.executable, str(Path(diagnostic.__file__).resolve()), "--output", str(output)],
        env=environment,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert process.returncode == 1
    report = json.loads(output.read_text())
    assert report["status"] == "not_disposable_macos_ci" and not report["service_identity_verified"]
