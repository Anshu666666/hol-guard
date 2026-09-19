"""Post-failure selection observations never retry or redeem SDK discovery."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import plistlib
import sys
from pathlib import Path

import pytest

from scripts.ci import native_macos_xcode_selection as observer


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"/Applications/Xcode.app/Contents/Developer",
        b"/tmp\n/private\n",
        b"relative\n",
        b"/a/../b\n",
        b"/a/./b\n",
        b"/a//b\n",
        b"/a\x00b\n",
        b"/a\rb\n",
        b"/\xff\n",
        b"/" + b"a" * 4096 + b"\n",
    ],
)
def test_selection_output_must_be_one_bounded_absolute_path(data):
    with pytest.raises(ValueError):
        observer.selected_path(data)


@pytest.mark.parametrize(
    "value,shape",
    [
        ("/Applications/Xcode_16.4.app/Contents/Developer", "xcode_developer"),
        ("/Library/Developer/CommandLineTools", "command_line_tools"),
        ("/private/elsewhere", "other_absolute"),
    ],
)
def test_selection_classification_exports_fixed_categories(value, shape):
    assert observer.selection_shape(observer.selected_path(value.encode() + b"\n")) == shape


def test_environment_exports_only_shape_length_and_hash(monkeypatch):
    monkeypatch.delenv("SDKROOT", raising=False)
    monkeypatch.setenv("DEVELOPER_DIR", "/private/person/project")
    result = observer.environment_identity()
    assert result["SDKROOT"] == {"present": False}
    assert result["DEVELOPER_DIR"] == {
        "present": True,
        "shape": "absolute_path",
        "bytes": 23,
        "sha256": hashlib.sha256(b"/private/person/project").hexdigest(),
    }
    assert "person" not in json.dumps(result)
    monkeypatch.setenv("SDKROOT", "a" * 5000)
    assert observer.environment_identity()["SDKROOT"]["shape"] == "over_limit"


def test_stable_plist_capture_uses_actual_bytes_and_refuses_nonregular_or_large_files(tmp_path):
    path = tmp_path / "Info.plist"
    data = plistlib.dumps({"CFBundleIdentifier": "com.apple.dt.Xcode"})
    path.write_bytes(data)
    assert observer.stable_bytes(path) == data
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        observer.stable_bytes(link)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        observer.stable_bytes(fifo)
    path.write_bytes(b"x" * (observer.PLIST_LIMIT + 1))
    with pytest.raises(ValueError):
        observer.stable_bytes(path)


def test_selected_bundle_metadata_omits_private_fields_and_unrecognized_versions(monkeypatch):
    selected = Path("/Applications/Xcode.app/Contents/Developer")
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: self)
    data = plistlib.dumps(
        {
            "CFBundleIdentifier": "com.apple.dt.Xcode",
            "CFBundleShortVersionString": "16.4",
            "CFBundleVersion": "23717",
            "DTXcodeBuild": "16F6",
            "PrivateName": "private.example.invalid",
        }
    )
    seen = []
    monkeypatch.setattr(observer, "stable_bytes", lambda p: seen.append(p) or data)
    result = observer.bundle_identity(selected)
    assert seen == [Path("/Applications/Xcode.app/Contents/Info.plist")]
    assert result["bundle_identifier_matches_xcode"] and result["CFBundleShortVersionString"] == "16.4"
    assert result["plist_sha256"] == hashlib.sha256(data).hexdigest() and "private" not in json.dumps(result)
    data = plistlib.dumps({"CFBundleShortVersionString": "/private/person", "CFBundleIdentifier": "private"})
    result = observer.bundle_identity(selected)
    assert not result["CFBundleShortVersionString_valid"] and not result["bundle_identifier_matches_xcode"]
    assert "person" not in json.dumps(result)


def test_unsupported_or_redirected_bundle_is_not_read(monkeypatch):
    monkeypatch.setattr(observer, "stable_bytes", lambda _: pytest.fail("unexpected file read"))
    assert (
        observer.bundle_identity(Path("/private/Other.app/Contents/Developer"))["status"]
        == "unsupported_selection_shape"
    )
    monkeypatch.setattr(Path, "resolve", lambda self, strict=False: Path("/private/Xcode.app/Contents/Developer"))
    assert (
        observer.bundle_identity(Path("/Applications/Xcode.app/Contents/Developer"))["status"]
        == "unsupported_resolved_selection"
    )


def configured(monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    prepared = observer.original._base() | {
        "status": "identity_failed",
        "stage": "tool_identity",
        "source": {"head": "a" * 40},
        "identity_command_failure": {
            "operation": "clang",
            "direct_child_reaped": True,
            "completed_without_intervention": False,
            "status": "deadline_exceeded",
        },
    }
    monkeypatch.setattr(observer.original, "_eligible", lambda: True)
    monkeypatch.setattr(observer.original, "source_identity", lambda: prepared["source"])
    monkeypatch.setattr(observer, "file_sha", lambda *args, **kwargs: "b" * 64)
    monkeypatch.setattr(
        observer, "environment_identity", lambda: {"DEVELOPER_DIR": {"present": False}, "SDKROOT": {"present": False}}
    )
    monkeypatch.setattr(
        observer,
        "bundle_identity",
        lambda _: {"status": "observed", "plist_sha256": "c" * 64, "bundle_identifier_matches_xcode": True},
    )
    return prepared


def success_capture():
    raw = b"/Applications/Xcode.app/Contents/Developer\n"
    return {
        "argv": list(observer.COMMAND),
        "completed_without_intervention": True,
        "direct_child_reaped": True,
        "stderr_bytes": 0,
        "stdout": raw.decode("utf-8"),
        "stdout_bytes": len(raw),
        "stderr": "",
        "termination_attempted": False,
        "status": "completed",
        "return_code": 0,
        "stdout_sha256": hashlib.sha256(raw).hexdigest(),
    }


def test_successful_selection_never_changes_the_retained_original_failure(monkeypatch):
    prepared = configured(monkeypatch)
    before = copy.deepcopy(prepared)
    calls = []
    monkeypatch.setattr(observer, "_capture", lambda args: calls.append(args) or success_capture())
    report = observer.collect(prepared, "d" * 64)
    assert calls == [("/usr/bin/xcode-select", "--print-path")]
    assert prepared == before and report["observation_complete"] and report["selected_xcode_bundle_identity_verified"]
    assert not report["diagnostic_passed"] and not report["qualification_pass"] and not report["xcrun_retried"]
    assert not report["selection_modified"] and not report["selection_requeried"]
    assert "Xcode.app" not in json.dumps(report) and "stdout" not in report["capture"]


@pytest.mark.parametrize(
    "key,value",
    [
        ("status", "prepared"),
        ("stage", "complete"),
        ("workflow_commit", "b" * 40),
        ("workflow_run", "456"),
        ("workflow_attempt", "2"),
        ("diagnostic_passed", True),
        ("qualification_pass", True),
    ],
)
def test_nonmatching_original_failure_cannot_run_any_command(monkeypatch, key, value):
    prepared = configured(monkeypatch)
    prepared[key] = value
    monkeypatch.setattr(observer, "_capture", lambda _: pytest.fail("command must not run"))
    assert observer.collect(prepared, "d" * 64)["status"] == "original_failure_not_admitted"


@pytest.mark.parametrize(
    "key,value", [("operation", "sdk"), ("direct_child_reaped", False), ("completed_without_intervention", True)]
)
def test_original_child_must_be_retired_and_the_clang_identity_actually_failed(monkeypatch, key, value):
    prepared = configured(monkeypatch)
    prepared["identity_command_failure"][key] = value
    monkeypatch.setattr(observer, "_capture", lambda _: pytest.fail("command must not run"))
    assert observer.collect(prepared, "d" * 64)["status"] == "original_failure_not_admitted"


@pytest.mark.parametrize("code,stderr,admitted", [(72, 535, True), (0, 1, True), (0, 0, False), (True, 0, False)])
def test_original_natural_failure_is_distinct_from_clean_success(monkeypatch, code, stderr, admitted):
    prepared = configured(monkeypatch)
    prepared["identity_command_failure"].update(
        status="completed", completed_without_intervention=True, return_code=code, stderr_bytes=stderr
    )
    calls = []
    monkeypatch.setattr(observer, "_capture", lambda args: calls.append(args) or success_capture())
    report = observer.collect(prepared, "d" * 64)
    assert bool(calls) == admitted and not report["diagnostic_passed"]


def test_observer_deadline_retains_failure_without_retry(monkeypatch):
    prepared = configured(monkeypatch)
    calls = []
    capture = success_capture() | {
        "completed_without_intervention": False,
        "status": "deadline_exceeded",
        "return_code": -9,
    }
    monkeypatch.setattr(observer, "_capture", lambda args: calls.append(args) or capture)
    report = observer.collect(prepared, "d" * 64)
    assert report["status"] == "selection_command_failed" and len(calls) == 1 and not report["observation_complete"]
    assert report["capture"]["return_code"] == -9


@pytest.mark.parametrize(
    "output,code,expected",
    [
        (b"/Applications/Xcode.app/Contents/Developer\n", 0, "observation_finished"),
        (b"/Applications/Xcode.app/Contents/Developer\n", 7, "selection_command_failed"),
        (b"/Applications/Xcode\xff.app/Contents/Developer\n", 0, "observation_failed"),
    ],
)
def test_actual_capture_schema_is_composed_with_selection_admission(monkeypatch, output, code, expected):
    prepared = configured(monkeypatch)
    actual_capture = observer._capture
    calls = []

    def composed(arguments):
        assert arguments == observer.COMMAND
        calls.append(arguments)
        return actual_capture(
            (sys.executable, "-I", "-c", f"import sys;sys.stdout.buffer.write({output!r});sys.exit({code})")
        )

    monkeypatch.setattr(observer, "_capture", composed)
    report = observer.collect(prepared, "d" * 64)
    assert calls == [observer.COMMAND] and report["status"] == expected
    assert report["capture"]["return_code"] == code and report["capture"]["direct_child_reaped"]
    assert report["observation_complete"] == (expected == "observation_finished")
    assert not report["diagnostic_passed"] and not report["qualification_pass"]


@pytest.mark.parametrize(
    "key,value",
    [
        ("return_code", True),
        ("return_code", 5),
        ("direct_child_reaped", False),
        ("termination_attempted", True),
        ("stderr_bytes", 1),
        ("stdout_truncated", True),
        ("cleanup_error", "TimeoutExpired"),
    ],
)
def test_natural_output_does_not_override_failed_capture_accounting(monkeypatch, key, value):
    prepared = configured(monkeypatch)
    captured = success_capture()
    captured[key] = value
    monkeypatch.setattr(observer, "_capture", lambda _: captured)
    report = observer.collect(prepared, "d" * 64)
    assert report["status"] == "selection_command_failed" and not report["observation_complete"]


def test_main_binds_actual_failed_preparation_and_preserves_it(tmp_path, monkeypatch):
    prepared = configured(monkeypatch)
    path = tmp_path / "prepared.json"
    path.write_text(json.dumps(prepared))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(observer, "file_sha", lambda source, **kwargs: digest if source == path else "b" * 64)
    monkeypatch.setattr(observer, "_capture", lambda _: success_capture())
    output = tmp_path / "selection.json"
    monkeypatch.setattr(sys, "argv", ["observer", "--prepared", str(path), "--output", str(output)])
    assert observer.main() == 0
    result = json.loads(output.read_bytes())
    assert result["prepared_sha256"] == digest and result["prepared_unchanged"] and not result["diagnostic_passed"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    prepared["identity_command_failure"]["direct_child_reaped"] = False
    path.write_text(json.dumps(prepared))
    monkeypatch.setattr(observer, "_capture", lambda _: pytest.fail("must not run a command"))
    assert observer.main() == 1
    assert json.loads(output.read_bytes())["status"] == "original_failure_not_admitted"


def test_invalid_selected_plist_error_is_sanitized(monkeypatch):
    prepared = configured(monkeypatch)
    monkeypatch.setattr(observer, "_capture", lambda _: success_capture())

    def invalid(_):
        raise ValueError("private malformed plist content")

    monkeypatch.setattr(observer, "bundle_identity", invalid)
    result = observer.collect(prepared, "d" * 64)
    assert result["status"] == "observation_failed" and result["error_type"] == "ValueError"
    assert "private malformed" not in json.dumps(result)


@pytest.mark.parametrize("binding", ["source_identity", "environment_identity", "bundle_identity", "file_sha"])
def test_changed_identity_invalidates_observation(monkeypatch, binding):
    prepared = configured(monkeypatch)
    monkeypatch.setattr(observer, "_capture", lambda _: success_capture())
    owner = observer.original if binding == "source_identity" else observer
    real = getattr(owner, binding)
    calls = []

    def changing(*args, **kwargs):
        calls.append(True)
        return (
            real(*args, **kwargs)
            if len(calls) <= (2 if binding == "file_sha" else 1)
            else ("e" * 64 if binding == "file_sha" else {})
        )

    monkeypatch.setattr(owner, binding, changing)
    assert not observer.collect(prepared, "d" * 64)["observation_complete"]


def test_workflow_observation_is_only_post_failure_and_has_no_retry_or_switch():
    root = observer.original.ROOT
    source = (root / "scripts/ci/native_macos_xcode_selection.py").read_text()
    tree = ast.parse(source)
    calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_capture"
    ]
    assert len(calls) == 1 and ast.unparse(calls[0].args[0]) == "COMMAND"
    assert observer.COMMAND == ("/usr/bin/xcode-select", "--print-path")
    workflow = (root / ".github/workflows/native-macos-resolver-path.yml").read_text()
    assert "always() && matrix.architecture == 'x86_64' && steps.prepare.outcome == 'failure'" in workflow
    assert workflow.index("id: dnssd_lookups") < workflow.index("id: xcode_selection")
    assert "scripts/ci/native_macos_xcode_selection.py" in observer.original.SOURCES
    assert "tests/test_native_macos_xcode_selection.py" in observer.original.SOURCES
