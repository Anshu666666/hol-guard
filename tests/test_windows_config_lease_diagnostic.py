"""Negative controls for the isolated Windows lease diagnostic evidence."""

from __future__ import annotations

import ctypes
import json
import subprocess
import sys
import types
import warnings
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from scripts.ci import windows_config_lease_diagnostic as diagnostic  # noqa: E402
from scripts.ci import windows_config_lease_evidence as evidence  # noqa: E402


@pytest.mark.parametrize("code", [2, 3, 5, 32, 80, 183])
def test_original_open_exception_keeps_class_code_identity_and_explicit_cause(monkeypatch, code):
    from codex_plugin_scanner import safe_output_windows as original
    from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError

    monkeypatch.setattr(ctypes, "get_last_error", lambda: code, raising=False)
    monkeypatch.setattr(ctypes, "FormatError", lambda _: "private-exception-message", raising=False)
    api = types.SimpleNamespace(create_file=lambda *_: original._INVALID_HANDLE_VALUE)
    with pytest.raises(OSError) as raised:
        original._open_locked_directory(api, Path("private-path-value"))
    error = raised.value
    category = type(error)
    args = error.args
    original_traceback = error.__traceback__
    assert diagnostic._sharing_rejection(error, config=False) is (code == 32)
    detail = evidence.exception_record(error)
    assert raised.value is error
    assert type(error) is category
    assert error.args is args
    assert error.__traceback__ is original_traceback
    assert error.errno == code
    assert detail["chain"][0]["category"] == category.__name__
    assert detail["chain"][0]["errno"] == code
    assert "private-path-value" not in json.dumps(detail)
    assert "private-exception-message" not in json.dumps(detail)
    assert any(frame["line"] == 218 for frame in detail["chain"][0]["stack"])
    try:
        raise GuardConfigSourceError("private-config-message") from error
    except GuardConfigSourceError as wrapped:
        assert diagnostic._sharing_rejection(wrapped, config=True) is (code == 32)
        assert wrapped.__cause__ is error
        assert "private-config-message" not in json.dumps(evidence.exception_record(wrapped))


def test_inspection_failure_with_same_numeric_code_is_not_an_open_rejection(monkeypatch):
    from codex_plugin_scanner import safe_output_windows as original

    closed = []
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 32, raising=False)
    monkeypatch.setattr(ctypes, "FormatError", lambda _: "private-message", raising=False)
    api = types.SimpleNamespace(
        create_file=lambda *_: 71,
        inspect_file=lambda *_: False,
        close_handle=closed.append,
    )
    with pytest.raises(OSError) as raised:
        original._open_locked_directory(api, Path("private-path"))
    assert closed == [71]
    assert not diagnostic._sharing_rejection(raised.value, config=False)
    assert any(frame["line"] == 222 for frame in evidence.exception_record(raised.value)["chain"][0]["stack"])


def test_reparse_rejection_is_not_relabelled_as_sharing(monkeypatch):
    from codex_plugin_scanner import safe_output_windows as original

    def inspect(_handle, information):
        information.file_attributes = original._FILE_ATTRIBUTE_REPARSE_POINT
        return True

    closed = []
    api = types.SimpleNamespace(create_file=lambda *_: 71, inspect_file=inspect, close_handle=closed.append)
    with pytest.raises(OSError) as raised:
        original._open_locked_directory(api, Path("private-path"))
    assert closed == [71]
    assert not diagnostic._sharing_rejection(raised.value, config=False)


def test_unrelated_numeric_error_does_not_establish_sharing_cause():
    assert not diagnostic._sharing_rejection(BrokenPipeError(32, "unrelated"), config=False)


def test_checkout_binding_rejects_wrong_commit_and_tracked_modification(tmp_path):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(tmp_path), *args], stderr=subprocess.DEVNULL).decode().strip()

    git("init")
    (tmp_path / "control").write_bytes(b"original\n")
    git("add", "control")
    git("-c", "user.name=Finite Control", "-c", "user.email=control@example.invalid", "commit", "-m", "control")
    commit = git("rev-parse", "HEAD")
    assert evidence.checkout_binding(tmp_path, commit)["tracked_files_unchanged"]
    with pytest.raises(RuntimeError, match="commit_mismatch"):
        evidence.checkout_binding(tmp_path, "0" * 40)
    (tmp_path / "control").write_bytes(b"changed\n")
    with pytest.raises(RuntimeError, match="checkout_changed"):
        evidence.checkout_binding(tmp_path, commit)
    git("checkout", "--", "control")
    (tmp_path / "untracked").write_bytes(b"untracked\n")
    with pytest.raises(RuntimeError, match="checkout_changed"):
        evidence.checkout_binding(tmp_path, commit)


@pytest.fixture
def installed_fixture(tmp_path, monkeypatch):
    source = tmp_path / "source"
    package = source / "src/codex_plugin_scanner"
    package.mkdir(parents=True)
    (source / "pyproject.toml").write_text(
        '[tool.hatch.build.targets.wheel.force-include]\n"contract.json" = "codex_plugin_scanner/data/contract.json"\n'
    )
    (source / "contract.json").write_text('{"original": true}\n')
    (package / "__init__.py").write_text('"""Finite package."""\n')
    (package / "control.py").write_text("VALUE = 1\n")
    for args in (
        ("init",),
        ("add", "."),
        ("-c", "user.name=Finite Control", "-c", "user.email=control@example.invalid", "commit", "-m", "source"),
    ):
        subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True)
    purelib = tmp_path / "environment/site-packages"
    installed = purelib / "codex_plugin_scanner"
    installed.mkdir(parents=True)
    members = {
        "codex_plugin_scanner/__init__.py": (package / "__init__.py").read_bytes(),
        "codex_plugin_scanner/control.py": (package / "control.py").read_bytes(),
        "codex_plugin_scanner/data/contract.json": (source / "contract.json").read_bytes(),
    }
    wheel = tmp_path / "finite.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
            output = purelib / name
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(payload)
    monkeypatch.setattr(evidence, "sys", types.SimpleNamespace(prefix="venv", base_prefix="base"))
    monkeypatch.setattr(evidence, "sysconfig", types.SimpleNamespace(get_path=lambda _: str(purelib)))
    monkeypatch.delenv("PYTHONPATH", raising=False)
    return source, wheel, installed


def test_installed_binding_checks_python_and_force_included_contract_bytes(installed_fixture):
    source, wheel, installed = installed_fixture
    record = evidence.installed_binding(source, wheel, installed)
    assert record["installed_from_wheel"]
    assert len(record["members"]) == 3
    (installed / "data/contract.json").write_bytes(b"{}")
    with pytest.raises(RuntimeError, match="installed_wheel_mismatch"):
        evidence.installed_binding(source, wheel, installed)


@pytest.mark.parametrize("changed", ["source", "installed", "extra", "duplicate"])
def test_installed_binding_rejects_mismatches_and_ambiguous_members(installed_fixture, changed):
    source, wheel, installed = installed_fixture
    if changed == "source":
        (source / "src/codex_plugin_scanner/control.py").write_text("VALUE = 2\n")
    elif changed == "installed":
        (installed / "control.py").write_text("VALUE = 2\n")
    elif changed == "extra":
        (installed / "unrecorded.py").write_text("VALUE = 3\n")
    else:
        with warnings.catch_warnings(), zipfile.ZipFile(wheel, "a") as archive:
            warnings.simplefilter("ignore", UserWarning)
            archive.writestr("codex_plugin_scanner/control.py", b"VALUE = 1\n")
    with pytest.raises(RuntimeError):
        evidence.installed_binding(source, wheel, installed)


def test_installed_binding_rejects_source_import_and_pythonpath(installed_fixture, monkeypatch):
    source, wheel, installed = installed_fixture
    monkeypatch.setenv("PYTHONPATH", str(source / "src"))
    with pytest.raises(RuntimeError, match="pythonpath_must_be_unset"):
        evidence.installed_binding(source, wheel, installed)
    monkeypatch.delenv("PYTHONPATH")
    with pytest.raises(RuntimeError, match="installed_package_location_mismatch"):
        evidence.installed_binding(source, wheel, source / "src/codex_plugin_scanner")


def test_exception_chain_is_bounded_and_does_not_serialize_messages():
    errors = [RuntimeError(f"private-message-{index}") for index in range(6)]
    for index in range(len(errors) - 1):
        errors[index].__cause__ = errors[index + 1]
    errors[-1].__cause__ = errors[0]
    detail = evidence.exception_record(errors[0])
    assert len(detail["chain"]) == 4
    assert detail["chain_truncated"]
    assert "private-message" not in json.dumps(detail)


def test_reports_do_not_overwrite_original_results_or_exceed_bound(tmp_path):
    output = tmp_path / "report.json"
    evidence.write_report(output, {"passed": False})
    original = output.read_bytes()
    with pytest.raises(FileExistsError):
        evidence.write_report(output, {"passed": True})
    assert output.read_bytes() == original
    with pytest.raises(RuntimeError, match="report_size_limit"):
        evidence.write_report(tmp_path / "oversized.json", {"value": "a" * evidence.MAX_REPORT_BYTES})
    assert not (tmp_path / "oversized.json").exists()


def test_build_refuses_wrong_source_before_backend_hooks(installed_fixture, tmp_path):
    source, _, _ = installed_fixture
    output = tmp_path / "build-output"
    report = tmp_path / "build-report.json"
    assert evidence.build_wheel(source, output, report) == 1
    result = json.loads(report.read_text())
    assert not result["passed"]
    assert not result["build_dependencies_fully_locked"]
    assert result["failure"]["chain"][0]["diagnostic_code"] == "checkout_commit_mismatch"
    assert "backend_before_requires_hook" not in result
    assert not output.exists()
