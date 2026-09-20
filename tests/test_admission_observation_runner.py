"""Admission binding and diagnostic export cannot erase an original result."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from ci.native_runtime import admission_observation_binding as binding
from ci.native_runtime.admission_observation_capture import AdmissionCapture
from ci.native_runtime.admission_observation_run import observe_once
from tests.test_admission_observation import fixture


@pytest.mark.parametrize("result", [0, 7])
def test_original_return_survives_export_failure(result, capsys):
    probe, routes, _, _, _ = fixture()
    calls = []
    exports = []

    def original():
        calls.append(1)
        return result

    def export(report):
        exports.append(report)
        raise KeyboardInterrupt("private export")

    assert observe_once(original, AdmissionCapture(probe, routes), export) == result
    assert calls == [1] and exports[0]["original_outcome"] == {"returned": True, "returncode": result}
    assert capsys.readouterr().err == "admission_observation_export_failed\n"


def test_original_exception_survives_export_failure(capsys):
    probe, routes, _, _, _ = fixture()
    error = KeyboardInterrupt("private original")
    calls = []

    def original():
        calls.append(1)
        raise error

    def export(report):
        assert report["original_outcome"] == {"returned": False, "returncode": None}
        raise OSError("private export")

    with pytest.raises(KeyboardInterrupt) as caught:
        observe_once(original, AdmissionCapture(probe, routes), export)
    assert caught.value is error and calls == [1]
    assert capsys.readouterr().err == "admission_observation_export_failed\n"


def test_installed_origin_accepts_nested_venv_and_rejects_source(tmp_path):
    prefix = tmp_path / ".venv"
    binding.installed_origin(prefix / "Lib/site-packages/codex_plugin_scanner", tmp_path, prefix)
    with pytest.raises(RuntimeError, match="admission_installed_package_required"):
        binding.installed_origin(tmp_path / "src/codex_plugin_scanner", tmp_path, prefix)
    with pytest.raises(RuntimeError, match="admission_installed_package_required"):
        binding.installed_origin(tmp_path / "foreign/codex_plugin_scanner", tmp_path, prefix)


def wheel_fixture(tmp_path: Path, *, source: str = binding.SOURCE_SHA):
    package = tmp_path / "package"
    native = package / "_native"
    native.mkdir(parents=True)
    (native / "hol-guard-runtime.exe").write_bytes(b"synthetic-runtime-control")
    (native / "runtime-manifest.json").write_text(
        json.dumps({"source_sha": source, "target": "x86_64-pc-windows-msvc"})
    )
    wheel = tmp_path / "synthetic.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for path in native.iterdir():
            archive.write(path, "codex_plugin_scanner/_native/" + path.name)
    return wheel, package


def test_wheel_binding_joins_installed_members_but_claims_only_new_build(tmp_path):
    wheel, package = wheel_fixture(tmp_path)
    report = binding.wheel_binding(wheel, package)
    assert report["new_isolated_build"] and report["historical_failed_executable"] is False
    assert report["wheel_sha256"] == hashlib.sha256(wheel.read_bytes()).hexdigest()
    (package / "_native/hol-guard-runtime.exe").write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="admission_installed_member_changed"):
        binding.wheel_binding(wheel, package)


def test_wrong_build_source_refuses_even_when_wheel_and_installed_bytes_agree(tmp_path):
    wheel, package = wheel_fixture(tmp_path, source="0" * 40)
    with pytest.raises(RuntimeError, match="admission_native_build_source_changed"):
        binding.wheel_binding(wheel, package)


def test_exact_source_guards_accept_lf_crlf_and_refuse_changed_bytes(tmp_path, monkeypatch):
    fixture_root = tmp_path / "fixture"
    package = tmp_path / "package"
    package.mkdir()
    fixture_root.mkdir()
    body = b"exact source\n"
    (package / "module.py").write_bytes(body.replace(b"\n", b"\r\n"))
    (fixture_root / "fixture.json").write_bytes(body)
    monkeypatch.setattr(
        binding,
        "GUARDS",
        {
            "src/codex_plugin_scanner/module.py": hashlib.sha256(body).hexdigest(),
            "fixture.json": hashlib.sha256(body).hexdigest(),
        },
    )
    report = binding.source_binding(package, fixture_root)
    assert len(report) == 2 and report[0]["actual_sha256"] != report[0]["lf_sha256"]
    (package / "module.py").write_bytes(b"changed\n")
    with pytest.raises(RuntimeError, match="admission_source_bytes_changed"):
        binding.source_binding(package, fixture_root)


def test_all_declared_source_guards_match_exact_checkout():
    root = Path(__file__).resolve().parents[1]
    report: Any = binding.source_binding(root / "src/codex_plugin_scanner", root)
    assert len(report) == len(binding.GUARDS) == 22
