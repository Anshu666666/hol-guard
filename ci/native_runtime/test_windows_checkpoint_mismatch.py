"""Synthetic controls for refusal-only source-byte evidence."""

from __future__ import annotations

from types import ModuleType

import pytest

from ci.native_runtime import windows_checkpoint_mismatch as mismatch


def rig(tmp_path, source_bytes=b"VALUE = 1\n", installed_bytes=b"VALUE = 1\r\n"):
    relative = "codex_plugin_scanner/__init__.py"
    source_file = tmp_path / "src" / relative
    source_file.parent.mkdir(parents=True)
    source_file.write_bytes(source_bytes)
    installed_file = tmp_path / ".venv" / "Lib" / "site-packages" / relative
    installed_file.parent.mkdir(parents=True)
    installed_file.write_bytes(installed_bytes)
    manifest = {
        "source": {
            "files": {
                "src/" + relative: {
                    "blob": "a" * 40,
                    "bytes": len(source_bytes),
                    "sha256": mismatch.digest(source_bytes),
                }
            }
        }
    }
    record = {"bytes": len(installed_bytes), "sha256": mismatch.digest(installed_bytes)}
    installation = {"wheel_files": {relative: record}, "installed_record_files": {relative: record.copy()}}
    module = ModuleType("codex_plugin_scanner")
    module.__file__ = str(installed_file)
    return relative, source_file, installed_file, manifest, installation, module


@pytest.mark.parametrize(
    ("installed_bytes", "raw_matches", "candidate_matches"),
    [(b"VALUE = 1\n", True, False), (b"VALUE = 1\r\n", False, True), (b"VALUE = 2\n", False, False)],
)
def test_raw_crlf_and_different_bytes_are_distinct(tmp_path, installed_bytes, raw_matches, candidate_matches):
    relative, _source, _installed, manifest, installation, module = rig(tmp_path, installed_bytes=installed_bytes)
    report = mismatch.compare_source_bytes(tmp_path, manifest, installation)
    mismatch.capture_imports(tmp_path, report, {"codex_plugin_scanner": module})
    row = report["comparisons"][relative]
    assert row["raw_matches_wheel"] is raw_matches
    assert row["candidate_matches_wheel"] is candidate_matches
    assert row["installed_matches_wheel"] is True
    assert report["strict_source_admission_unchanged"] is True
    assert report["transformed_source_admitted"] is False
    if raw_matches:
        assert report["first_mismatching_import"] is None
    else:
        assert report["first_mismatching_import"]["path"] == relative
        assert report["first_mismatching_import"]["matches_lf_to_crlf_candidate"] is candidate_matches


def test_mixed_or_existing_cr_source_is_not_normalized(tmp_path):
    relative, _source, _installed, manifest, installation, _module = rig(tmp_path, source_bytes=b"VALUE = 1\r\n")
    report = mismatch.compare_source_bytes(tmp_path, manifest, installation)
    assert report["comparisons"][relative]["lf_to_crlf_candidate"] is None
    assert report["comparisons"][relative]["candidate_matches_wheel"] is False


def test_installed_record_difference_stays_visible(tmp_path):
    relative, _source, _installed, manifest, installation, module = rig(tmp_path)
    installation["installed_record_files"][relative] = {"bytes": 1, "sha256": "0" * 64}
    report = mismatch.compare_source_bytes(tmp_path, manifest, installation)
    mismatch.capture_imports(tmp_path, report, {"codex_plugin_scanner": module})
    assert report["comparisons"][relative]["installed_matches_wheel"] is False
    assert report["first_mismatching_import"]["matches_recorded_install"] is False


def test_changed_raw_source_refuses_report(tmp_path):
    _relative, source, _installed, manifest, installation, _module = rig(tmp_path)
    source.write_bytes(b"VALUE = 2\n")
    with pytest.raises(RuntimeError, match="mismatch_source_hash_changed"):
        mismatch.compare_source_bytes(tmp_path, manifest, installation)


def test_import_outside_exact_prefix_refuses_without_exporting_path(tmp_path):
    _relative, source, _installed, manifest, installation, module = rig(tmp_path)
    module.__file__ = str(source)
    report = mismatch.compare_source_bytes(tmp_path, manifest, installation)
    with pytest.raises(RuntimeError, match="mismatch_import_outside_prefix") as caught:
        mismatch.capture_imports(tmp_path, report, {"codex_plugin_scanner": module})
    assert str(tmp_path) not in str(caught.value)


def test_untracked_import_does_not_export_its_name(tmp_path):
    _relative, _source, installed, manifest, installation, module = rig(tmp_path)
    private = installed.with_name("private_fixture.py")
    private.write_bytes(b"VALUE = 1\n")
    module.__file__ = str(private)
    report = mismatch.compare_source_bytes(tmp_path, manifest, installation)
    mismatch.capture_imports(tmp_path, report, {"codex_plugin_scanner": module})
    assert report["first_mismatching_import"] == {"position": 0, "source_path_admitted": False}
    assert "private_fixture" not in repr(report)


def test_loaded_file_difference_stays_visible(tmp_path):
    _relative, _source, installed, manifest, installation, module = rig(tmp_path)
    report = mismatch.compare_source_bytes(tmp_path, manifest, installation)
    installed.write_bytes(b"VALUE = 3\n")
    mismatch.capture_imports(tmp_path, report, {"codex_plugin_scanner": module})
    assert report["first_mismatching_import"]["matches_recorded_install"] is False
    assert report["first_mismatching_import"]["matches_lf_to_crlf_candidate"] is False


def test_loaded_growth_after_stat_refuses_before_hashing(tmp_path, monkeypatch):
    _relative, _source, installed, manifest, installation, module = rig(tmp_path)
    report = mismatch.compare_source_bytes(tmp_path, manifest, installation)
    original = type(installed).read_bytes

    def read_bytes(path):
        if path == installed:
            return b"x" * (4 * 1024 * 1024 + 1)
        return original(path)

    monkeypatch.setattr(type(installed), "read_bytes", read_bytes)
    with pytest.raises(RuntimeError, match="mismatch_import_byte_bound"):
        mismatch.capture_imports(tmp_path, report, {"codex_plugin_scanner": module})
    assert "imported_files" not in report
