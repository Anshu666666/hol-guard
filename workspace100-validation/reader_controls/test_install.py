"""Bounded archive/source admission controls; fake runtime bytes never execute."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from install import SOURCE_EXCLUSION, admitted_wheel


def identity(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def fixture(tmp_path: Path, damage: str | None = None) -> tuple[Path, Path, dict[str, Any]]:
    source = tmp_path / "source"
    package = source / "src/codex_plugin_scanner"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"")
    (package / "implementation.py").write_bytes(b"value = 1\n")
    excluded = source / SOURCE_EXCLUSION
    excluded.parent.mkdir()
    excluded.write_bytes(b"legacy = True\n")
    exclusions = [] if damage == "exclusion_removed" else [SOURCE_EXCLUSION]
    if damage == "exclusion_extra":
        exclusions.append("src/codex_plugin_scanner/implementation.py")
    (source / "pyproject.toml").write_text("[tool.hatch.build]\nexclude = " + json.dumps(exclusions) + "\n")
    runtime = b"not executable; fixture only"
    manifest = {"source_sha": "a" * 40, "runtime_sha256": identity(runtime)["sha256"]}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as wheel:
        wheel.writestr("codex_plugin_scanner/__init__.py", b"")
        if damage != "omitted_module":
            wheel.writestr("codex_plugin_scanner/implementation.py", b"value = 1\n")
        if damage == "excluded_included":
            wheel.writestr(SOURCE_EXCLUSION.removeprefix("src/"), excluded.read_bytes())
        wheel.writestr("codex_plugin_scanner/_native/hol-guard-runtime", b"changed" if damage == "runtime" else runtime)
        wheel.writestr(
            "codex_plugin_scanner/_native/runtime-manifest.json", json.dumps({} if damage == "manifest" else manifest)
        )
        if damage == "package_roster":
            wheel.writestr("codex_plugin_scanner/extra.py", b"")
        if damage == "traversal":
            wheel.writestr("../outside", b"refused")
    raw = stream.getvalue()
    archive = tmp_path / "artifact.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("owned/wheel.whl", raw)
    spec = {
        "archive_identity": identity(archive.read_bytes()),
        "wheel_member": "owned/wheel.whl",
        "wheel_identity": identity(raw),
        "runtime_identity": identity(runtime),
        "runtime_manifest": manifest,
    }
    if damage == "archive":
        archive.write_bytes(archive.read_bytes() + b"changed")
    elif damage == "source":
        (package / "implementation.py").write_bytes(b"value = 2\n")
    return source, archive, spec


def test_exact_archive_wheel_runtime_source_and_empty_initializer_are_admitted(tmp_path: Path) -> None:
    source, archive, spec = fixture(tmp_path)
    wheel, result = admitted_wheel(archive, spec, source)
    assert identity(wheel) == spec["wheel_identity"]
    assert result["source_python_files_matched"] == 2
    assert result["configured_source_python_exclusions"] == [SOURCE_EXCLUSION]
    assert result["package_entries"]["codex_plugin_scanner/__init__.py"]["bytes"] == 0


@pytest.mark.parametrize(
    "damage",
    [
        "archive",
        "source",
        "runtime",
        "manifest",
        "package_roster",
        "traversal",
        "omitted_module",
        "excluded_included",
        "exclusion_removed",
        "exclusion_extra",
    ],
)
def test_any_mismatched_archive_or_executable_or_source_is_refused(tmp_path: Path, damage: str) -> None:
    source, archive, spec = fixture(tmp_path, damage)
    with pytest.raises(ValueError):
        admitted_wheel(archive, spec, source)
