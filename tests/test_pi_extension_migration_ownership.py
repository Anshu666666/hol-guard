"""Ownership boundaries for migration of the former combined Pi installation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.pi import (
    legacy_omp_managed_extension_is_verified,
    remove_legacy_omp_managed_extension,
)
from codex_plugin_scanner.guard.adapters.pi_extension_migration_source import legacy_managed_extension_source
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.cli import update_commands


def _seed_extension(
    tmp_path: Path,
    *,
    legacy_format: bool,
    harness: str = "pi",
    install_harness: str = "omp",
    modified: bool = False,
) -> tuple[HarnessContext, Path, Path, dict[str, object]]:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace_dir=None,
    )
    settings_path = context.home_dir / f".{install_harness}" / "agent" / "settings.json"
    extension_path = settings_path.parent / "extensions" / "hol-guard.ts"
    extension_path.parent.mkdir(parents=True)
    generator = legacy_managed_extension_source if legacy_format else managed_extension_source
    source = generator(
        guard_home=context.guard_home,
        home_dir=context.home_dir,
        settings_path=settings_path,
        harness=harness,
        display_name="Pi" if harness == "pi" else "Oh My Pi",
    )
    if modified:
        source += "\n// User-owned customization must survive Pi cleanup.\n"
    extension_path.write_text(source, encoding="utf-8")
    settings_path.write_text(
        json.dumps({"extensions": [str(extension_path), "./user-extension.ts"], "theme": "custom"}) + "\n",
        encoding="utf-8",
    )
    pi_extension_path = context.home_dir / ".pi" / "agent" / "extensions" / "hol-guard.ts"
    pi_install: dict[str, object] = {"active": True, "manifest": {"config_path": str(pi_extension_path)}}
    return context, extension_path, settings_path, pi_install


@pytest.mark.parametrize("legacy_format", [False, True], ids=["current", "pre-response-contract"])
@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize("modified", [False, True], ids=["original", "user-modified"])
def test_legacy_omp_cleanup_requires_unchanged_pi_owned_source(
    tmp_path: Path,
    legacy_format: bool,
    harness: str,
    modified: bool,
) -> None:
    context, extension_path, settings_path, pi_install = _seed_extension(
        tmp_path, legacy_format=legacy_format, harness=harness, modified=modified
    )
    original_source = extension_path.read_bytes()
    original_settings = settings_path.read_bytes()
    owned = harness == "pi" and not modified

    assert legacy_omp_managed_extension_is_verified(context, pi_install) is owned
    assert extension_path.read_bytes() == original_source
    assert settings_path.read_bytes() == original_settings

    assert remove_legacy_omp_managed_extension(context) is owned

    if owned:
        assert not extension_path.exists()
        assert json.loads(settings_path.read_text(encoding="utf-8")) == {
            "extensions": ["./user-extension.ts"],
            "theme": "custom",
        }
    else:
        assert extension_path.read_bytes() == original_source
        assert settings_path.read_bytes() == original_settings


@pytest.mark.parametrize("legacy_format", [False, True], ids=["current", "pre-response-contract"])
@pytest.mark.parametrize("missing_proof", ["active-install", "manifest", "pi-path", "omp-registration"])
def test_legacy_omp_migration_requires_complete_pi_install_ownership(
    tmp_path: Path,
    legacy_format: bool,
    missing_proof: str,
) -> None:
    context, extension_path, settings_path, pi_install = _seed_extension(tmp_path, legacy_format=legacy_format)
    if missing_proof == "active-install":
        pi_install["active"] = False
    elif missing_proof == "manifest":
        pi_install.pop("manifest")
    elif missing_proof == "pi-path":
        pi_install["manifest"] = {"config_path": str(extension_path)}
    else:
        settings_path.write_text('{"extensions": ["./user-extension.ts"], "theme": "custom"}\n', encoding="utf-8")
    original_source = extension_path.read_bytes()
    original_settings = settings_path.read_bytes()

    assert not legacy_omp_managed_extension_is_verified(context, pi_install)

    assert extension_path.read_bytes() == original_source
    assert settings_path.read_bytes() == original_settings


@pytest.mark.parametrize("legacy_format", [False, True], ids=["current", "pre-response-contract"])
@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_legacy_owned_source_is_not_reported_current(
    tmp_path: Path,
    legacy_format: bool,
    harness: str,
) -> None:
    context, extension_path, settings_path, _pi_install = _seed_extension(
        tmp_path,
        legacy_format=legacy_format,
        harness=harness,
        install_harness=harness,
    )
    original_source = extension_path.read_bytes()
    original_settings = settings_path.read_bytes()

    assert update_commands._pi_family_extension_is_current(harness=harness, context=context) is not legacy_format

    assert extension_path.read_bytes() == original_source
    assert settings_path.read_bytes() == original_settings
