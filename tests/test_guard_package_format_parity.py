"""Frozen format outcomes through the real evaluator, including malformed tails."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
from codex_plugin_scanner.guard.runtime.lockfile_parse_result import LOCKFILE_PARSER_VERSION
from codex_plugin_scanner.guard.stable_digest import stable_digest_hex
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_js_supply_chain_phase11 import _artifact_from_command
from tests.test_guard_supply_chain_evaluator import (
    WORKSPACE_ID,
    _bundle_response,
    _force_cloud_fallback,
    _package,
    _seed_guard_cloud,
)

NOW = "2026-05-19T00:00:00Z"

# Each vector has a complete dependency before the malformed suffix. None may
# publish that prefix as a complete result or silently become an empty success.
MALFORMED = (
    ("package-lock.json", "npm install", "npm", '{"packages":{"node_modules/demo":{"version":"1.0.0"}},"tail":'),
    ("pnpm-lock.yaml", "pnpm install", "npm", "packages:\n  demo@1.0.0:\n  truncated-entry\n"),
    ("yarn.lock", "yarn install", "npm", '"demo@^1":\n  version "1.0.0"\n"truncated@^2"\n'),
    ("bun.lock", "bun install", "npm", '{"packages":{"demo":["demo@1.0.0","",{}]},"tail":'),
    ("Cargo.lock", "cargo install --path .", "cargo", '[[package]]\nname="demo"\nversion="1.0.0"\n[[package]\n'),
    ("composer.lock", "composer install", "packagist", '{"packages":[{"name":"acme/demo","version":"1.0.0"}],"tail":'),
    ("Gemfile.lock", "bundle install", "rubygems", "GEM\n  specs:\n    demo (1.0.0)\n    unfinished (\n"),
    ("poetry.lock", "poetry install", "pypi", '[[package]]\nname="demo"\nversion="1.0.0"\n[[package]\n'),
    ("uv.lock", "uv sync", "pypi", '[[package]]\nname="demo"\nversion="1.0.0"\n[[package]\n'),
    ("Pipfile.lock", "pipenv sync", "pypi", '{"default":{"demo":{"version":"==1.0.0"}},"tail":'),
)


@pytest.mark.parametrize(("filename", "command", "ecosystem", "source"), MALFORMED, ids=[v[0] for v in MALFORMED])
def test_malformed_tail_discards_every_view_and_requires_review(
    filename: str, command: str, ecosystem: str, source: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / filename).write_text(source, encoding="utf-8")
    store = GuardStore(tmp_path / "guard")
    calls = []
    real_parse = evaluator.parse_lockfile_with_budget

    def counted(*args, **kwargs):
        result = real_parse(*args, **kwargs)
        calls.append(result)
        return result

    monkeypatch.setattr(evaluator, "parse_lockfile_with_budget", counted)
    result = evaluator.evaluate_package_request_artifact(
        artifact=_artifact_from_command(command, workspace=workspace), store=store, workspace_dir=workspace, now=NOW
    )

    assert len(calls) == 1
    parsed = calls[0]
    assert parsed.complete is False and parsed.error_reason == "syntax_error"
    assert parsed.entries == parsed.direct_version_candidates == ()
    assert parsed.manifest_dependencies is None
    assert parsed.dependency_map() == parsed.manifest_dependency_map() == {}
    assert parsed.text_direct_candidates == parsed.selector_version_candidates == ()
    assert result.decision == "ask" and result.policy_action == "require-reapproval"
    assert len(result.packages) == 1
    package = result.packages[0]
    assert (package["name"], package["ecosystem"]) == ("unresolved-lockfile", ecosystem)
    assert package["lockfileParseComplete"] is False
    assert package["lockfileParseError"] == "syntax_error"
    assert package["lockfileParserVersion"] == LOCKFILE_PARSER_VERSION
    assert package["lockfileHash"] == stable_digest_hex(source.encode())
    evidence = json.dumps(store.list_evidence(), sort_keys=True)
    assert package["lockfileHash"] in evidence and "lockfile_parse_incomplete" in evidence
    assert source not in evidence


ALIASES = (
    (
        "package-lock.json",
        "npm install friendly@npm:minimist@^2.0.0-beta.1",
        '{"lockfileVersion":3,"packages":{"node_modules/friendly":{"name":"minimist","version":"2.0.0-beta.1"}}}',
    ),
    (
        "pnpm-lock.yaml",
        "pnpm add friendly@npm:minimist@^2.0.0-beta.1",
        "lockfileVersion: '9.0'\nimporters:\n  .:\n    optionalDependencies:\n      friendly:\n"
        "        specifier: npm:minimist@^2.0.0-beta.1\n        version: minimist@2.0.0-beta.1\n"
        "  apps/other:\n    dependencies:\n      friendly: minimist@2.0.0\n"
        "packages:\n  minimist@2.0.0-beta.1:\n",
    ),
    (
        "yarn.lock",
        "yarn workspace app add friendly@npm:minimist@^2.0.0-beta.1",
        '"friendly@npm:minimist@^2.0.0-beta.1":\n  version "2.0.0-beta.1"\n',
    ),
)


def signed_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, ecosystem: str, prerelease: str = "2.0.0-beta.1"
) -> GuardStore:
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            packages=[
                _package(ecosystem=ecosystem, name="minimist", version=prerelease, default_action="block"),
                _package(ecosystem=ecosystem, name="minimist", version="2.0.0", default_action="allow"),
            ]
        ),
        NOW,
    )
    return store


@pytest.mark.parametrize(("filename", "command", "source"), ALIASES, ids=[v[0] for v in ALIASES])
def test_alias_and_root_workspace_resolution_preserve_prerelease_bundle_identity(
    filename: str, command: str, source: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text(
        '{"optionalDependencies":{"friendly":"npm:minimist@^2.0.0-beta.1"}}', encoding="utf-8"
    )
    (workspace / filename).write_text(source, encoding="utf-8")
    store = signed_store(tmp_path, monkeypatch, ecosystem="npm")
    result = evaluator.evaluate_package_request_artifact(
        artifact=_artifact_from_command(command, workspace=workspace), store=store, workspace_dir=workspace, now=NOW
    )

    assert result.decision == "block"
    direct = [package for package in result.packages if package.get("direct") is True]
    assert len(direct) == 1
    assert (direct[0]["name"], direct[0]["resolvedVersion"], direct[0]["decision"]) == (
        "minimist",
        "2.0.0-beta.1",
        "block",
    )
    assert direct[0]["alias"] == "friendly"
    assert {reason["code"] for reason in direct[0]["reasons"]} == {"known_malware_or_kev"}


@pytest.mark.parametrize(("filename", "command"), (("poetry.lock", "poetry install"), ("uv.lock", "uv sync")))
def test_optional_python_manifest_prerelease_is_evaluated_with_exact_locked_identity(
    filename: str, command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "pyproject.toml").write_text(
        '[project]\nname="demo"\n[project.optional-dependencies]\nextra=["minimist==2.0.0b1"]\n',
        encoding="utf-8",
    )
    (workspace / filename).write_text(
        '[[package]]\nname="minimist"\nversion="2.0.0b1"\noptional=true\n', encoding="utf-8"
    )
    store = signed_store(tmp_path, monkeypatch, ecosystem="pypi", prerelease="2.0.0b1")
    result = evaluator.evaluate_package_request_artifact(
        artifact=_artifact_from_command(command, workspace=workspace), store=store, workspace_dir=workspace, now=NOW
    )

    assert result.decision == "block"
    assert any(
        package["name"] == "minimist"
        and package["ecosystem"] == "pypi"
        and package["resolvedVersion"] == "2.0.0b1"
        and package["decision"] == "block"
        for package in result.packages
    )


@pytest.mark.parametrize("section", ("GEM", "GIT", "PATH"))
@pytest.mark.parametrize(
    "tail",
    (
        "unfinished (",
        "unfinished (1.0",
        "unfinished ()",
        "UNFINISHED",
        "demo (2) junk",
        "!unfinished (",
        "unfinished : 1.0",
        "specs:",
    ),
)
def test_bundler_recognized_truncated_spec_cannot_leave_a_complete_prefix(section: str, tail: str) -> None:
    source = f"{section}\n  specs:\n    first (1.0.0)\n      nested (~> 2)\n    {tail}\n"
    parsed = evaluator._parse_lockfile_text_result("Gemfile.lock", source)
    assert parsed.complete is False and parsed.error_reason == "syntax_error"
    assert parsed.entries == () and parsed.manifest_dependency_map() == {}
    assert parsed.source_hash == stable_digest_hex(source.encode())


@pytest.mark.parametrize("security_level", ("balanced", "strict", "paranoid"))
@pytest.mark.parametrize("command", ("bun install", "bun add minimist@1.0.0"))
def test_binary_bun_fallback_never_becomes_a_complete_text_lockfile(
    security_level: str, command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"name":"demo"}', encoding="utf-8")
    (workspace / "bun.lockb").write_bytes(b"\xff\x00binary-fixture")
    store = GuardStore(tmp_path / "guard")
    (store.guard_home / "config.toml").write_text(f'security_level = "{security_level}"\n', encoding="utf-8")

    def no_text_parse(*_args, **_kwargs):
        raise AssertionError("Binary Bun fallback must never invoke the text lockfile parser")

    artifact = _artifact_from_command(command, workspace=workspace)
    real_open = Path.open

    def no_binary_open(path, *args, **kwargs):
        assert path != workspace / "bun.lockb", "Binary fallback must remain metadata-only"
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(evaluator, "parse_lockfile_with_budget", no_text_parse)
    monkeypatch.setattr(Path, "open", no_binary_open)
    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact, store=store, workspace_dir=workspace, now=NOW
    )
    assert result.decision == ("ask" if security_level == "balanced" else "block")
    assert len(result.packages) == 1
    package = result.packages[0]
    assert package["name"] == ("workspace" if command == "bun install" else "minimist")
    assert {reason["code"] for reason in package["reasons"]} == {"bun_lockfile_binary_fallback"}
    assert "lockfileParseComplete" not in package


@pytest.mark.parametrize("stale", (False, True))
@pytest.mark.parametrize("high_confidence", (False, True))
def test_stale_transitive_bundle_retains_confirmed_blocks_without_promoting_lower_confidence(
    stale: bool, high_confidence: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "package-lock.json").write_text(
        '{"packages":{"node_modules/anchor/node_modules/minimist":{"version":"1.0.0"}}}', encoding="utf-8"
    )
    store = GuardStore(tmp_path / "guard")
    # Model a configured but unavailable cloud transport, so this exercises the
    # actual stale offline branch rather than the distinct cloud-auth decision.
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    _force_cloud_fallback(monkeypatch)
    response = _bundle_response(
        packages=[
            _package(ecosystem="npm", name="anchor", version="1.0.0", default_action="allow"),
            _package(
                ecosystem="npm",
                name="minimist",
                version="1.0.0",
                default_action="block",
                known_exploited=high_confidence,
                malware_state="known" if high_confidence else "none",
                exploit_level="active" if high_confidence else "none",
                normalized_severity="high",
                confidence=990,
            ),
        ],
        expires_at=datetime(2026, 5, 19, 0, 1, tzinfo=timezone.utc),
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, NOW)
    result = evaluator.evaluate_package_request_artifact(
        artifact=_artifact_from_command("npm install anchor@1.0.0", workspace=workspace),
        store=store,
        workspace_dir=workspace,
        now="2026-05-19T01:00:00Z" if stale else NOW,
    )
    package = next(item for item in result.packages if item.get("direct") is False)
    downgraded = stale and not high_confidence
    assert (package["name"], package["resolvedVersion"], package["dependencyPath"]) == (
        "minimist",
        "1.0.0",
        "anchor/node_modules/minimist",
    )
    assert package["decision"] == ("warn" if downgraded else "block")
    assert {reason["code"] for reason in package["reasons"]} == {
        "transitive_low_confidence_match" if downgraded else "transitive_lockfile_match",
        "cloud_timeout",
    }
    with store._connect() as connection:
        persisted = [
            json.loads(row[0])["package"] for row in connection.execute("select details_json from guard_evidence")
        ]
    assert json.loads(json.dumps(package)) in persisted
