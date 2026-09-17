"""Frozen text grammar outcomes, complete-or-fail bounds, and parse reuse."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime import lockfile_parse_result as parser
from codex_plugin_scanner.guard.runtime import package_manifest_diff as manifests
from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
from codex_plugin_scanner.guard.runtime import text_lockfile_parse as text_parser
from codex_plugin_scanner.guard.stable_digest import stable_digest_hex
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_js_supply_chain_phase11 import _artifact_from_command
from tests.test_guard_supply_chain_evaluator import WORKSPACE_ID, _bundle_response, _package

PNPM = """lockfileVersion: '9.0'
dependencies:
  inline: 'npm:real@1.0.0(peer@2)'
    version: 8.0.0
importers:
  .:
    dependencies:
      demo:
        specifier: ^1.0.0
        version: 1.1.0(peer@3)
      alias: real@2.0.0
      local:
        version: link:../local
    devDependencies:
      dev: 3.0.0
  default:
    optionalDependencies:
      demo: 1.2.0
  apps/other:
    dependencies:
      demo: 9.9.9
packages:
  demo@1.0.0:
    resolution: {integrity: sha512-example}
  /legacy/5.0.0:
    resolution: {integrity: sha512-example}
  'demo@2.0.0(peer@3)':
    resolution: {integrity: sha512-example}
snapshots:
  parent@9.0.0:
    dependencies:
      demo: 7.0.0
      external: ^v4.0.0
    optionalDependencies:
      ignored: 8.0.0
"""

YARN = """# yarn lockfile v1 and Berry selectors
__metadata:
  version: 8
"demo@npm:^1":
  version: 2.0.0
"demo@^1", "demo@~1":
  version "1.0.0"
"demo@^1":
  version "9.0.0"
"alias@npm:real@^2":
  version: "2.0.0"
"@scope/pkg@^3":
  version "3.0.0-beta.1"
"local@workspace:packages/local":
  version: 0.0.0-use.local
"unversioned@^1":
  resolved "https://example.invalid/pkg.tgz"
"""

GEMS = """GEM
  remote: https://rubygems.org/
  specs:
    demo (1.0.0)
      indirect (~> 2)
    indirect (2.0.0-x86_64-linux)
GIT
  remote: https://example.invalid/repo
  revision: synthetic
  specs:
    gitgem (3.0.0.pre)
PATH
  remote: ../local
  specs:
    demo (4.0.0)
PLATFORMS
  ruby
DEPENDENCIES
  demo!
BUNDLED WITH
   2.5.0
"""


def parse(name: str, source: str | bytes) -> parser.LockfileParseResult:
    return parser.parse_lockfile_text(
        name,
        source,
        deadline=float("inf"),
        budget_ms=1500,
        dependency_parser=evaluator._dependency_map_for_path,
        package_lock_parser=evaluator._package_lock_entries,
    )


def target(name: str, requested: str | None, alias: str | None = None) -> dict[str, object]:
    return {"name": name, "normalized_name": name, "range": requested, "alias": alias}


@pytest.mark.parametrize(
    ("name", "source", "expected"),
    (
        ("pnpm-lock.yaml", PNPM, {"demo": "2.0.0", "parent": "9.0.0", "external": "4.0.0"}),
        (
            "yarn.lock",
            YARN,
            {"demo": "9.0.0", "alias": "2.0.0", "@scope/pkg": "3.0.0-beta.1", "local": "0.0.0-use.local"},
        ),
        ("Gemfile.lock", GEMS, {"demo": "4.0.0", "indirect": "2.0.0-x86_64-linux", "gitgem": "3.0.0.pre"}),
    ),
)
def test_manifest_views_match_frozen_supported_grammar(name, source, expected):
    result = parse(name, source)
    assert result.complete
    assert result.dependency_map() == result.manifest_dependency_map() == expected
    assert result.source_hash == stable_digest_hex(source.encode())
    # The independent existing manifest API still has the same extraction view.
    assert manifests._dependency_map_for_path(name, source, deadline=float("inf")) == expected
    with pytest.raises(FrozenInstanceError):
        result.__setattr__("entries", ())


def test_pnpm_root_importers_alias_and_legacy_fallback_are_preserved():
    result = parse("pnpm-lock.yaml", PNPM)
    targets = (
        *(target(name, "^1") for name in ("inline", "demo", "local", "dev")),
        target("real", "^2", "alias"),
    )
    assert evaluator._pnpm_lock_target_versions(result, targets) == {
        ("inline", None): "1.0.0",
        ("demo", None): "1.2.0",
        ("dev", None): "3.0.0",
        ("real", "alias"): "2.0.0",
    }
    legacy = parse("pnpm-lock.yaml", "lockfileVersion: 5.4\ndependencies:\n  demo: 1.2.8\npackages:\n  /demo/1.2.8:\n")
    assert legacy.complete and legacy.entries == ()
    assert evaluator._pnpm_lock_target_versions(legacy, (target("demo", "^1"),)) == {("demo", None): "1.2.8"}


def test_yarn_direct_resolution_keeps_first_selector_match_and_target_key_order():
    result = parse("yarn.lock", YARN)
    targets = (
        target("demo", "^1"),
        target("real", "^2", "alias"),
        target("@scope/pkg", "^3"),
        target("unversioned", "^1"),
        target("local", None),
    )
    assert evaluator._yarn_lock_target_versions(result, targets) == {
        ("demo", None): "2.0.0",
        ("real", "alias"): "2.0.0",
        ("@scope/pkg", None): "3.0.0-beta.1",
    }
    assert evaluator._yarn_lock_target_versions(result, (target("demo", "^1"), target("demo", "missing"))) == {}


@pytest.mark.parametrize(
    "separator", ("\n", "\r\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")
)
@pytest.mark.parametrize("terminal", (False, True))
def test_line_iterator_preserves_existing_splitlines_semantics(separator, terminal):
    source = separator.join(("", "# comment", '"demo@1":', '  version "1"', ""))
    if terminal:
        source += separator
    assert list(text_parser._iter_lines(source)) == source.splitlines()
    assert parse("yarn.lock", source).dependency_map() == {"demo": "1"}


@pytest.mark.parametrize(
    ("name", "source"),
    (
        ("pnpm-lock.yaml", "packages:\n  partial\n"),
        ("pnpm-lock.yaml", "packages:\n\tdemo@1:\n"),
        ("yarn.lock", '"demo@1"\n  version "1"\n'),
        ("yarn.lock", '"demo@1":\n  version "1"\n  unknown [\n'),
        ("Gemfile.lock", GEMS + "\x00"),
        ("Gemfile.lock", GEMS + "  unknown }\n"),
    ),
)
def test_malformed_suffix_never_publishes_prefix_dependencies(name, source):
    result = parse(name, source)
    assert not result.complete and result.error_reason == "syntax_error"
    assert result.entries == result.text_direct_candidates == result.selector_version_candidates == ()
    assert result.source_hash == stable_digest_hex(source.encode())


@pytest.mark.parametrize("name", ("pnpm-lock.yaml", "yarn.lock", "Gemfile.lock"))
def test_text_byte_and_decode_admission_are_unchanged(name):
    assert parse(name, b"\xff").error_reason == "decode_error"
    result = parse(name, b"\xff" * (parser.LOCKFILE_MAX_BYTES + 1))
    assert result.error_reason == "byte_limit_exceeded"


@pytest.mark.parametrize(
    ("name", "source"),
    (
        ("pnpm-lock.yaml", "dependencies:\n" + "".join(f"  d{i}: 1\n" for i in range(4))),
        ("yarn.lock", ", ".join(f'"demo@^{i}"' for i in range(4)) + ':\n  version "1"\n'),
        ("Gemfile.lock", "GEM\n  specs:\n" + "".join(f"    d{i} (1)\n" for i in range(4))),
    ),
)
def test_every_text_view_has_an_entry_limit(name, source, monkeypatch):
    monkeypatch.setattr(parser, "LOCKFILE_MAX_ENTRIES", 4)
    assert parse(name, source).complete
    monkeypatch.setattr(parser, "LOCKFILE_MAX_ENTRIES", 3)
    result = parse(name, source)
    assert result.error_reason == "entry_limit_exceeded"
    assert result.entries == result.text_direct_candidates == result.selector_version_candidates == ()


def test_yarn_selector_view_cannot_escape_the_real_100000_entry_contract():
    # All selectors name one package: bounding only the dependency map misses it.
    source = ",".join(f"demo@{i}" for i in range(parser.LOCKFILE_MAX_ENTRIES + 1)) + ':\n  version "1"\n'
    result = parse("yarn.lock", source)
    assert result.error_reason == "entry_limit_exceeded"
    assert result.entries == result.selector_version_candidates == ()


@pytest.mark.parametrize("name", ("pnpm-lock.yaml", "yarn.lock", "Gemfile.lock"))
def test_ignored_text_is_still_subject_to_node_and_depth_admission(name, monkeypatch):
    monkeypatch.setattr(parser, "LOCKFILE_MAX_NODES", 3)
    # Root + two records, with an additional Yarn selector node for each header.
    source = "unused:\n  data: 1\n"
    required = 4 if name == "yarn.lock" else 3
    monkeypatch.setattr(parser, "LOCKFILE_MAX_NODES", required)
    assert parse(name, source).complete
    monkeypatch.setattr(parser, "LOCKFILE_MAX_NODES", required - 1)
    assert parse(name, source).error_reason == "node_limit_exceeded"
    monkeypatch.setattr(parser, "LOCKFILE_MAX_NODES", 250_000)
    monkeypatch.setattr(parser, "LOCKFILE_MAX_DEPTH", 2)
    assert parse(name, "unused:\n  data:\n    child:\n").complete
    assert parse(name, "unused:\n  data:\n    child:\n      too_deep:\n").error_reason == "depth_limit_exceeded"
    assert parse(name, "unused:\n  data: [[1]]\n").error_reason == "depth_limit_exceeded"


def test_expired_deadline_discards_all_text_views(monkeypatch):
    calls = 0

    def bounded_clock():
        nonlocal calls
        calls += 1
        return 0.0 if calls < 15 else 2.0

    monkeypatch.setattr(parser.time, "monotonic", bounded_clock)
    result = parser.parse_lockfile_text(
        "pnpm-lock.yaml",
        PNPM,
        deadline=1.0,
        budget_ms=1000,
        dependency_parser=evaluator._dependency_map_for_path,
        package_lock_parser=evaluator._package_lock_entries,
    )
    assert result.error_reason == "deadline_exceeded"
    assert result.entries == result.text_direct_candidates == ()


@pytest.mark.parametrize("source", (YARN, YARN + "  unfinished [\n"))
def test_complete_and_incomplete_results_use_one_traversal_per_evaluation(source, monkeypatch):
    original = text_parser._iter_lines
    traversals = 0

    def counted(text):
        nonlocal traversals
        traversals += 1
        yield from original(text)

    monkeypatch.setattr(text_parser, "_iter_lines", counted)
    token = evaluator._LOCKFILE_PARSE_CACHE.set({})
    try:
        first = evaluator._parse_lockfile_text_result("yarn.lock", source)
        second = evaluator._parse_lockfile_text_result("YARN.LOCK", source.encode())
        assert first is second
        first.dependency_map()
        first.manifest_dependency_map()
        evaluator._yarn_lock_target_versions(first, (target("demo", "^1"),))
        assert traversals == 1
    finally:
        evaluator._LOCKFILE_PARSE_CACHE.reset(token)
    evaluator._parse_lockfile_text_result("yarn.lock", source)
    assert traversals == 2


@pytest.mark.parametrize(
    ("name", "source", "command", "ecosystem"),
    (
        (
            "pnpm-lock.yaml",
            "dependencies:\n  minimist: 1.2.8\npackages:\n  minimist@1.2.8:\n",
            "pnpm add minimist@^1.2.0",
            "npm",
        ),
        ("yarn.lock", '"minimist@^1.2.0":\n  version "1.2.8"\n', "yarn add minimist@^1.2.0", "npm"),
        ("Gemfile.lock", "GEM\n  specs:\n    minimist (1.2.8)\n", "bundle add minimist --version '~> 1.2'", "rubygems"),
    ),
)
def test_real_package_evaluation_parses_text_once(name, source, command, ecosystem, tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / name).write_bytes(source.encode())
    manifest_name = "Gemfile" if ecosystem == "rubygems" else "package.json"
    manifest = "gem 'minimist', '~> 1.2'\n" if ecosystem == "rubygems" else '{"dependencies":{"minimist":"^1.2.0"}}'
    (workspace / manifest_name).write_text(manifest)
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            packages=[_package(ecosystem=ecosystem, name="minimist", version="1.2.8", default_action="block")]
        ),
        "2026-05-19T00:00:00Z",
    )
    original = text_parser._iter_lines
    traversals = []

    def counted(text):
        traversals.append(text)
        yield from original(text)

    def legacy_rescan(*_args, **_kwargs):
        raise AssertionError("Evaluation reparsed a validated text lockfile")

    monkeypatch.setattr(text_parser, "_iter_lines", counted)
    for legacy_parser in ("_pnpm_lock_dependency_map", "_yarn_lock_dependency_map", "_gemfile_lock_dependency_map"):
        monkeypatch.setattr(manifests, legacy_parser, legacy_rescan)
    artifact = _artifact_from_command(command, workspace=workspace)
    assert isinstance(artifact, GuardArtifact)
    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace,
        now="2026-05-19T00:00:00Z",
    )
    assert result.decision == "block"
    assert any(package["resolvedVersion"] == "1.2.8" for package in result.packages)
    assert traversals == [source]
