"""Real Composer lockfile coverage must retain vendor-qualified identities."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
from codex_plugin_scanner.guard.runtime.package_intent_common import build_package_request_artifact
from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_supply_chain_bundle import _generate_key_pair, _sign_bundle_response
from tests.test_guard_supply_chain_evaluator import WORKSPACE_ID, _bundle_response, _package


def evaluate(tmp_path, monkeypatch, *, emergency=False, stale=False, direct=False, invalid=False):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "composer.json").write_text('{"name":"fixture/root"}')
    entries = [{"name": "acme/parser", "version": "1.0.0"}]
    if invalid:
        entries = [
            {"name": name, "version": "1.0.0"}
            for name in ("../parser", "/acme/parser", "acme/parser/", "acme/../parser", "acme\\parser", "acme//parser")
        ]
    if direct:
        entries = [{"name": "FIXTURE/ANCHOR", "version": "1.0.0"}, *entries]
    (workspace / "composer.lock").write_text(json.dumps({"packages": entries}))
    intent = parse_package_intent("composer require fixture/anchor:1.0.0", workspace=workspace)
    assert intent is not None
    artifact = build_package_request_artifact("hol-guard", intent, config_path="hol-guard.toml", source_scope="project")
    packages = [
        _package(ecosystem="packagist", namespace="fixture", name="anchor", version="1.0.0", default_action="block"),
        _package(ecosystem="packagist", namespace="acme", name="parser", version="1.0.0", default_action="block"),
        # Identical leaf in another vendor must not be selected by leaf name.
        _package(ecosystem="packagist", namespace="other", name="parser", version="1.0.0", default_action="ask"),
    ]
    response = _bundle_response(
        packages=packages,
        expires_at=datetime(2026, 5, 19, 0, 1, tzinfo=timezone.utc) if stale else None,
    )
    if emergency:
        bundle = response["bundle"]
        assert isinstance(bundle, dict)
        bundle["emergencyDenylist"] = [
            {
                "ecosystem": "packagist",
                "namespace": "acme",
                "name": "parser",
                "reason": "known_malware",
                "recommendedFixVersion": "2.0.0",
            }
        ]
        private_key, _ = _generate_key_pair()
        response = _sign_bundle_response(bundle, private_key_pem=private_key)
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(WORKSPACE_ID, response, "2026-05-19T00:00:00Z")
    lookups = []
    original = evaluator.evaluate_cached_supply_chain_bundle

    def capture(*args, **kwargs):
        lookups.append((kwargs["ecosystem"], kwargs["package_name"]))
        return original(*args, **kwargs)

    monkeypatch.setattr(evaluator, "evaluate_cached_supply_chain_bundle", capture)
    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace,
        now="2026-05-19T01:00:00Z" if stale else "2026-05-19T00:00:00Z",
    )
    with store._connect() as connection:
        rows = [dict(row) for row in connection.execute("select * from guard_evidence")]
    return result, rows, lookups


def first_reason(package: dict[str, object]) -> object:
    reasons = package["reasons"]
    assert isinstance(reasons, (tuple, list)) and isinstance(reasons[0], dict)
    return reasons[0]["code"]


def test_vendor_package_is_really_looked_up_and_persisted(tmp_path, monkeypatch):
    result, rows, lookups = evaluate(tmp_path, monkeypatch)
    assert ("packagist", "acme/parser") in lookups
    assert len(result.packages) == len(rows) == 2
    package = next(item for item in result.packages if item["direct"] is False)
    assert package["name"] == "parser" and package["namespace"] == "acme"
    assert package["dependencyPath"] == "acme/parser" and package["resolvedVersion"] == "1.0.0"
    assert package["decision"] == "block" and first_reason(package) == "transitive_lockfile_match"
    persisted = [json.loads(row["details_json"])["package"] for row in rows]
    assert any(item["namespace"] == "acme" and item["direct"] is False for item in persisted)
    assert not any(item["namespace"] == "other" for item in result.packages)


@pytest.mark.parametrize("stale", (False, True))
def test_emergency_deny_retains_vendor_and_fix_version_when_fresh_or_stale(tmp_path, monkeypatch, stale):
    result, rows, lookups = evaluate(tmp_path, monkeypatch, emergency=True, stale=stale)
    package = next(item for item in result.packages if item["direct"] is False)
    assert package["namespace"] == "acme" and package["name"] == "parser"
    assert package["decision"] == "block" and first_reason(package) == "known_malware"
    assert package["recommendedFixVersion"] == "2.0.0"
    assert ("packagist", "acme/parser") in lookups and len(rows) == 2


def test_canonical_direct_composer_identity_is_not_duplicated_as_transitive(tmp_path, monkeypatch):
    result, rows, _ = evaluate(tmp_path, monkeypatch, direct=True)
    assert len(result.packages) == len(rows) == 2
    anchor = [item for item in result.packages if item["namespace"] == "fixture"]
    assert len(anchor) == 1 and anchor[0]["direct"] is True


def test_invalid_lockfile_names_never_become_vendor_package_lookups(tmp_path, monkeypatch):
    result, rows, lookups = evaluate(tmp_path, monkeypatch, invalid=True)
    assert not any(item[1] == "acme/parser" for item in lookups)
    assert len(result.packages) == len(rows) == 1
    assert result.packages[0]["direct"] is True


@pytest.mark.parametrize(
    "name",
    (
        "../parser",
        "./parser",
        "acme/..",
        "acme/.",
        "/acme/parser",
        "acme/parser/",
        "acme//parser",
        "acme/../parser",
        "acme\\parser",
        "acme/parser:1",
        "acme/parser name",
        "acme/pa%2frser",
        " acme/parser",
        "acme/parser\n",
        "acme./parser",
        "acme/parser-",
        "acme--vendor/parser",
        "acme/parser---name",
        "acme/\u212ait",
        "\u212ait/parser",
    ),
)
def test_composer_name_admission_does_not_normalize_invalid_paths(name):
    assert evaluator._dependency_package_name(name, ecosystem="packagist") is None


@pytest.mark.parametrize("name", ("a/b", "acme.vendor/parser--name", "acme_vendor/parser.name", "ACME/PARSER"))
def test_composer_name_admission_keeps_supported_schema_names(name):
    assert evaluator._dependency_package_name(name, ecosystem="packagist") == name.lower()


def test_npm_and_other_ecosystem_slash_rules_are_preserved():
    for ecosystem in (None, "npm", "pypi", "cargo", "rubygems"):
        assert evaluator._dependency_package_name("acme/parser", ecosystem=ecosystem) is None
    assert evaluator._dependency_package_name("node_modules/a/node_modules/@scope/pkg", ecosystem="npm") == "@scope/pkg"
    assert evaluator._dependency_package_name("@scope/pkg", ecosystem="npm") == "@scope/pkg"
