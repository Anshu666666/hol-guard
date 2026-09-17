"""Range-request resolution is distinct from an unversioned bundle lookup."""

from __future__ import annotations

import urllib.request
from pathlib import Path

import pytest

from scripts.package_benchmark_corpus import bundle, supplemental_cases
from scripts.package_benchmark_evidence import sign_fixture
from scripts.package_benchmark_phases import new_profile, phase_report
from scripts.package_benchmark_registry import REGISTRY_BYTES, REGISTRY_HEADERS, RegistryTransport
from tests.test_package_benchmark_matrix import worker_case


def request(name="bench-dep-00000", **kwargs):
    return urllib.request.Request("https://registry.npmjs.org/" + name, headers=REGISTRY_HEADERS, **kwargs)


@pytest.mark.parametrize("mutation", ("host", "name", "method", "header", "timeout", "body", "duplicate"))
def test_transport_accepts_only_frozen_finite_gets(mutation):
    fixture = RegistryTransport(1)
    value, timeout = request(), 1
    if mutation == "host":
        value.full_url = "https://unexpected.invalid/bench-dep-00000"
    elif mutation == "name":
        value = request("unknown")
    elif mutation == "method":
        value.method = "POST"
    elif mutation == "header":
        value.add_header("Authorization", "private")
    elif mutation == "timeout":
        timeout = 2
    elif mutation == "body":
        value.data = b"payload"
    elif mutation == "duplicate":
        with fixture.open(value, timeout=timeout) as response:
            assert response.read() == REGISTRY_BYTES
    with pytest.raises(AssertionError, match="transport_contract_changed"), fixture.open(value, timeout=timeout):
        pass
    with pytest.raises(ValueError, match="registry_calls"):
        fixture.report()


def test_actual_full_protect_resolves_range_instead_of_highest_risk(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.runtime import runner

    case = supplemental_cases()[0]
    previous = runner.managed_urlopen
    observed = worker_case(case, tmp_path, monkeypatch)
    assert runner.managed_urlopen is previous
    assert observed["status"] == "completed" and observed["packages"] == observed["evidence_rows"] == 100
    assert observed["registry_transport"]["calls"] == 100
    assert "wall_ms" not in observed and "cpu_ms" not in observed


def test_signed_fixture_distinguishes_concrete_version_from_none_and_profiles_real_verification():
    from codex_plugin_scanner.guard.runtime.supply_chain_bundle import (
        evaluate_cached_supply_chain_bundle,
        load_supply_chain_bundle_response,
        verify_supply_chain_bundle_response,
    )
    from scripts.package_benchmark_corpus import NOW_SECONDS

    case = supplemental_cases()[0]
    signed, _ = sign_fixture(bundle(case))
    response = load_supply_chain_bundle_response(signed)
    profile = new_profile()
    profile.runcall(
        verify_supply_chain_bundle_response, response, trusted_keys=response.verification_keys, now=NOW_SECONDS
    )
    root = Path(__file__).resolve().parents[1]
    phases = phase_report(profile, root, wall_ns=10**9, process_ns=10**9)
    assert phases["functions"]["bundle_verification"]["calls"] == 1
    assert phases["functions"]["rsa_signature_verify"]["calls"] == 1
    exact = evaluate_cached_supply_chain_bundle(
        response, package_name="bench-dep-00000", package_version="2.0.0", ecosystem="npm", now=NOW_SECONDS
    )
    unversioned = evaluate_cached_supply_chain_bundle(
        response, package_name="bench-dep-00000", package_version=None, ecosystem="npm", now=NOW_SECONDS
    )
    assert exact.reason == "bundle_match" and unversioned.reason == "known_malware_or_kev"
